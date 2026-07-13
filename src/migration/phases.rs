use super::*;
use sea_orm::DatabaseTransaction;

pub(super) async fn migrate_policies(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    options: &MigrationOptions,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let mut default_assigned = false;
    for policy in &source.policies {
        let Some(driver_type) = map_driver_type(&policy.r#type).filter(|_| {
            !source_settings(&policy.settings)
                .get("encryption")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }) else {
            report.skipped += 1;
            continue;
        };
        let base_path = if policy.r#type == "local" {
            options.local_base_path.clone()
        } else {
            String::new()
        };
        let model = ad::storage_policies::ActiveModel {
            name: Set(policy.name.clone()),
            driver_type: Set(driver_type.to_string()),
            endpoint: Set(policy.server.clone().unwrap_or_default()),
            bucket: Set(policy.bucket_name.clone().unwrap_or_default()),
            access_key: Set(policy.access_key.clone().unwrap_or_default()),
            secret_key: Set(policy.secret_key.clone().unwrap_or_default()),
            base_path: Set(base_path),
            remote_node_id: Set(None),
            max_file_size: Set(policy.max_size.unwrap_or(0)),
            allowed_types: Set(allowed_types(policy)),
            options: Set(policy_options(policy)),
            is_default: Set(!default_assigned),
            chunk_size: Set(chunk_size(policy)),
            created_at: Set(policy.created_at),
            updated_at: Set(policy.updated_at),
            remote_storage_target_key: Set(None),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate storage policy {}", policy.id))?;
        default_assigned = true;
        context.policies.insert(policy.id, model.id);
        report.migrated_policies += 1;
    }
    Ok(())
}

pub(super) async fn migrate_policy_groups(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    for group in &source.groups {
        let target_group = ad::storage_policy_groups::ActiveModel {
            name: Set(group.name.clone()),
            description: Set(format!("Migrated from Cloudreve group {}", group.id)),
            is_enabled: Set(true),
            is_default: Set(false),
            created_at: Set(group.created_at),
            updated_at: Set(group.updated_at),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve group {}", group.id))?;
        context.policy_groups.insert(group.id, target_group.id);
        report.migrated_policy_groups += 1;

        if let Some(source_policy_id) = group.storage_policy_id
            && let Some(target_policy_id) = context.policies.get(&source_policy_id)
        {
            ad::storage_policy_group_items::ActiveModel {
                group_id: Set(target_group.id),
                policy_id: Set(*target_policy_id),
                priority: Set(0),
                min_file_size: Set(0),
                max_file_size: Set(0),
                created_at: Set(group.created_at),
                ..Default::default()
            }
            .insert(transaction)
            .await
            .wrap_err_with(|| format!("link Cloudreve group {} storage policy", group.id))?;
        }
    }
    Ok(())
}

pub(super) async fn migrate_users(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    password_hash: &str,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let groups: HashMap<i64, &cr::groups::Model> = source
        .groups
        .iter()
        .map(|group| (group.id, group))
        .collect();
    let mut used_usernames = HashSet::new();
    for user in &source.users {
        let username = unique_username(&user.nick, user.id, &mut used_usernames);
        let group = groups.get(&user.group_users).copied();
        let role = if group.is_some_and(group_is_admin) {
            "admin"
        } else {
            "user"
        };
        let status = if user.status == "active" && user.deleted_at.is_none() {
            "active"
        } else {
            "disabled"
        };
        let target = ad::users::ActiveModel {
            username: Set(username.clone()),
            email: Set(user.email.clone()),
            password_hash: Set(password_hash.to_string()),
            role: Set(role.to_string()),
            status: Set(status.to_string()),
            session_version: Set(1),
            email_verified_at: Set((status == "active").then_some(user.created_at)),
            pending_email: Set(None),
            storage_used: Set(user.storage),
            storage_quota: Set(group.and_then(|group| group.max_storage).unwrap_or(0)),
            policy_group_id: Set(context.policy_groups.get(&user.group_users).copied()),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
            config: Set(user.settings.as_ref().map(Value::to_string)),
            must_change_password: Set(true),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve user {}", user.id))?;

        let avatar = user.avatar.clone().unwrap_or_default();
        let avatar_source = if avatar.is_empty() {
            "none"
        } else if avatar.to_ascii_lowercase().contains("gravatar") {
            "gravatar"
        } else {
            "upload"
        };
        ad::user_profiles::ActiveModel {
            user_id: Set(target.id),
            display_name: Set(Some(user.nick.clone())),
            wopi_user_info: Set(None),
            avatar_source: Set(avatar_source.to_string()),
            avatar_key: Set((!avatar.is_empty()).then_some(avatar)),
            avatar_version: Set(0),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("create profile for Cloudreve user {}", user.id))?;

        context.users.insert(user.id, target.id);
        context.usernames.insert(user.id, username);
        report.migrated_users += 1;
    }
    Ok(())
}

pub(super) async fn migrate_folders(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let mut pending: Vec<&cr::files::Model> = source
        .files
        .iter()
        .filter(|file| file.r#type == 1)
        .collect();
    pending.sort_by_key(|folder| folder.id);

    while !pending.is_empty() {
        let mut progress = false;
        let mut next = Vec::new();
        for folder in pending {
            let parent = folder.file_children;
            if parent.is_some_and(|parent_id| {
                source
                    .files
                    .iter()
                    .any(|file| file.id == parent_id && file.r#type == 1)
                    && !context.folders.contains_key(&parent_id)
            }) {
                next.push(folder);
                continue;
            }
            let Some(owner_id) = context.users.get(&folder.owner_id).copied() else {
                report.skipped += 1;
                continue;
            };
            let target = ad::folders::ActiveModel {
                name: Set(folder.name.clone()),
                parent_id: Set(parent.and_then(|id| context.folders.get(&id).copied())),
                team_id: Set(None),
                owner_user_id: Set(Some(owner_id)),
                created_by_user_id: Set(Some(owner_id)),
                created_by_username: Set(context
                    .usernames
                    .get(&folder.owner_id)
                    .cloned()
                    .unwrap_or_default()),
                policy_id: Set(folder
                    .storage_policy_files
                    .and_then(|id| context.policies.get(&id).copied())),
                created_at: Set(folder.created_at),
                updated_at: Set(folder.updated_at),
                deleted_at: Set(None),
                is_locked: Set(false),
                ..Default::default()
            }
            .insert(transaction)
            .await
            .wrap_err_with(|| format!("migrate Cloudreve folder {}", folder.id))?;
            context.folders.insert(folder.id, target.id);
            report.migrated_folders += 1;
            progress = true;
        }
        if !progress && !next.is_empty() {
            bail!("Cloudreve folder hierarchy contains a cycle or a missing parent");
        }
        pending = next;
    }
    Ok(())
}

pub(super) async fn migrate_blobs(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let associations = associations(source);
    let entities: HashMap<i64, &cr::entities::Model> = source
        .entities
        .iter()
        .map(|entity| (entity.id, entity))
        .collect();
    let mut reference_counts: HashMap<i64, i64> = HashMap::new();
    let mut thumbnail_paths: HashMap<i64, String> = HashMap::new();
    for entity_ids in associations.values() {
        let thumbnail_path = entity_ids.iter().find_map(|entity_id| {
            entities
                .get(entity_id)
                .filter(|entity| entity.r#type == 1)
                .map(|entity| entity.source.clone())
        });
        for entity_id in entity_ids {
            if entities
                .get(entity_id)
                .is_some_and(|entity| entity.r#type == 0)
            {
                *reference_counts.entry(*entity_id).or_default() += 1;
                if let Some(path) = &thumbnail_path {
                    thumbnail_paths
                        .entry(*entity_id)
                        .or_insert_with(|| path.clone());
                }
            }
        }
    }
    for entity in source.entities.iter().filter(|entity| entity.r#type == 0) {
        let Some(policy_id) = context
            .policies
            .get(&entity.storage_policy_entities)
            .copied()
        else {
            report.skipped += 1;
            continue;
        };
        let reference_count = reference_counts.get(&entity.id).copied().unwrap_or(1);
        let thumbnail_path = thumbnail_paths.get(&entity.id).cloned();
        let target = ad::file_blobs::ActiveModel {
            hash: Set(opaque_blob_key(entity.id)),
            size: Set(entity.size),
            policy_id: Set(policy_id),
            storage_path: Set(entity.source.clone()),
            thumbnail_path: Set(thumbnail_path),
            thumbnail_processor: Set(None),
            thumbnail_version: Set(None),
            ref_count: Set(reference_count),
            created_at: Set(entity.created_at),
            updated_at: Set(entity.updated_at),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve entity {}", entity.id))?;
        context.blobs.insert(entity.id, target.id);
        report.migrated_blobs += 1;
    }
    Ok(())
}

pub(super) async fn migrate_files(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let associations = associations(source);
    let entities: HashMap<i64, &cr::entities::Model> = source
        .entities
        .iter()
        .map(|entity| (entity.id, entity))
        .collect();
    let mut files: Vec<&cr::files::Model> = source
        .files
        .iter()
        .filter(|file| file.r#type == 0)
        .collect();
    files.sort_by_key(|file| file.id);

    for file in files {
        if file.is_symbolic {
            report.skipped += 1;
            continue;
        }
        let Some(owner_id) = context.users.get(&file.owner_id).copied() else {
            report.skipped += 1;
            continue;
        };
        let mut version_entities: Vec<&cr::entities::Model> = associations
            .get(&file.id)
            .into_iter()
            .flatten()
            .filter_map(|entity_id| entities.get(entity_id).copied())
            .filter(|entity| entity.r#type == 0 && context.blobs.contains_key(&entity.id))
            .collect();
        version_entities.sort_by_key(|entity| entity.created_at);
        let primary_entity_id = file
            .primary_entity
            .filter(|id| context.blobs.contains_key(id))
            .or_else(|| version_entities.last().map(|entity| entity.id));
        let Some(primary_entity_id) = primary_entity_id else {
            report.skipped += 1;
            report
                .warnings
                .push(format!("file {} has no migratable version entity", file.id));
            continue;
        };
        let blob_id = context.blobs[&primary_entity_id];
        let (mime_type, compound_extension, extension, category) = file_classification(&file.name);
        let target = ad::files::ActiveModel {
            name: Set(file.name.clone()),
            folder_id: Set(file
                .file_children
                .and_then(|folder_id| context.folders.get(&folder_id).copied())),
            team_id: Set(None),
            blob_id: Set(blob_id),
            size: Set(file.size),
            owner_user_id: Set(Some(owner_id)),
            created_by_user_id: Set(Some(owner_id)),
            created_by_username: Set(context
                .usernames
                .get(&file.owner_id)
                .cloned()
                .unwrap_or_default()),
            mime_type: Set(mime_type),
            created_at: Set(file.created_at),
            updated_at: Set(file.updated_at),
            deleted_at: Set(None),
            is_locked: Set(false),
            extension: Set(extension),
            compound_extension: Set(compound_extension),
            file_category: Set(category),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve file {}", file.id))?;
        context.files.insert(file.id, target.id);
        report.migrated_files += 1;

        let historical: Vec<&cr::entities::Model> = version_entities
            .into_iter()
            .filter(|entity| entity.id != primary_entity_id)
            .collect();
        for (index, entity) in historical.into_iter().enumerate() {
            ad::file_versions::ActiveModel {
                file_id: Set(target.id),
                blob_id: Set(context.blobs[&entity.id]),
                version: Set((index + 1) as i64),
                size: Set(entity.size),
                created_at: Set(entity.created_at),
                ..Default::default()
            }
            .insert(transaction)
            .await
            .wrap_err_with(|| format!("migrate version {} for file {}", entity.id, file.id))?;
            report.migrated_versions += 1;
        }
    }
    Ok(())
}

pub(super) async fn migrate_metadata(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    for metadata in &source.metadata {
        let Some(file_id) = context.files.get(&metadata.file_id).copied() else {
            report.skipped += 1;
            continue;
        };
        let namespace = if metadata.is_public {
            "cloudreve.public"
        } else {
            "cloudreve.private"
        };
        ad::entity_properties::ActiveModel {
            entity_type: Set("file".to_string()),
            entity_id: Set(file_id),
            namespace: Set(namespace.to_string()),
            name: Set(metadata.name.clone()),
            value: Set(Some(metadata.value.clone())),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate metadata {}", metadata.id))?;
        report.migrated_properties += 1;
    }
    Ok(())
}

pub(super) async fn migrate_shares(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let source_files: HashMap<i64, &cr::files::Model> =
        source.files.iter().map(|file| (file.id, file)).collect();
    for share in &source.shares {
        let Some(source_user_id) = share.user_shares else {
            report.skipped += 1;
            continue;
        };
        let Some(user_id) = context.users.get(&source_user_id).copied() else {
            report.skipped += 1;
            continue;
        };
        let Some(source_file_id) = share.file_shares else {
            report.skipped += 1;
            continue;
        };
        let source_file = source_files.get(&source_file_id).copied();
        let file_id = source_file
            .filter(|file| file.r#type == 0)
            .and_then(|_| context.files.get(&source_file_id).copied());
        let folder_id = source_file
            .filter(|file| file.r#type == 1)
            .and_then(|_| context.folders.get(&source_file_id).copied());
        if file_id.is_none() && folder_id.is_none() {
            report.skipped += 1;
            continue;
        }
        let password = match share.password.as_deref().filter(|value| !value.is_empty()) {
            Some(password) => Some(hash_password(password)?),
            None => None,
        };
        let max_downloads = share
            .remain_downloads
            .map(|remaining| share.downloads.saturating_add(remaining))
            .unwrap_or(0);
        ad::shares::ActiveModel {
            token: Set(share_token(share.id)),
            user_id: Set(user_id),
            team_id: Set(None),
            file_id: Set(file_id),
            folder_id: Set(folder_id),
            password: Set(password),
            expires_at: Set(share.expires),
            max_downloads: Set(max_downloads),
            download_count: Set(share.downloads),
            view_count: Set(share.views),
            created_at: Set(share.created_at),
            updated_at: Set(share.updated_at),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("migrate share {}", share.id))?;
        report.migrated_shares += 1;
    }
    Ok(())
}

fn associations(source: &SourceData) -> HashMap<i64, Vec<i64>> {
    let mut result: HashMap<i64, Vec<i64>> = HashMap::new();
    for relation in &source.file_entities {
        result
            .entry(relation.file_id)
            .or_default()
            .push(relation.entity_id);
    }
    for file in &source.files {
        if let Some(primary_entity) = file.primary_entity {
            let values = result.entry(file.id).or_default();
            if !values.contains(&primary_entity) {
                values.push(primary_entity);
            }
        }
    }
    result
}
