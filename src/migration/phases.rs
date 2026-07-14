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
            report.record_skip(
                "storage_policy",
                Some(policy.id),
                unsupported_policy_reason(policy)
                    .unwrap_or_else(|| "storage policy is not compatible with AD".to_string()),
            );
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
        .folders
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
                    .folders
                    .iter()
                    .any(|file| file.id == parent_id && file.r#type == 1)
                    && !context.folders.contains_key(&parent_id)
            }) {
                next.push(folder);
                continue;
            }
            let Some(owner_id) = context.users.get(&folder.owner_id).copied() else {
                report.record_skip(
                    "folder",
                    Some(folder.id),
                    format!("owner user {} was not migrated", folder.owner_id),
                );
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

pub(super) async fn migrate_blob_batch(
    transaction: &DatabaseTransaction,
    entities: &[cr::entities::Model],
    reference_counts: &HashMap<i64, i64>,
    thumbnail_paths: &HashMap<i64, String>,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<Vec<(i64, i64)>> {
    let mut mappings = Vec::with_capacity(entities.len());
    for entity in entities {
        let Some(policy_id) = context
            .policies
            .get(&entity.storage_policy_entities)
            .copied()
        else {
            report.record_skip(
                "blob",
                Some(entity.id),
                format!(
                    "storage policy {} was not migrated",
                    entity.storage_policy_entities
                ),
            );
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
        mappings.push((entity.id, target.id));
        report.migrated_blobs += 1;
    }
    Ok(mappings)
}

pub(super) async fn migrate_file_batch(
    transaction: &DatabaseTransaction,
    files: &[cr::files::Model],
    associations: &HashMap<i64, Vec<i64>>,
    entities: &HashMap<i64, cr::entities::Model>,
    blob_mappings: &HashMap<i64, i64>,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<Vec<(i64, i64)>> {
    let mut mappings = Vec::with_capacity(files.len());
    for file in files {
        if file.is_symbolic {
            report.record_skip(
                "file",
                Some(file.id),
                "symbolic/placeholder files are not representable in AD",
            );
            continue;
        }
        let Some(owner_id) = context.users.get(&file.owner_id).copied() else {
            report.record_skip(
                "file",
                Some(file.id),
                format!("owner user {} was not migrated", file.owner_id),
            );
            continue;
        };
        let mut version_entities: Vec<&cr::entities::Model> = associations
            .get(&file.id)
            .into_iter()
            .flatten()
            .filter_map(|entity_id| entities.get(entity_id))
            .filter(|entity| entity.r#type == 0 && blob_mappings.contains_key(&entity.id))
            .collect();
        version_entities.sort_by_key(|entity| entity.created_at);
        let primary_entity_id = file
            .primary_entity
            .filter(|id| blob_mappings.contains_key(id))
            .or_else(|| version_entities.last().map(|entity| entity.id));
        let Some(primary_entity_id) = primary_entity_id else {
            report.record_skip(
                "file",
                Some(file.id),
                "file has no migratable version entity",
            );
            report
                .warnings
                .push(format!("file {} has no migratable version entity", file.id));
            continue;
        };
        let blob_id = blob_mappings[&primary_entity_id];
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
        mappings.push((file.id, target.id));
        report.migrated_files += 1;

        let historical: Vec<&cr::entities::Model> = version_entities
            .into_iter()
            .filter(|entity| entity.id != primary_entity_id)
            .collect();
        for (index, entity) in historical.into_iter().enumerate() {
            ad::file_versions::ActiveModel {
                file_id: Set(target.id),
                blob_id: Set(blob_mappings[&entity.id]),
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
    Ok(mappings)
}

pub(super) async fn migrate_metadata(
    transaction: &DatabaseTransaction,
    source_db: &DatabaseConnection,
    source: &SourceData,
    file_mappings: &HashMap<i64, i64>,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let source_file_ids = source
        .metadata
        .iter()
        .map(|metadata| metadata.file_id)
        .collect::<Vec<_>>();
    let source_files = load_source_files(source_db, &source_file_ids).await?;
    let mut tags: HashMap<(i64, String), i64> = HashMap::new();
    for metadata in &source.metadata {
        let Some(source_file) = source_files.get(&metadata.file_id) else {
            report.record_skip(
                "metadata",
                Some(metadata.id),
                format!("source file {} does not exist", metadata.file_id),
            );
            continue;
        };
        let target_entity = if source_file.r#type == 0 {
            file_mappings
                .get(&metadata.file_id)
                .copied()
                .map(|id| ("file", id))
        } else {
            context
                .folders
                .get(&metadata.file_id)
                .copied()
                .map(|id| ("folder", id))
        };
        let Some((entity_type, entity_id)) = target_entity else {
            report.record_skip(
                "metadata",
                Some(metadata.id),
                format!("source entity {} was not migrated", metadata.file_id),
            );
            continue;
        };

        if let Some(source_tag_name) = tag_name(&metadata.name) {
            let Some(owner_user_id) = context.users.get(&source_file.owner_id).copied() else {
                report.record_skip(
                    "tag_assignment",
                    Some(metadata.id),
                    format!("owner user {} was not migrated", source_file.owner_id),
                );
                continue;
            };
            let name = target_tag_name(source_tag_name);
            if name.is_empty() {
                report.record_skip(
                    "tag_assignment",
                    Some(metadata.id),
                    "tag name is empty after normalization",
                );
                continue;
            }
            let normalized_name = normalize_tag_name(&name);
            let tag_id = match tags.get(&(owner_user_id, normalized_name.clone())) {
                Some(tag_id) => *tag_id,
                None => {
                    let tag = ad::tags::ActiveModel {
                        scope_type: Set("personal".to_string()),
                        owner_user_id: Set(Some(owner_user_id)),
                        team_id: Set(None),
                        name: Set(name),
                        normalized_name: Set(normalized_name.clone()),
                        color: Set(target_tag_color(&metadata.value)),
                        sort_order: Set(0),
                        created_at: Set(metadata.created_at),
                        updated_at: Set(metadata.updated_at),
                        ..Default::default()
                    }
                    .insert(transaction)
                    .await
                    .wrap_err_with(|| format!("migrate tag metadata {}", metadata.id))?;
                    tags.insert((owner_user_id, normalized_name), tag.id);
                    report.migrated_tags += 1;
                    tag.id
                }
            };
            ad::entity_properties::ActiveModel {
                entity_type: Set(entity_type.to_string()),
                entity_id: Set(entity_id),
                namespace: Set("system.tags".to_string()),
                name: Set(tag_id.to_string()),
                value: Set(None),
                ..Default::default()
            }
            .insert(transaction)
            .await
            .wrap_err_with(|| format!("attach migrated tag for metadata {}", metadata.id))?;
            report.migrated_properties += 1;
            report.migrated_tag_assignments += 1;
            report.tag_assignments.push(TagAssignmentReport {
                source_metadata_id: metadata.id,
                source_entity_id: metadata.file_id,
                target_entity_type: entity_type.to_string(),
                target_entity_id: entity_id,
                target_tag_id: tag_id,
                tag_name: source_tag_name.to_string(),
            });
            continue;
        }

        let namespace = if metadata.is_public {
            "cloudreve.public"
        } else {
            "cloudreve.private"
        };
        ad::entity_properties::ActiveModel {
            entity_type: Set(entity_type.to_string()),
            entity_id: Set(entity_id),
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

pub(super) async fn migrate_direct_links(
    transaction: &DatabaseTransaction,
    source_db: &DatabaseConnection,
    source: &SourceData,
    file_mappings: &HashMap<i64, i64>,
    context: &MigrationContext,
    direct_link_secret: Option<&str>,
    report: &mut MigrationReport,
) -> Result<()> {
    if source.direct_links.is_empty() {
        return Ok(());
    }
    let Some(secret) = direct_link_secret else {
        for link in &source.direct_links {
            report.record_skip(
                "direct_link",
                Some(link.id),
                if link.deleted_at.is_some() {
                    "source direct link is deleted and must not be reactivated"
                } else {
                    "AD direct_link_secret was not supplied"
                },
            );
        }
        report.warnings.push(format!(
            "{} Cloudreve direct links were not regenerated because --direct-link-secret was not supplied",
            source.direct_links.len()
        ));
        return Ok(());
    };
    let source_file_ids = source
        .direct_links
        .iter()
        .map(|link| link.file_id)
        .collect::<Vec<_>>();
    let source_files = load_source_files(source_db, &source_file_ids).await?;
    for link in &source.direct_links {
        if link.deleted_at.is_some() {
            report.record_skip(
                "direct_link",
                Some(link.id),
                "source direct link is deleted and must not be reactivated",
            );
            continue;
        }
        let Some(source_file) = source_files.get(&link.file_id) else {
            report.record_skip(
                "direct_link",
                Some(link.id),
                format!("source file {} does not exist", link.file_id),
            );
            continue;
        };
        let Some(file_id) = file_mappings.get(&link.file_id).copied() else {
            report.record_skip(
                "direct_link",
                Some(link.id),
                format!("source file {} was not migrated", link.file_id),
            );
            continue;
        };
        let Some(owner_user_id) = context.users.get(&source_file.owner_id).copied() else {
            report.record_skip(
                "direct_link",
                Some(link.id),
                format!("owner user {} was not migrated", source_file.owner_id),
            );
            continue;
        };
        let url = direct_link_url(file_id, owner_user_id, &source_file.name, secret)?;
        ad::entity_properties::ActiveModel {
            entity_type: Set("file".to_string()),
            entity_id: Set(file_id),
            namespace: Set("cloudreve.direct_links".to_string()),
            name: Set(link.id.to_string()),
            value: Set(Some(
                json!({
                    "url": url.clone(),
                    "source_direct_link_id": link.id,
                    "source_file_id": link.file_id,
                    "source_name": link.name,
                    "source_downloads": link.downloads,
                    "source_speed_limit": link.speed,
                })
                .to_string(),
            )),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("archive direct link {} mapping", link.id))?;
        report.migrated_properties += 1;
        report.migrated_direct_links += 1;
        report.direct_links.push(DirectLinkReport {
            source_direct_link_id: link.id,
            source_file_id: link.file_id,
            target_file_id: file_id,
            source_name: link.name.clone(),
            source_downloads: link.downloads,
            source_speed_limit: link.speed,
            url,
        });
    }
    Ok(())
}

pub(super) async fn migrate_tasks(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let active_count = source
        .tasks
        .iter()
        .filter(|task| source_task_was_active(&task.status))
        .count();
    if active_count > 0 {
        report.warnings.push(format!(
            "{active_count} active Cloudreve tasks were archived as canceled terminal records and were not resumed"
        ));
    }

    for task in &source.tasks {
        let status = archived_task_status(&task.status);
        let duration_ms = (task.updated_at - task.created_at)
            .num_milliseconds()
            .max(0);
        let task_name = format!(
            "cloudreve-legacy-{}",
            task.r#type
                .replace(|character: char| !character.is_ascii_alphanumeric(), "-")
        );
        let result = json!({
            "duration_ms": duration_ms,
            "summary": format!("Archived Cloudreve {} task with source status {}", task.r#type, task.status),
        });
        let runtime = json!({
            "source": "cloudreve",
            "source_task_id": task.id,
            "source_type": task.r#type,
            "source_status": task.status,
            "source_public_state": task.public_state,
            "source_private_state": task.private_state,
            "source_correlation_id": task.correlation_id,
            "source_deleted_at": task.deleted_at,
            "archived_without_resume": true,
        });
        let started_at = (!matches!(task.status.as_str(), "queued")).then_some(task.created_at);
        let expires_at = task
            .updated_at
            .checked_add_signed(chrono::Duration::days(36_500))
            .unwrap_or(task.updated_at);
        let target = ad::background_tasks::ActiveModel {
            kind: Set("system_runtime".to_string()),
            status: Set(status.to_string()),
            creator_user_id: Set(task
                .user_tasks
                .and_then(|user_id| context.users.get(&user_id).copied())),
            team_id: Set(None),
            share_id: Set(None),
            display_name: Set(format!("Cloudreve task: {}", task.r#type)),
            payload_json: Set(json!({"task_name": task_name}).to_string()),
            result_json: Set(Some(result.to_string())),
            steps_json: Set(Some("[]".to_string())),
            progress_current: Set(i64::from(status == "succeeded")),
            progress_total: Set(1),
            status_text: Set(Some(format!(
                "Archived from Cloudreve with source status {}; execution was not resumed",
                task.status
            ))),
            attempt_count: Set(0),
            max_attempts: Set(1),
            next_run_at: Set(task.updated_at),
            processing_token: Set(0),
            processing_started_at: Set(None),
            last_heartbeat_at: Set(None),
            lease_expires_at: Set(None),
            started_at: Set(started_at),
            finished_at: Set(Some(task.updated_at)),
            last_error: Set(
                (status == "failed").then(|| "Cloudreve task ended with status error".to_string())
            ),
            failure_can_retry: Set(Some(false)),
            expires_at: Set(expires_at),
            created_at: Set(task.created_at),
            updated_at: Set(task.updated_at),
            runtime_json: Set(Some(runtime.to_string())),
            ..Default::default()
        }
        .insert(transaction)
        .await
        .wrap_err_with(|| format!("archive Cloudreve task {}", task.id))?;
        context.tasks.insert(task.id, target.id);
        report.migrated_tasks += 1;
    }
    Ok(())
}

pub(super) async fn migrate_shares(
    transaction: &DatabaseTransaction,
    source_db: &DatabaseConnection,
    source: &SourceData,
    file_mappings: &HashMap<i64, i64>,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let source_file_ids = source
        .shares
        .iter()
        .filter_map(|share| share.file_shares)
        .collect::<Vec<_>>();
    let source_files = load_source_files(source_db, &source_file_ids).await?;
    for share in &source.shares {
        let Some(source_user_id) = share.user_shares else {
            report.record_skip("share", Some(share.id), "share has no owner user");
            continue;
        };
        let Some(user_id) = context.users.get(&source_user_id).copied() else {
            report.record_skip(
                "share",
                Some(share.id),
                format!("owner user {source_user_id} was not migrated"),
            );
            continue;
        };
        let Some(source_file_id) = share.file_shares else {
            report.record_skip("share", Some(share.id), "share has no file/folder target");
            continue;
        };
        let source_file = source_files.get(&source_file_id);
        let file_id = source_file
            .filter(|file| file.r#type == 0)
            .and_then(|_| file_mappings.get(&source_file_id).copied());
        let folder_id = source_file
            .filter(|file| file.r#type == 1)
            .and_then(|_| context.folders.get(&source_file_id).copied());
        if file_id.is_none() && folder_id.is_none() {
            report.record_skip(
                "share",
                Some(share.id),
                format!("source target {source_file_id} was not migrated"),
            );
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
        let target = ad::shares::ActiveModel {
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
        context.shares.insert(share.id, target.id);
        report.migrated_shares += 1;
    }
    Ok(())
}

pub(super) async fn load_source_files(
    source_db: &DatabaseConnection,
    source_ids: &[i64],
) -> Result<HashMap<i64, cr::files::Model>> {
    const QUERY_ID_BATCH_SIZE: usize = 500;

    let source_ids = source_ids.iter().copied().collect::<HashSet<_>>();
    let mut files = HashMap::with_capacity(source_ids.len());
    let source_ids = source_ids.into_iter().collect::<Vec<_>>();
    for source_ids in source_ids.chunks(QUERY_ID_BATCH_SIZE) {
        for file in cr::files::Entity::find()
            .filter(cr::files::Column::Id.is_in(source_ids.iter().copied()))
            .all(source_db)
            .await?
        {
            files.insert(file.id, file);
        }
    }
    Ok(files)
}

pub(super) fn associations(
    files: &[cr::files::Model],
    file_entities: &[cr::file_entities::Model],
) -> HashMap<i64, Vec<i64>> {
    let mut result: HashMap<i64, Vec<i64>> = HashMap::new();
    for relation in file_entities {
        result
            .entry(relation.file_id)
            .or_default()
            .push(relation.entity_id);
    }
    for file in files {
        if let Some(primary_entity) = file.primary_entity {
            let values = result.entry(file.id).or_default();
            if !values.contains(&primary_entity) {
                values.push(primary_entity);
            }
        }
    }
    result
}
