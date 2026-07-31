use super::*;
use sea_orm::DatabaseTransaction;

use aster_drive_migration_core::{Conversion, ConversionContext, SourceConverter};
use aster_drive_writer::{
    AsterDriveWriter, ResolvedBlob, ResolvedFile, ResolvedFileVersion, ResolvedFolder,
    ResolvedPolicyGroup, ResolvedUser,
};
use cloudreve_adapter::{
    CloudreveBlobRecord, CloudreveConverter, CloudreveFileRecord, CloudreveFolderRecord,
    CloudrevePolicyGroupRecord, CloudreveStoragePolicyRecord, CloudreveUserRecord,
};

pub(super) async fn migrate_policies(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    options: &MigrationOptions,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    let mut default_assigned = false;
    for policy in &source.policies {
        let local_root = if policy.r#type == "local" {
            Some(local_policy_root(options, policy.id).to_string())
        } else {
            None
        };
        match converter.convert(
            CloudreveStoragePolicyRecord {
                policy: policy.clone(),
                local_root,
            },
            &conversion_context,
        )? {
            Conversion::Ready(converted) => {
                let source_id = converted.source_id;
                let target_id = writer.write_policy(converted, !default_assigned).await?;
                default_assigned = true;
                context.policies.insert(source_id, target_id);
                report.migrated_policies += 1;
            }
            Conversion::Skipped(reason) => {
                report.record_skip("storage_policy", Some(policy.id), reason.message);
            }
        }
    }
    Ok(())
}

pub(super) async fn migrate_policy_groups(
    transaction: &DatabaseTransaction,
    source: &SourceData,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    for group in &source.groups {
        let converted = match converter.convert(
            CloudrevePolicyGroupRecord {
                group: group.clone(),
            },
            &conversion_context,
        )? {
            Conversion::Ready(converted) => converted,
            Conversion::Skipped(reason) => bail!(
                "Cloudreve policy group {} was unexpectedly skipped: {}",
                group.id,
                reason.message
            ),
        };
        let source_id = converted.source_id;
        let policy_id = converted
            .policy_source_id
            .and_then(|source_id| context.policies.get(&source_id).copied());
        let target_id = writer
            .write_policy_group(ResolvedPolicyGroup {
                group: converted,
                policy_id,
            })
            .await?;
        context.policy_groups.insert(source_id, target_id);
        report.migrated_policy_groups += 1;
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
    let groups: HashMap<i64, &cloudreve_schema::groups::Model> = source
        .groups
        .iter()
        .map(|group| (group.id, group))
        .collect();
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    let mut used_usernames = HashSet::new();
    for user in &source.users {
        let username = unique_username(&user.nick, user.id, &mut used_usernames);
        let converted = match converter.convert(
            CloudreveUserRecord {
                user: user.clone(),
                group: groups.get(&user.group_users).map(|group| (*group).clone()),
                username: username.clone(),
            },
            &conversion_context,
        )? {
            Conversion::Ready(converted) => converted,
            Conversion::Skipped(reason) => bail!(
                "Cloudreve user {} was unexpectedly skipped: {}",
                user.id,
                reason.message
            ),
        };
        let source_id = converted.source_id;
        let policy_group_id = context
            .policy_groups
            .get(&converted.policy_group_source_id)
            .copied();
        let target_id = writer
            .write_user(
                ResolvedUser {
                    user: converted,
                    policy_group_id,
                },
                password_hash,
            )
            .await?;
        context.users.insert(source_id, target_id);
        context.usernames.insert(source_id, username);
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
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    let mut pending = source
        .folders
        .iter()
        .map(|folder| {
            converter
                .convert(
                    CloudreveFolderRecord {
                        folder: folder.clone(),
                    },
                    &conversion_context,
                )
                .and_then(|conversion| {
                    conversion.into_ready().ok_or_else(|| {
                        color_eyre::eyre::eyre!("source folder query returned a non-folder row")
                    })
                })
        })
        .collect::<Result<Vec<_>>>()?;
    pending.sort_by_key(|folder| folder.source_id);

    while !pending.is_empty() {
        let mut progress = false;
        let mut next = Vec::new();
        for folder in pending {
            if folder.parent_source_id.is_some_and(|parent_id| {
                source
                    .folders
                    .iter()
                    .any(|candidate| candidate.id == parent_id && candidate.r#type == 1)
                    && !context.folders.contains_key(&parent_id)
            }) {
                next.push(folder);
                continue;
            }
            let source_id = folder.source_id;
            let owner_source_id = folder.owner_source_id;
            if !context.users.contains_key(&owner_source_id) {
                report.record_skip(
                    "folder",
                    Some(source_id),
                    format!("owner user {owner_source_id} was not migrated"),
                );
                continue;
            }
            let owner_id = context.users[&owner_source_id];
            let resolved = ResolvedFolder {
                parent_id: folder
                    .parent_source_id
                    .and_then(|id| context.folders.get(&id).copied()),
                owner_id,
                owner_username: context
                    .usernames
                    .get(&owner_source_id)
                    .cloned()
                    .unwrap_or_default(),
                policy_id: folder
                    .policy_source_id
                    .and_then(|id| context.policies.get(&id).copied()),
                folder,
            };
            let target_id = writer.write_folder(resolved).await?;
            context.folders.insert(source_id, target_id);
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
    entities: &[cloudreve_schema::entities::Model],
    reference_counts: &HashMap<i64, i64>,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<Vec<(i64, i64)>> {
    let mut mappings = Vec::with_capacity(entities.len());
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    for entity in entities {
        let conversion = converter.convert(
            CloudreveBlobRecord {
                entity: entity.clone(),
                reference_count: reference_counts.get(&entity.id).copied().unwrap_or(0),
            },
            &conversion_context,
        )?;
        let blob = match conversion {
            Conversion::Ready(blob) => blob,
            Conversion::Skipped(reason) => {
                report.record_skip("blob", Some(entity.id), reason.message);
                continue;
            }
        };
        let Some(policy_id) = context.policies.get(&blob.policy_source_id).copied() else {
            report.record_skip(
                "blob",
                Some(blob.source_id),
                format!("storage policy {} was not migrated", blob.policy_source_id),
            );
            continue;
        };
        let source_id = blob.source_id;
        let target_id = writer.write_blob(ResolvedBlob { blob, policy_id }).await?;
        mappings.push((source_id, target_id));
        report.migrated_blobs += 1;
    }
    Ok(mappings)
}

pub(super) async fn migrate_file_batch(
    transaction: &DatabaseTransaction,
    files: &[cloudreve_schema::files::Model],
    associations: &HashMap<i64, Vec<i64>>,
    entities: &HashMap<i64, cloudreve_schema::entities::Model>,
    blob_mappings: &HashMap<i64, i64>,
    context: &MigrationContext,
    report: &mut MigrationReport,
) -> Result<Vec<(i64, i64)>> {
    let mut mappings = Vec::with_capacity(files.len());
    let converter = CloudreveConverter;
    let conversion_context = ConversionContext;
    let writer = AsterDriveWriter::new(transaction);
    for file in files {
        let mut source_entity_ids = associations.get(&file.id).cloned().unwrap_or_default();
        if let Some(primary_entity) = file.primary_entity
            && !source_entity_ids.contains(&primary_entity)
        {
            source_entity_ids.push(primary_entity);
        }
        let conversion = converter.convert(
            CloudreveFileRecord {
                file: file.clone(),
                entities: source_entity_ids
                    .into_iter()
                    .filter_map(|entity_id| entities.get(&entity_id).cloned())
                    .collect(),
            },
            &conversion_context,
        )?;
        let migrated_file = match conversion {
            Conversion::Ready(file) => file,
            Conversion::Skipped(reason) => {
                report.record_skip("file", Some(file.id), reason.message);
                continue;
            }
        };
        let Some(owner_id) = context.users.get(&migrated_file.owner_source_id).copied() else {
            report.record_skip(
                "file",
                Some(migrated_file.source_id),
                format!(
                    "owner user {} was not migrated",
                    migrated_file.owner_source_id
                ),
            );
            continue;
        };
        let Some(primary_entity_id) = migrated_file.preferred_blob_source_id else {
            bail!(
                "converted Cloudreve file {} has no primary entity",
                migrated_file.source_id
            );
        };
        if !blob_mappings.contains_key(&primary_entity_id) {
            report.record_skip(
                "file",
                Some(migrated_file.source_id),
                format!("current entity {primary_entity_id} was not migrated"),
            );
            report.warnings.push(format!(
                "file {} current entity {primary_entity_id} was not migrated",
                migrated_file.source_id,
            ));
            continue;
        }
        let historical_versions = migrated_file
            .versions
            .iter()
            .filter(|version| version.blob_source_id != primary_entity_id)
            .filter_map(|version| {
                blob_mappings
                    .get(&version.blob_source_id)
                    .copied()
                    .map(|blob_id| ResolvedFileVersion {
                        blob_id,
                        size: version.size,
                        created_at: version.created_at,
                    })
            })
            .collect();
        let source_id = migrated_file.source_id;
        let Some(primary_blob_size) = migrated_file
            .versions
            .iter()
            .find(|version| version.blob_source_id == primary_entity_id)
            .map(|version| version.size)
        else {
            bail!(
                "converted Cloudreve file {} is missing current entity {primary_entity_id} in its version set",
                migrated_file.source_id
            );
        };
        let resolved = ResolvedFile {
            folder_id: migrated_file
                .folder_source_id
                .and_then(|folder_id| context.folders.get(&folder_id).copied()),
            owner_id,
            owner_username: context
                .usernames
                .get(&migrated_file.owner_source_id)
                .cloned()
                .unwrap_or_default(),
            primary_blob_id: blob_mappings[&primary_entity_id],
            primary_blob_size,
            historical_versions,
            file: migrated_file,
        };
        let written = writer.write_file(resolved).await?;
        mappings.push((source_id, written.target_id));
        report.migrated_files += 1;
        report.migrated_versions += written.version_count;
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
                .map(|id| (EntityType::File, id))
        } else {
            context
                .folders
                .get(&metadata.file_id)
                .copied()
                .map(|id| (EntityType::Folder, id))
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
                    let tag = aster_drive_schema::entities::tag::ActiveModel {
                        scope_type: Set(TagScopeType::Personal),
                        owner_user_id: Set(Some(owner_user_id)),
                        team_id: Set(None),
                        name: Set(name),
                        normalized_name: Set(normalized_name.clone()),
                        color: Set(target_tag_color(&metadata.value)),
                        sort_order: Set(0),
                        created_at: Set(target_time(metadata.created_at)),
                        updated_at: Set(target_time(metadata.updated_at)),
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
            aster_drive_schema::entities::entity_property::ActiveModel {
                entity_type: Set(entity_type),
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
                target_entity_type: entity_type.as_str().to_string(),
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
        aster_drive_schema::entities::entity_property::ActiveModel {
            entity_type: Set(entity_type),
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
        aster_drive_schema::entities::entity_property::ActiveModel {
            entity_type: Set(EntityType::File),
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
        let status = match archived_task_status(&task.status) {
            "succeeded" => BackgroundTaskStatus::Succeeded,
            "failed" => BackgroundTaskStatus::Failed,
            _ => BackgroundTaskStatus::Canceled,
        };
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
        let started_at =
            (!matches!(task.status.as_str(), "queued")).then(|| target_time(task.created_at));
        let expires_at = task
            .updated_at
            .checked_add_signed(chrono::Duration::days(36_500))
            .unwrap_or(task.updated_at);
        let target = aster_drive_schema::entities::background_task::ActiveModel {
            kind: Set(BackgroundTaskKind::SystemRuntime),
            status: Set(status),
            creator_user_id: Set(task
                .user_tasks
                .and_then(|user_id| context.users.get(&user_id).copied())),
            team_id: Set(None),
            share_id: Set(None),
            display_name: Set(format!("Cloudreve task: {}", task.r#type)),
            payload_json: Set(StoredTaskPayload::from(
                json!({"task_name": task_name}).to_string(),
            )),
            result_json: Set(Some(StoredTaskResult::from(result.to_string()))),
            steps_json: Set(Some(StoredTaskSteps::from("[]".to_string()))),
            progress_current: Set(i64::from(status == BackgroundTaskStatus::Succeeded)),
            progress_total: Set(1),
            status_text: Set(Some(format!(
                "Archived from Cloudreve with source status {}; execution was not resumed",
                task.status
            ))),
            attempt_count: Set(0),
            max_attempts: Set(1),
            next_run_at: Set(target_time(task.updated_at)),
            processing_token: Set(0),
            processing_started_at: Set(None),
            last_heartbeat_at: Set(None),
            lease_expires_at: Set(None),
            started_at: Set(started_at),
            finished_at: Set(Some(target_time(task.updated_at))),
            last_error: Set((status == BackgroundTaskStatus::Failed)
                .then(|| "Cloudreve task ended with status error".to_string())),
            failure_can_retry: Set(Some(false)),
            expires_at: Set(target_time(expires_at)),
            created_at: Set(target_time(task.created_at)),
            updated_at: Set(target_time(task.updated_at)),
            runtime_json: Set(Some(StoredTaskRuntime::from(runtime.to_string()))),
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
        let target = aster_drive_schema::entities::share::ActiveModel {
            token: Set(share_token(share.id)),
            user_id: Set(user_id),
            team_id: Set(None),
            file_id: Set(file_id),
            folder_id: Set(folder_id),
            password: Set(password),
            expires_at: Set(target_optional_time(share.expires)),
            max_downloads: Set(max_downloads),
            download_count: Set(share.downloads),
            view_count: Set(share.views),
            created_at: Set(target_time(share.created_at)),
            updated_at: Set(target_time(share.updated_at)),
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
) -> Result<HashMap<i64, cloudreve_schema::files::Model>> {
    const QUERY_ID_BATCH_SIZE: usize = 500;

    let source_ids = source_ids.iter().copied().collect::<HashSet<_>>();
    let mut files = HashMap::with_capacity(source_ids.len());
    let source_ids = source_ids.into_iter().collect::<Vec<_>>();
    for source_ids in source_ids.chunks(QUERY_ID_BATCH_SIZE) {
        for file in cloudreve_schema::files::Entity::find()
            .filter(cloudreve_schema::files::Column::Id.is_in(source_ids.iter().copied()))
            .all(source_db)
            .await?
        {
            files.insert(file.id, file);
        }
    }
    Ok(files)
}

pub(super) fn associations(
    files: &[cloudreve_schema::files::Model],
    file_entities: &[cloudreve_schema::file_entities::Model],
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
