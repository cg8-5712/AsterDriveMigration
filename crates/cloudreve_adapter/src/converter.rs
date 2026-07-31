use std::collections::BTreeMap;

use color_eyre::eyre::{Result, bail};
use serde_json::{Value, json};

use super::{
    CloudreveBlobRecord, CloudreveDirectLinkRecord, CloudreveFileRecord, CloudreveFolderRecord,
    CloudreveMetadataRecord, CloudrevePolicyGroupRecord, CloudreveShareRecord,
    CloudreveStoragePolicyRecord, CloudreveUserRecord,
};
use aster_drive_migration_core::{
    Conversion, ConversionContext, MigrationAvatarSource, MigrationBlob, MigrationDirectLink,
    MigrationEntityKind, MigrationEntityRef, MigrationFile, MigrationFileVersion, MigrationFolder,
    MigrationMetadata, MigrationPolicyGroup, MigrationProperty, MigrationShare,
    MigrationShareTarget, MigrationStorageDriver, MigrationStoragePolicy, MigrationTagAssignment,
    MigrationUser, MigrationUserRole, MigrationUserStatus, SkipReason, SourceConverter,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct CloudreveConverter;

fn target_time(value: chrono::DateTime<chrono::FixedOffset>) -> chrono::DateTime<chrono::Utc> {
    value.with_timezone(&chrono::Utc)
}

fn settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
}

const ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS: usize = 255;
const ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES: usize = 65_536;
const ASTER_DRIVE_TAG_NAME_MAX_CHARS: usize = 64;
const DEFAULT_TAG_COLOR: &str = "#3b82f6";

fn metadata_target(target: &cloudreve_schema::files::Model) -> Option<MigrationEntityRef> {
    let kind = match target.r#type {
        0 => MigrationEntityKind::File,
        1 => MigrationEntityKind::Folder,
        _ => return None,
    };
    Some(MigrationEntityRef {
        kind,
        source_id: target.id,
    })
}

fn tag_name(metadata_name: &str) -> Option<&str> {
    metadata_name.strip_prefix("tag:").map(str::trim)
}

fn target_tag_name(name: &str) -> String {
    name.trim()
        .chars()
        .take(ASTER_DRIVE_TAG_NAME_MAX_CHARS)
        .collect()
}

fn target_tag_color(color: &str) -> String {
    let color = color.trim().to_ascii_lowercase();
    if color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return color;
    }
    if color.len() == 4
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let mut expanded = String::with_capacity(7);
        expanded.push('#');
        for character in color[1..].chars() {
            expanded.push(character);
            expanded.push(character);
        }
        return expanded;
    }
    DEFAULT_TAG_COLOR.to_string()
}

impl SourceConverter<CloudreveStoragePolicyRecord> for CloudreveConverter {
    type Output = MigrationStoragePolicy;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveStoragePolicyRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let policy = source.policy;
        let policy_settings = settings(&policy.settings);
        if policy_settings
            .get("encryption")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(Conversion::Skipped(SkipReason {
                code: "cloudreve_storage_encryption",
                message: format!("{} (Cloudreve encryption enabled)", policy.r#type),
            }));
        }
        let driver = match policy.r#type.as_str() {
            "local" => MigrationStorageDriver::Local,
            "s3" | "oss" | "ks3" | "obs" => MigrationStorageDriver::S3,
            "cos" => MigrationStorageDriver::TencentCos,
            unsupported => {
                return Ok(Conversion::Skipped(SkipReason {
                    code: "unsupported_storage_driver",
                    message: unsupported.to_string(),
                }));
            }
        };
        let base_path = match driver {
            MigrationStorageDriver::Local => source.local_root.ok_or_else(|| {
                color_eyre::eyre::eyre!(
                    "local Cloudreve policy {} has no resolved target root",
                    policy.id
                )
            })?,
            MigrationStorageDriver::S3 | MigrationStorageDriver::TencentCos => String::new(),
        };
        let allowed_types = policy_settings
            .get("file_type")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let Some(allowed_types) = allowed_types.as_array() else {
            bail!(
                "Cloudreve policy {} file_type setting must be an array",
                policy.id
            );
        };
        let allowed_types = allowed_types
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "Cloudreve policy {} file_type entries must be strings",
                        policy.id
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let chunk_size = policy_settings
            .get("chunk_size")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if chunk_size < 0 {
            bail!(
                "Cloudreve policy {} chunk_size must not be negative",
                policy.id
            );
        }
        let path_style = policy_settings
            .get("s3_path_style")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let extensions = BTreeMap::from([
            ("cloudreve_source".to_string(), policy_settings),
            ("cloudreve_policy_type".to_string(), json!(policy.r#type)),
        ]);
        Ok(Conversion::Ready(MigrationStoragePolicy {
            source_id: policy.id,
            name: policy.name,
            driver,
            endpoint: policy.server.unwrap_or_default(),
            bucket: policy.bucket_name.unwrap_or_default(),
            access_key: policy.access_key.unwrap_or_default(),
            secret_key: policy.secret_key.unwrap_or_default(),
            base_path,
            max_file_size: policy.max_size.unwrap_or(0),
            allowed_types,
            s3_path_style: path_style,
            extensions,
            chunk_size,
            created_at: target_time(policy.created_at),
            updated_at: target_time(policy.updated_at),
        }))
    }
}

impl SourceConverter<CloudrevePolicyGroupRecord> for CloudreveConverter {
    type Output = MigrationPolicyGroup;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudrevePolicyGroupRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let group = source.group;
        Ok(Conversion::Ready(MigrationPolicyGroup {
            source_id: group.id,
            name: group.name,
            description: format!("Migrated from Cloudreve group {}", group.id),
            policy_source_id: group.storage_policy_id,
            created_at: target_time(group.created_at),
            updated_at: target_time(group.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveUserRecord> for CloudreveConverter {
    type Output = MigrationUser;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveUserRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let user = source.user;
        let role = if source.group.as_ref().is_some_and(|group| {
            group
                .permissions
                .first()
                .is_some_and(|permissions| permissions & 1 == 1)
        }) {
            MigrationUserRole::Admin
        } else {
            MigrationUserRole::User
        };
        let status = if user.status == "active" && user.deleted_at.is_none() {
            MigrationUserStatus::Active
        } else {
            MigrationUserStatus::Disabled
        };
        let avatar = user.avatar.filter(|avatar| !avatar.is_empty());
        let avatar_source = match avatar.as_deref() {
            None => MigrationAvatarSource::None,
            Some(value) if value.to_ascii_lowercase().contains("gravatar") => {
                MigrationAvatarSource::Gravatar
            }
            Some(_) => MigrationAvatarSource::Upload,
        };
        Ok(Conversion::Ready(MigrationUser {
            source_id: user.id,
            username: source.username,
            email: user.email,
            display_name: user.nick,
            role,
            status,
            storage_used: user.storage,
            storage_quota: source
                .group
                .and_then(|group| group.max_storage)
                .unwrap_or(0),
            policy_group_source_id: user.group_users,
            config: user.settings,
            avatar_source,
            avatar_key: avatar,
            created_at: target_time(user.created_at),
            updated_at: target_time(user.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveFolderRecord> for CloudreveConverter {
    type Output = MigrationFolder;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveFolderRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let folder = source.folder;
        if folder.r#type != 1 {
            return Ok(Conversion::Skipped(SkipReason {
                code: "not_a_folder",
                message: format!("Cloudreve file {} is not a folder", folder.id),
            }));
        }
        Ok(Conversion::Ready(MigrationFolder {
            source_id: folder.id,
            name: folder.name,
            parent_source_id: folder.file_children,
            owner_source_id: folder.owner_id,
            policy_source_id: folder.storage_policy_files,
            created_at: target_time(folder.created_at),
            updated_at: target_time(folder.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveBlobRecord> for CloudreveConverter {
    type Output = MigrationBlob;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveBlobRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let entity = source.entity;
        if entity.r#type != 0 {
            return Ok(Conversion::Skipped(SkipReason {
                code: "not_a_blob",
                message: format!("Cloudreve entity {} is not an original object", entity.id),
            }));
        }
        if entity.size < 0 {
            bail!(
                "Cloudreve entity {} has negative size {}",
                entity.id,
                entity.size
            );
        }
        if entity.source.is_empty() {
            bail!("Cloudreve entity {} has an empty storage path", entity.id);
        }
        let reference_count = i32::try_from(source.reference_count)
            .map_err(|_| color_eyre::eyre::eyre!("blob reference count exceeds i32"))?;
        if reference_count < 0 {
            bail!(
                "Cloudreve entity {} has a negative reference count",
                entity.id
            );
        }
        Ok(Conversion::Ready(MigrationBlob {
            source_id: entity.id,
            policy_source_id: entity.storage_policy_entities,
            opaque_key: format!("cloudreve-{:016x}", entity.id),
            storage_path: entity.source,
            size: entity.size,
            reference_count,
            created_at: target_time(entity.created_at),
            updated_at: target_time(entity.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveFileRecord> for CloudreveConverter {
    type Output = MigrationFile;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveFileRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let file = source.file;
        if file.r#type != 0 {
            return Ok(Conversion::Skipped(SkipReason {
                code: "not_a_file",
                message: format!("Cloudreve file {} is not a regular file", file.id),
            }));
        }
        if file.is_symbolic {
            return Ok(Conversion::Skipped(SkipReason {
                code: "symbolic_file",
                message: "symbolic/placeholder files are not representable in AD".to_string(),
            }));
        }
        if file.size < 0 {
            bail!("Cloudreve file {} has negative size {}", file.id, file.size);
        }
        if file.primary_entity.is_none() {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_primary_entity",
                message: format!("Cloudreve file {} has no current entity", file.id),
            }));
        }

        let mut entities = source
            .entities
            .into_iter()
            .filter(|entity| entity.r#type == 0)
            .collect::<Vec<_>>();
        entities.sort_by_key(|entity| (entity.created_at, entity.id));
        let versions = entities
            .into_iter()
            .map(|entity| {
                if entity.size < 0 {
                    bail!(
                        "Cloudreve entity {} for file {} has negative size {}",
                        entity.id,
                        file.id,
                        entity.size
                    );
                }
                Ok(MigrationFileVersion {
                    blob_source_id: entity.id,
                    size: entity.size,
                    created_at: target_time(entity.created_at),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Conversion::Ready(MigrationFile {
            source_id: file.id,
            name: file.name,
            owner_source_id: file.owner_id,
            folder_source_id: file.file_children,
            preferred_blob_source_id: file.primary_entity,
            versions,
            created_at: target_time(file.created_at),
            updated_at: target_time(file.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveShareRecord> for CloudreveConverter {
    type Output = MigrationShare;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveShareRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let share = source.share;
        if share.deleted_at.is_some() {
            return Ok(Conversion::Skipped(SkipReason {
                code: "deleted_share",
                message: format!("Cloudreve share {} is deleted", share.id),
            }));
        }
        let Some(owner_source_id) = share.user_shares else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_share_owner",
                message: format!("Cloudreve share {} has no owner user", share.id),
            }));
        };
        let Some(target_source_id) = share.file_shares else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_share_target",
                message: format!("Cloudreve share {} has no file/folder target", share.id),
            }));
        };
        let Some(target) = source.target else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_share_target",
                message: format!(
                    "Cloudreve share {} target {} does not exist",
                    share.id, target_source_id
                ),
            }));
        };
        if target.id != target_source_id {
            bail!(
                "Cloudreve share {} target record {} does not match target {}",
                share.id,
                target.id,
                target_source_id
            );
        }
        let target = match target.r#type {
            0 => MigrationShareTarget::File {
                source_id: target_source_id,
            },
            1 => MigrationShareTarget::Folder {
                source_id: target_source_id,
            },
            target_type => {
                return Ok(Conversion::Skipped(SkipReason {
                    code: "unsupported_share_target",
                    message: format!(
                        "Cloudreve share {} target {} has unsupported type {}",
                        share.id, target_source_id, target_type
                    ),
                }));
            }
        };
        if share.downloads < 0 || share.views < 0 {
            bail!(
                "Cloudreve share {} has negative view or download counters",
                share.id
            );
        }
        let max_downloads = match share.remain_downloads {
            None => 0,
            Some(remaining) if remaining < 0 => {
                bail!(
                    "Cloudreve share {} has negative remaining downloads {}",
                    share.id,
                    remaining
                );
            }
            Some(remaining) => share.downloads.checked_add(remaining).ok_or_else(|| {
                color_eyre::eyre::eyre!("Cloudreve share {} download limit exceeds i64", share.id)
            })?,
        };
        let plain_password = share.password.filter(|password| !password.is_empty());
        Ok(Conversion::Ready(MigrationShare {
            source_id: share.id,
            owner_source_id,
            target,
            plain_password,
            expires_at: share.expires.map(target_time),
            max_downloads,
            download_count: share.downloads,
            view_count: share.views,
            created_at: target_time(share.created_at),
            updated_at: target_time(share.updated_at),
        }))
    }
}

impl SourceConverter<CloudreveMetadataRecord> for CloudreveConverter {
    type Output = MigrationMetadata;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveMetadataRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let metadata = source.metadata;
        if metadata.deleted_at.is_some() {
            return Ok(Conversion::Skipped(SkipReason {
                code: "deleted_metadata",
                message: format!("Cloudreve metadata {} is deleted", metadata.id),
            }));
        }
        let Some(target) = source.target else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_metadata_target",
                message: format!(
                    "Cloudreve metadata {} target {} does not exist",
                    metadata.id, metadata.file_id
                ),
            }));
        };
        if target.id != metadata.file_id {
            bail!(
                "Cloudreve metadata {} target record {} does not match target {}",
                metadata.id,
                target.id,
                metadata.file_id
            );
        }
        let Some(target_ref) = metadata_target(&target) else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "unsupported_metadata_target",
                message: format!(
                    "Cloudreve metadata {} target {} has unsupported type {}",
                    metadata.id, target.id, target.r#type
                ),
            }));
        };

        if let Some(source_tag_name) = tag_name(&metadata.name) {
            let name = target_tag_name(source_tag_name);
            if name.is_empty() {
                return Ok(Conversion::Skipped(SkipReason {
                    code: "empty_tag_name",
                    message: format!(
                        "Cloudreve metadata {} tag name is empty after trimming",
                        metadata.id
                    ),
                }));
            }
            let normalized_name = name.to_lowercase();
            if normalized_name.chars().count() > ASTER_DRIVE_TAG_NAME_MAX_CHARS {
                bail!(
                    "Cloudreve metadata {} normalized tag name exceeds AsterDrive's {} character limit",
                    metadata.id,
                    ASTER_DRIVE_TAG_NAME_MAX_CHARS
                );
            }
            return Ok(Conversion::Ready(MigrationMetadata::TagAssignment(
                MigrationTagAssignment {
                    source_metadata_id: metadata.id,
                    owner_source_id: target.owner_id,
                    target: target_ref,
                    normalized_name,
                    name,
                    color: target_tag_color(&metadata.value),
                    created_at: target_time(metadata.created_at),
                    updated_at: target_time(metadata.updated_at),
                },
            )));
        }

        if metadata.name.chars().count() > ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS {
            bail!(
                "Cloudreve metadata {} name exceeds AsterDrive's {} character limit",
                metadata.id,
                ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS
            );
        }
        if metadata.value.len() > ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES {
            bail!(
                "Cloudreve metadata {} value exceeds AsterDrive's {} byte API limit",
                metadata.id,
                ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES
            );
        }
        Ok(Conversion::Ready(MigrationMetadata::Property(
            MigrationProperty {
                source_metadata_id: metadata.id,
                target: target_ref,
                namespace: if metadata.is_public {
                    "cloudreve.public".to_string()
                } else {
                    "cloudreve.private".to_string()
                },
                name: metadata.name,
                value: Some(metadata.value),
            },
        )))
    }
}

impl SourceConverter<CloudreveDirectLinkRecord> for CloudreveConverter {
    type Output = MigrationDirectLink;
    type Error = color_eyre::Report;

    fn convert(
        &self,
        source: CloudreveDirectLinkRecord,
        _: &ConversionContext,
    ) -> Result<Conversion<Self::Output>> {
        let link = source.direct_link;
        if link.deleted_at.is_some() {
            return Ok(Conversion::Skipped(SkipReason {
                code: "deleted_direct_link",
                message: format!("Cloudreve direct link {} is deleted", link.id),
            }));
        }
        let Some(target) = source.target else {
            return Ok(Conversion::Skipped(SkipReason {
                code: "missing_direct_link_target",
                message: format!(
                    "Cloudreve direct link {} target file {} does not exist",
                    link.id, link.file_id
                ),
            }));
        };
        if target.id != link.file_id {
            bail!(
                "Cloudreve direct link {} target record {} does not match target {}",
                link.id,
                target.id,
                link.file_id
            );
        }
        if target.r#type != 0 {
            return Ok(Conversion::Skipped(SkipReason {
                code: "unsupported_direct_link_target",
                message: format!(
                    "Cloudreve direct link {} target {} is not a file",
                    link.id, target.id
                ),
            }));
        }
        if link.downloads < 0 {
            bail!(
                "Cloudreve direct link {} has negative download count {}",
                link.id,
                link.downloads
            );
        }
        if link.speed < 0 {
            bail!(
                "Cloudreve direct link {} has negative speed limit {}",
                link.id,
                link.speed
            );
        }
        Ok(Conversion::Ready(MigrationDirectLink {
            source_id: link.id,
            file_source_id: target.id,
            owner_source_id: target.owner_id,
            file_name: target.name,
            source_name: link.name,
            source_downloads: link.downloads,
            source_speed_limit: link.speed,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::FixedOffset> {
        chrono::Utc::now().fixed_offset()
    }

    fn policy(policy_type: &str, settings: Value) -> cloudreve_schema::storage_policies::Model {
        cloudreve_schema::storage_policies::Model {
            id: 7,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            name: "Primary".to_string(),
            r#type: policy_type.to_string(),
            server: Some("https://storage.example.test".to_string()),
            bucket_name: Some("bucket".to_string()),
            is_private: Some(true),
            access_key: Some("access".to_string()),
            secret_key: Some("secret".to_string()),
            max_size: Some(1_024),
            dir_name_rule: None,
            file_name_rule: None,
            settings: Some(settings),
            node_id: None,
        }
    }

    fn group(permissions: Vec<u8>) -> cloudreve_schema::groups::Model {
        cloudreve_schema::groups::Model {
            id: 8,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            name: "Members".to_string(),
            max_storage: Some(4_096),
            speed_limit: None,
            permissions,
            settings: None,
            storage_policy_id: Some(7),
        }
    }

    fn user() -> cloudreve_schema::users::Model {
        cloudreve_schema::users::Model {
            id: 9,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            email: "user@example.test".to_string(),
            nick: "User".to_string(),
            password: Some("legacy".to_string()),
            status: "active".to_string(),
            storage: 512,
            two_factor_secret: None,
            avatar: Some("https://gravatar.example/avatar".to_string()),
            settings: Some(json!({"theme": "dark"})),
            group_users: 8,
        }
    }

    fn folder(file_type: i64) -> cloudreve_schema::files::Model {
        cloudreve_schema::files::Model {
            id: 10,
            created_at: now(),
            updated_at: now(),
            r#type: file_type,
            name: "Documents".to_string(),
            size: 0,
            primary_entity: None,
            is_symbolic: false,
            props: None,
            file_children: Some(2),
            storage_policy_files: Some(7),
            owner_id: 9,
        }
    }

    fn entity(id: i64, entity_type: i64, size: i64) -> cloudreve_schema::entities::Model {
        cloudreve_schema::entities::Model {
            id,
            created_at: now() + chrono::TimeDelta::seconds(id),
            updated_at: now(),
            deleted_at: None,
            r#type: entity_type,
            source: format!("objects/{id}"),
            size,
            reference_count: 1,
            upload_session_id: None,
            recycle_options: None,
            storage_policy_entities: 7,
            created_by: Some(9),
        }
    }

    fn share(
        id: i64,
        target_id: Option<i64>,
        owner_id: Option<i64>,
    ) -> cloudreve_schema::shares::Model {
        cloudreve_schema::shares::Model {
            id,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            password: Some("secret".to_string()),
            views: 5,
            downloads: 7,
            expires: Some(now() + chrono::TimeDelta::days(1)),
            remain_downloads: Some(3),
            props: Some(json!({"show_readme": true})),
            file_shares: target_id,
            user_shares: owner_id,
        }
    }

    fn metadata(id: i64, name: &str, value: &str) -> cloudreve_schema::metadata::Model {
        cloudreve_schema::metadata::Model {
            id,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            name: name.to_string(),
            value: value.to_string(),
            is_public: true,
            file_id: 10,
        }
    }

    fn direct_link(id: i64) -> cloudreve_schema::direct_links::Model {
        cloudreve_schema::direct_links::Model {
            id,
            created_at: now(),
            updated_at: now(),
            deleted_at: None,
            name: "legacy-name.txt".to_string(),
            downloads: 7,
            speed: 1_024,
            file_id: 10,
        }
    }

    fn ready<T>(conversion: Conversion<T>) -> T {
        conversion.into_ready().expect("ready conversion")
    }

    #[test]
    fn converts_every_supported_storage_driver() -> Result<()> {
        for (source, expected) in [
            ("local", MigrationStorageDriver::Local),
            ("s3", MigrationStorageDriver::S3),
            ("oss", MigrationStorageDriver::S3),
            ("ks3", MigrationStorageDriver::S3),
            ("obs", MigrationStorageDriver::S3),
            ("cos", MigrationStorageDriver::TencentCos),
        ] {
            let converted = ready(CloudreveConverter.convert(
                CloudreveStoragePolicyRecord {
                    policy: policy(
                        source,
                        json!({
                            "chunk_size": 128,
                            "file_type": ["jpg", "png"],
                            "s3_path_style": false
                        }),
                    ),
                    local_root: (source == "local").then(|| "/source".to_string()),
                },
                &ConversionContext,
            )?);
            assert_eq!(converted.driver, expected);
            assert_eq!(converted.chunk_size, 128);
            assert_eq!(converted.allowed_types, ["jpg", "png"]);
            assert!(!converted.s3_path_style);
            assert_eq!(converted.extensions["cloudreve_policy_type"], source);
            assert_eq!(
                converted.base_path,
                if source == "local" { "/source" } else { "" }
            );
        }
        Ok(())
    }

    #[test]
    fn skips_unsupported_or_encrypted_storage_policies() -> Result<()> {
        for (source, settings, expected_code) in [
            ("onedrive", json!({}), "unsupported_storage_driver"),
            (
                "s3",
                json!({"encryption": true}),
                "cloudreve_storage_encryption",
            ),
        ] {
            let converted = CloudreveConverter.convert(
                CloudreveStoragePolicyRecord {
                    policy: policy(source, settings),
                    local_root: None,
                },
                &ConversionContext,
            )?;
            let Conversion::Skipped(reason) = converted else {
                panic!("expected skipped conversion");
            };
            assert_eq!(reason.code, expected_code);
            assert!(!reason.message.is_empty());
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_policy_boundaries() {
        let missing_root = CloudreveConverter.convert(
            CloudreveStoragePolicyRecord {
                policy: policy("local", json!({})),
                local_root: None,
            },
            &ConversionContext,
        );
        assert!(format!("{:?}", missing_root.unwrap_err()).contains("no resolved target root"));

        let invalid_types = CloudreveConverter.convert(
            CloudreveStoragePolicyRecord {
                policy: policy("s3", json!({"file_type": "jpg"})),
                local_root: None,
            },
            &ConversionContext,
        );
        assert!(format!("{:?}", invalid_types.unwrap_err()).contains("must be an array"));

        let negative_chunk = CloudreveConverter.convert(
            CloudreveStoragePolicyRecord {
                policy: policy("s3", json!({"chunk_size": -1})),
                local_root: None,
            },
            &ConversionContext,
        );
        assert!(format!("{:?}", negative_chunk.unwrap_err()).contains("must not be negative"));
    }

    #[test]
    fn converts_group_user_and_folder_records() -> Result<()> {
        let converted_group = ready(CloudreveConverter.convert(
            CloudrevePolicyGroupRecord {
                group: group(vec![1]),
            },
            &ConversionContext,
        )?);
        assert_eq!(converted_group.source_id, 8);
        assert_eq!(converted_group.policy_source_id, Some(7));

        let converted_user = ready(CloudreveConverter.convert(
            CloudreveUserRecord {
                user: user(),
                group: Some(group(vec![1])),
                username: "user".to_string(),
            },
            &ConversionContext,
        )?);
        assert_eq!(converted_user.role, MigrationUserRole::Admin);
        assert_eq!(converted_user.status, MigrationUserStatus::Active);
        assert_eq!(converted_user.storage_quota, 4_096);
        assert_eq!(
            converted_user.avatar_source,
            MigrationAvatarSource::Gravatar
        );
        assert_eq!(converted_user.config, Some(json!({"theme": "dark"})));

        let converted_folder = ready(CloudreveConverter.convert(
            CloudreveFolderRecord { folder: folder(1) },
            &ConversionContext,
        )?);
        assert_eq!(converted_folder.parent_source_id, Some(2));
        assert_eq!(converted_folder.owner_source_id, 9);
        assert_eq!(converted_folder.policy_source_id, Some(7));
        Ok(())
    }

    #[test]
    fn handles_user_and_folder_boundaries() -> Result<()> {
        let mut disabled = user();
        disabled.status = "inactive".to_string();
        disabled.avatar = Some("/avatars/custom.png".to_string());
        let converted = ready(CloudreveConverter.convert(
            CloudreveUserRecord {
                user: disabled,
                group: None,
                username: "disabled".to_string(),
            },
            &ConversionContext,
        )?);
        assert_eq!(converted.role, MigrationUserRole::User);
        assert_eq!(converted.status, MigrationUserStatus::Disabled);
        assert_eq!(converted.storage_quota, 0);
        assert_eq!(converted.avatar_source, MigrationAvatarSource::Upload);

        let conversion = CloudreveConverter.convert(
            CloudreveFolderRecord { folder: folder(0) },
            &ConversionContext,
        )?;
        let Conversion::Skipped(reason) = conversion else {
            panic!("expected non-folder row to be skipped");
        };
        assert_eq!(reason.code, "not_a_folder");
        Ok(())
    }

    #[test]
    fn converts_blob_and_orders_file_versions() -> Result<()> {
        let blob = ready(CloudreveConverter.convert(
            CloudreveBlobRecord {
                entity: entity(12, 0, 512),
                reference_count: 3,
            },
            &ConversionContext,
        )?);
        assert_eq!(blob.source_id, 12);
        assert_eq!(blob.opaque_key, "cloudreve-000000000000000c");
        assert_eq!(blob.storage_path, "objects/12");
        assert_eq!(blob.reference_count, 3);

        let mut file = folder(0);
        file.id = 20;
        file.name = "archive.tar.gz".to_string();
        file.size = 512;
        file.primary_entity = Some(12);
        let converted = ready(CloudreveConverter.convert(
            CloudreveFileRecord {
                file,
                entities: vec![entity(12, 0, 512), entity(11, 0, 256)],
            },
            &ConversionContext,
        )?);
        assert_eq!(converted.preferred_blob_source_id, Some(12));
        assert_eq!(
            converted
                .versions
                .iter()
                .map(|version| version.blob_source_id)
                .collect::<Vec<_>>(),
            [11, 12]
        );
        Ok(())
    }

    #[test]
    fn handles_blob_and_file_boundaries() -> Result<()> {
        let conversion = CloudreveConverter.convert(
            CloudreveBlobRecord {
                entity: entity(12, 1, 512),
                reference_count: 1,
            },
            &ConversionContext,
        )?;
        assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == "not_a_blob"));

        let mut invalid_blob = entity(12, 0, 512);
        invalid_blob.source.clear();
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveBlobRecord {
                        entity: invalid_blob,
                        reference_count: 1,
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("empty storage path")
        );

        let mut symbolic = folder(0);
        symbolic.is_symbolic = true;
        let conversion = CloudreveConverter.convert(
            CloudreveFileRecord {
                file: symbolic,
                entities: vec![],
            },
            &ConversionContext,
        )?;
        assert!(
            matches!(conversion, Conversion::Skipped(reason) if reason.code == "symbolic_file")
        );

        let conversion = CloudreveConverter.convert(
            CloudreveFileRecord {
                file: folder(0),
                entities: vec![],
            },
            &ConversionContext,
        )?;
        assert!(
            matches!(conversion, Conversion::Skipped(reason) if reason.code == "missing_primary_entity")
        );

        let mut negative_version_file = folder(0);
        negative_version_file.primary_entity = Some(13);
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveFileRecord {
                        file: negative_version_file,
                        entities: vec![entity(13, 0, -1)],
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("negative size")
        );
        Ok(())
    }

    #[test]
    fn converts_file_and_folder_shares_with_download_semantics() -> Result<()> {
        for (target_type, expected_target) in [
            (0, MigrationShareTarget::File { source_id: 10 }),
            (1, MigrationShareTarget::Folder { source_id: 10 }),
        ] {
            let converted = ready(CloudreveConverter.convert(
                CloudreveShareRecord {
                    share: share(30, Some(10), Some(9)),
                    target: Some(folder(target_type)),
                },
                &ConversionContext,
            )?);
            assert_eq!(converted.source_id, 30);
            assert_eq!(converted.owner_source_id, 9);
            assert_eq!(converted.target, expected_target);
            assert_eq!(converted.plain_password.as_deref(), Some("secret"));
            assert_eq!(converted.max_downloads, 10);
            assert_eq!(converted.download_count, 7);
            assert_eq!(converted.view_count, 5);
        }

        let mut unlimited = share(31, Some(10), Some(9));
        unlimited.password = Some(String::new());
        unlimited.remain_downloads = None;
        let converted = ready(CloudreveConverter.convert(
            CloudreveShareRecord {
                share: unlimited,
                target: Some(folder(0)),
            },
            &ConversionContext,
        )?);
        assert_eq!(converted.plain_password, None);
        assert_eq!(converted.max_downloads, 0);
        assert_eq!(converted.download_count, 7);
        Ok(())
    }

    #[test]
    fn handles_share_boundaries_without_reactivating_deleted_rows() -> Result<()> {
        let mut deleted = share(30, Some(10), Some(9));
        deleted.deleted_at = Some(now());
        let conversion = CloudreveConverter.convert(
            CloudreveShareRecord {
                share: deleted,
                target: Some(folder(0)),
            },
            &ConversionContext,
        )?;
        assert!(
            matches!(conversion, Conversion::Skipped(reason) if reason.code == "deleted_share")
        );

        for (source, target, expected_code) in [
            (
                share(30, Some(10), None),
                Some(folder(0)),
                "missing_share_owner",
            ),
            (share(30, None, Some(9)), None, "missing_share_target"),
            (share(30, Some(10), Some(9)), None, "missing_share_target"),
            (
                share(30, Some(10), Some(9)),
                Some(folder(2)),
                "unsupported_share_target",
            ),
        ] {
            let conversion = CloudreveConverter.convert(
                CloudreveShareRecord {
                    share: source,
                    target,
                },
                &ConversionContext,
            )?;
            assert!(
                matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code)
            );
        }

        let mut negative = share(30, Some(10), Some(9));
        negative.remain_downloads = Some(-1);
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveShareRecord {
                        share: negative,
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("negative remaining downloads")
        );

        let mut overflow = share(30, Some(10), Some(9));
        overflow.downloads = i64::MAX;
        overflow.remain_downloads = Some(1);
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveShareRecord {
                        share: overflow,
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("download limit exceeds i64")
        );
        Ok(())
    }

    #[test]
    fn converts_public_and_private_metadata_for_files_and_folders() -> Result<()> {
        for (is_public, target_type, namespace, kind) in [
            (true, 0, "cloudreve.public", MigrationEntityKind::File),
            (false, 1, "cloudreve.private", MigrationEntityKind::Folder),
        ] {
            let mut source = metadata(40, "author", "Cloudreve");
            source.is_public = is_public;
            let converted = ready(CloudreveConverter.convert(
                CloudreveMetadataRecord {
                    metadata: source,
                    target: Some(folder(target_type)),
                },
                &ConversionContext,
            )?);
            let MigrationMetadata::Property(property) = converted else {
                panic!("expected property conversion");
            };
            assert_eq!(property.source_metadata_id, 40);
            assert_eq!(property.target.kind, kind);
            assert_eq!(property.target.source_id, 10);
            assert_eq!(property.namespace, namespace);
            assert_eq!(property.name, "author");
            assert_eq!(property.value.as_deref(), Some("Cloudreve"));
        }
        Ok(())
    }

    #[test]
    fn converts_tags_with_asterdrive_name_and_color_rules() -> Result<()> {
        for (source_name, source_color, expected_name, expected_color) in [
            ("tag:Important", "#AbC", "Important", "#aabbcc"),
            ("tag:  Project A  ", "#3B82F6", "Project A", "#3b82f6"),
            ("tag:Fallback", "invalid", "Fallback", DEFAULT_TAG_COLOR),
        ] {
            let converted = ready(CloudreveConverter.convert(
                CloudreveMetadataRecord {
                    metadata: metadata(41, source_name, source_color),
                    target: Some(folder(0)),
                },
                &ConversionContext,
            )?);
            let MigrationMetadata::TagAssignment(tag) = converted else {
                panic!("expected tag conversion");
            };
            assert_eq!(tag.source_metadata_id, 41);
            assert_eq!(tag.owner_source_id, 9);
            assert_eq!(tag.target.kind, MigrationEntityKind::File);
            assert_eq!(tag.name, expected_name);
            assert_eq!(tag.normalized_name, expected_name.to_lowercase());
            assert_eq!(tag.color, expected_color);
        }

        let long_name = format!("tag:{}", "x".repeat(65));
        let converted = ready(CloudreveConverter.convert(
            CloudreveMetadataRecord {
                metadata: metadata(42, &long_name, ""),
                target: Some(folder(1)),
            },
            &ConversionContext,
        )?);
        let MigrationMetadata::TagAssignment(tag) = converted else {
            panic!("expected tag conversion");
        };
        assert_eq!(tag.name.chars().count(), ASTER_DRIVE_TAG_NAME_MAX_CHARS);
        assert_eq!(tag.target.kind, MigrationEntityKind::Folder);

        let expanding_name = format!("tag:{}İ", "x".repeat(63));
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveMetadataRecord {
                        metadata: metadata(43, &expanding_name, "#abc"),
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("normalized tag name exceeds")
        );
        Ok(())
    }

    #[test]
    fn skips_deleted_missing_and_unsupported_metadata() -> Result<()> {
        let mut deleted = metadata(40, "author", "Cloudreve");
        deleted.deleted_at = Some(now());
        let cases = [
            (
                CloudreveMetadataRecord {
                    metadata: deleted,
                    target: Some(folder(0)),
                },
                "deleted_metadata",
            ),
            (
                CloudreveMetadataRecord {
                    metadata: metadata(41, "author", "Cloudreve"),
                    target: None,
                },
                "missing_metadata_target",
            ),
            (
                CloudreveMetadataRecord {
                    metadata: metadata(42, "author", "Cloudreve"),
                    target: Some(folder(2)),
                },
                "unsupported_metadata_target",
            ),
            (
                CloudreveMetadataRecord {
                    metadata: metadata(43, "tag:   ", "#abc"),
                    target: Some(folder(0)),
                },
                "empty_tag_name",
            ),
        ];
        for (source, expected_code) in cases {
            let conversion = CloudreveConverter.convert(source, &ConversionContext)?;
            assert!(
                matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code)
            );
        }
        Ok(())
    }

    #[test]
    fn validates_metadata_target_identity_and_persistence_limits() -> Result<()> {
        let mut mismatched_target = folder(0);
        mismatched_target.id = 11;
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveMetadataRecord {
                        metadata: metadata(40, "author", "Cloudreve"),
                        target: Some(mismatched_target),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("does not match target")
        );

        let unicode_boundary = "界".repeat(ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS);
        let converted = ready(CloudreveConverter.convert(
            CloudreveMetadataRecord {
                metadata: metadata(41, &unicode_boundary, ""),
                target: Some(folder(0)),
            },
            &ConversionContext,
        )?);
        let MigrationMetadata::Property(property) = converted else {
            panic!("expected property conversion");
        };
        assert_eq!(
            property.name.chars().count(),
            ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS
        );

        let too_long_name = "界".repeat(ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS + 1);
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveMetadataRecord {
                        metadata: metadata(42, &too_long_name, ""),
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("name exceeds")
        );

        let value_boundary = "x".repeat(ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES);
        assert!(matches!(
            CloudreveConverter.convert(
                CloudreveMetadataRecord {
                    metadata: metadata(43, "boundary", &value_boundary),
                    target: Some(folder(0)),
                },
                &ConversionContext,
            )?,
            Conversion::Ready(MigrationMetadata::Property(_))
        ));
        let too_long_value = "x".repeat(ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES + 1);
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveMetadataRecord {
                        metadata: metadata(44, "too-long", &too_long_value),
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("value exceeds")
        );
        Ok(())
    }

    #[test]
    fn converts_direct_links_as_file_scoped_legacy_records() -> Result<()> {
        let converted = ready(CloudreveConverter.convert(
            CloudreveDirectLinkRecord {
                direct_link: direct_link(50),
                target: Some(folder(0)),
            },
            &ConversionContext,
        )?);
        assert_eq!(converted.source_id, 50);
        assert_eq!(converted.file_source_id, 10);
        assert_eq!(converted.owner_source_id, 9);
        assert_eq!(converted.file_name, "Documents");
        assert_eq!(converted.source_name, "legacy-name.txt");
        assert_eq!(converted.source_downloads, 7);
        assert_eq!(converted.source_speed_limit, 1_024);
        Ok(())
    }

    #[test]
    fn handles_direct_link_boundaries_without_reactivating_deleted_rows() -> Result<()> {
        let mut deleted = direct_link(50);
        deleted.deleted_at = Some(now());
        for (source, target, expected_code) in [
            (deleted, Some(folder(0)), "deleted_direct_link"),
            (direct_link(51), None, "missing_direct_link_target"),
            (
                direct_link(52),
                Some(folder(1)),
                "unsupported_direct_link_target",
            ),
        ] {
            let conversion = CloudreveConverter.convert(
                CloudreveDirectLinkRecord {
                    direct_link: source,
                    target,
                },
                &ConversionContext,
            )?;
            assert!(
                matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code)
            );
        }

        let mut mismatched_target = folder(0);
        mismatched_target.id = 11;
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveDirectLinkRecord {
                        direct_link: direct_link(53),
                        target: Some(mismatched_target),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("does not match target")
        );

        let mut negative_downloads = direct_link(54);
        negative_downloads.downloads = -1;
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveDirectLinkRecord {
                        direct_link: negative_downloads,
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("negative download count")
        );

        let mut negative_speed = direct_link(55);
        negative_speed.speed = -1;
        assert!(
            CloudreveConverter
                .convert(
                    CloudreveDirectLinkRecord {
                        direct_link: negative_speed,
                        target: Some(folder(0)),
                    },
                    &ConversionContext,
                )
                .unwrap_err()
                .to_string()
                .contains("negative speed limit")
        );
        Ok(())
    }
}
