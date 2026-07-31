//! AsterDrive database writer for resolved migration-domain values.

use color_eyre::eyre::{Result, WrapErr};
use sea_orm::{ActiveModelTrait, DatabaseTransaction, Set};
use serde_json::{Map, Value, json};

use aster_drive_model as aster_drive_schema;
use aster_drive_model::types::{
    AvatarSource, DriverType, StoredStoragePolicyAllowedTypes, StoredStoragePolicyOptions,
    StoredUserConfig, UserRole, UserStatus,
};

use aster_drive_migration_core::{
    MigrationAvatarSource, MigrationFolder, MigrationPolicyGroup, MigrationStorageDriver,
    MigrationStoragePolicy, MigrationUser, MigrationUserRole, MigrationUserStatus,
};

pub struct ResolvedPolicyGroup {
    pub group: MigrationPolicyGroup,
    pub policy_id: Option<i64>,
}

pub struct ResolvedUser {
    pub user: MigrationUser,
    pub policy_group_id: Option<i64>,
}

pub struct ResolvedFolder {
    pub folder: MigrationFolder,
    pub parent_id: Option<i64>,
    pub owner_id: i64,
    pub owner_username: String,
    pub policy_id: Option<i64>,
}

pub struct AsterDriveWriter<'a> {
    transaction: &'a DatabaseTransaction,
}

impl<'a> AsterDriveWriter<'a> {
    pub const fn new(transaction: &'a DatabaseTransaction) -> Self {
        Self { transaction }
    }

    pub async fn write_policy(
        &self,
        policy: MigrationStoragePolicy,
        is_default: bool,
    ) -> Result<i64> {
        let source_id = policy.source_id;
        let mut options = Map::from_iter([
            ("s3_path_style".to_string(), json!(policy.s3_path_style)),
            (
                "object_storage_upload_strategy".to_string(),
                json!("relay_stream"),
            ),
            (
                "object_storage_download_strategy".to_string(),
                json!("relay_stream"),
            ),
        ]);
        options.extend(policy.extensions);
        let target = aster_drive_schema::entities::storage_policy::ActiveModel {
            name: Set(policy.name),
            driver_type: Set(match policy.driver {
                MigrationStorageDriver::Local => DriverType::Local,
                MigrationStorageDriver::S3 => DriverType::S3,
                MigrationStorageDriver::TencentCos => DriverType::TencentCos,
            }),
            endpoint: Set(policy.endpoint),
            bucket: Set(policy.bucket),
            access_key: Set(policy.access_key),
            secret_key: Set(policy.secret_key),
            base_path: Set(policy.base_path),
            remote_node_id: Set(None),
            remote_storage_target_key: Set(None),
            max_file_size: Set(policy.max_file_size),
            allowed_types: Set(StoredStoragePolicyAllowedTypes::from(
                serde_json::to_string(&policy.allowed_types)
                    .wrap_err("serialize storage policy allowed types")?,
            )),
            options: Set(StoredStoragePolicyOptions::from(
                Value::Object(options).to_string(),
            )),
            is_default: Set(is_default),
            chunk_size: Set(policy.chunk_size),
            created_at: Set(policy.created_at),
            updated_at: Set(policy.updated_at),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate storage policy {source_id}"))?;
        Ok(target.id)
    }

    pub async fn write_policy_group(&self, resolved: ResolvedPolicyGroup) -> Result<i64> {
        let ResolvedPolicyGroup { group, policy_id } = resolved;
        let source_id = group.source_id;
        let target = aster_drive_schema::entities::storage_policy_group::ActiveModel {
            name: Set(group.name),
            description: Set(group.description),
            is_enabled: Set(true),
            is_default: Set(false),
            created_at: Set(group.created_at),
            updated_at: Set(group.updated_at),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve group {source_id}"))?;

        if let Some(target_policy_id) = policy_id {
            aster_drive_schema::entities::storage_policy_group_item::ActiveModel {
                group_id: Set(target.id),
                policy_id: Set(target_policy_id),
                priority: Set(0),
                min_file_size: Set(0),
                max_file_size: Set(0),
                created_at: Set(group.created_at),
                ..Default::default()
            }
            .insert(self.transaction)
            .await
            .wrap_err_with(|| format!("link Cloudreve group {source_id} storage policy"))?;
        }
        Ok(target.id)
    }

    pub async fn write_user(&self, resolved: ResolvedUser, password_hash: &str) -> Result<i64> {
        let ResolvedUser {
            user,
            policy_group_id,
        } = resolved;
        let source_id = user.source_id;
        let target = aster_drive_schema::entities::user::ActiveModel {
            username: Set(user.username),
            email: Set(user.email),
            password_hash: Set(password_hash.to_string()),
            role: Set(match user.role {
                MigrationUserRole::Admin => UserRole::Admin,
                MigrationUserRole::User => UserRole::User,
            }),
            status: Set(match user.status {
                MigrationUserStatus::Active => UserStatus::Active,
                MigrationUserStatus::Disabled => UserStatus::Disabled,
            }),
            session_version: Set(1),
            email_verified_at: Set(
                (user.status == MigrationUserStatus::Active).then_some(user.created_at)
            ),
            pending_email: Set(None),
            storage_used: Set(user.storage_used),
            storage_quota: Set(user.storage_quota),
            policy_group_id: Set(policy_group_id),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
            config: Set(user
                .config
                .map(|config| StoredUserConfig::from(config.to_string()))),
            must_change_password: Set(true),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve user {source_id}"))?;

        aster_drive_schema::entities::user_profile::ActiveModel {
            user_id: Set(target.id),
            display_name: Set(Some(user.display_name)),
            wopi_user_info: Set(None),
            avatar_source: Set(match user.avatar_source {
                MigrationAvatarSource::None => AvatarSource::None,
                MigrationAvatarSource::Gravatar => AvatarSource::Gravatar,
                MigrationAvatarSource::Upload => AvatarSource::Upload,
            }),
            avatar_key: Set(user.avatar_key),
            avatar_version: Set(0),
            created_at: Set(user.created_at),
            updated_at: Set(user.updated_at),
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("create profile for Cloudreve user {source_id}"))?;
        Ok(target.id)
    }

    pub async fn write_folder(&self, resolved: ResolvedFolder) -> Result<i64> {
        let ResolvedFolder {
            folder,
            parent_id,
            owner_id,
            owner_username,
            policy_id,
        } = resolved;
        let source_id = folder.source_id;
        let target = aster_drive_schema::entities::folder::ActiveModel {
            name: Set(folder.name),
            parent_id: Set(parent_id),
            team_id: Set(None),
            owner_user_id: Set(Some(owner_id)),
            created_by_user_id: Set(Some(owner_id)),
            created_by_username: Set(owner_username),
            policy_id: Set(policy_id),
            created_at: Set(folder.created_at),
            updated_at: Set(folder.updated_at),
            deleted_at: Set(None),
            is_locked: Set(false),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve folder {source_id}"))?;
        Ok(target.id)
    }
}
