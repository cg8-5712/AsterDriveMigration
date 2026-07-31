//! AsterDrive database writer for resolved migration-domain values.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::unreachable,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo
    )
)]

use color_eyre::eyre::{Result, WrapErr};
use sea_orm::{ActiveModelTrait, DatabaseTransaction, Set};
use serde_json::{Map, Value, json};

use aster_drive_model as aster_drive_schema;
use aster_drive_model::types::{
    AvatarSource, DriverType, StoredStoragePolicyAllowedTypes, StoredStoragePolicyOptions,
    StoredUserConfig, UserRole, UserStatus,
};

use aster_drive_migration_core::{
    MigrationAvatarSource, MigrationBlob, MigrationFile, MigrationFolder, MigrationPolicyGroup,
    MigrationStorageDriver, MigrationStoragePolicy, MigrationUser, MigrationUserRole,
    MigrationUserStatus,
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

pub struct ResolvedBlob {
    pub blob: MigrationBlob,
    pub policy_id: i64,
}

pub struct ResolvedFileVersion {
    pub blob_id: i64,
    pub size: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct ResolvedFile {
    pub file: MigrationFile,
    pub folder_id: Option<i64>,
    pub owner_id: i64,
    pub owner_username: String,
    pub primary_blob_id: i64,
    pub primary_blob_size: i64,
    pub historical_versions: Vec<ResolvedFileVersion>,
}

pub enum ResolvedShareTarget {
    File { target_id: i64 },
    Folder { target_id: i64 },
}

pub struct ResolvedShare {
    pub source_id: i64,
    pub owner_id: i64,
    pub target: ResolvedShareTarget,
    pub password_hash: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_downloads: i64,
    pub download_count: i64,
    pub view_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrittenFile {
    pub target_id: i64,
    pub version_count: usize,
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

    pub async fn write_blob(&self, resolved: ResolvedBlob) -> Result<i64> {
        let ResolvedBlob { blob, policy_id } = resolved;
        let source_id = blob.source_id;
        let target = aster_drive_schema::entities::file_blob::ActiveModel {
            hash: Set(blob.opaque_key),
            size: Set(blob.size),
            policy_id: Set(policy_id),
            storage_path: Set(blob.storage_path),
            // Cloudreve thumbnails do not carry AsterDrive's processor/version cache contract.
            thumbnail_path: Set(None),
            thumbnail_processor: Set(None),
            thumbnail_version: Set(None),
            ref_count: Set(blob.reference_count),
            created_at: Set(blob.created_at),
            updated_at: Set(blob.updated_at),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve entity {source_id}"))?;
        Ok(target.id)
    }

    pub async fn write_file(&self, resolved: ResolvedFile) -> Result<WrittenFile> {
        let ResolvedFile {
            file,
            folder_id,
            owner_id,
            owner_username,
            primary_blob_id,
            primary_blob_size,
            historical_versions,
        } = resolved;
        let source_id = file.source_id;
        // Cloudreve v4 has no stable MIME column. Use the filename only as the MIME hint;
        // AsterDrive's ActiveModelBehavior delegates classification to the Forge crate.
        let mime_type = mime_guess::from_path(&file.name)
            .first_or_octet_stream()
            .essence_str()
            .to_string();
        let target = aster_drive_schema::entities::file::ActiveModel {
            name: Set(file.name),
            folder_id: Set(folder_id),
            team_id: Set(None),
            blob_id: Set(primary_blob_id),
            size: Set(primary_blob_size),
            owner_user_id: Set(Some(owner_id)),
            created_by_user_id: Set(Some(owner_id)),
            created_by_username: Set(owner_username),
            mime_type: Set(mime_type),
            created_at: Set(file.created_at),
            updated_at: Set(file.updated_at),
            deleted_at: Set(None),
            is_locked: Set(false),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve file {source_id}"))?;

        let version_count = historical_versions.len();
        for (index, version) in historical_versions.into_iter().enumerate() {
            aster_drive_schema::entities::file_version::ActiveModel {
                file_id: Set(target.id),
                blob_id: Set(version.blob_id),
                version: Set(i32::try_from(index + 1).wrap_err("file version exceeds i32")?),
                size: Set(version.size),
                created_at: Set(version.created_at),
                ..Default::default()
            }
            .insert(self.transaction)
            .await
            .wrap_err_with(|| format!("migrate version {} for file {source_id}", index + 1))?;
        }
        Ok(WrittenFile {
            target_id: target.id,
            version_count,
        })
    }

    pub async fn write_share(&self, resolved: ResolvedShare) -> Result<i64> {
        let ResolvedShare {
            source_id,
            owner_id,
            target,
            password_hash,
            expires_at,
            max_downloads,
            download_count,
            view_count,
            created_at,
            updated_at,
        } = resolved;
        let (file_id, folder_id) = match target {
            ResolvedShareTarget::File { target_id } => (Some(target_id), None),
            ResolvedShareTarget::Folder { target_id } => (None, Some(target_id)),
        };
        let target = aster_drive_schema::entities::share::ActiveModel {
            token: Set(uuid::Uuid::new_v4().simple().to_string()),
            user_id: Set(owner_id),
            team_id: Set(None),
            file_id: Set(file_id),
            folder_id: Set(folder_id),
            password: Set(password_hash),
            expires_at: Set(expires_at),
            max_downloads: Set(max_downloads),
            download_count: Set(download_count),
            view_count: Set(view_count),
            created_at: Set(created_at),
            updated_at: Set(updated_at),
            ..Default::default()
        }
        .insert(self.transaction)
        .await
        .wrap_err_with(|| format!("migrate Cloudreve share {source_id}"))?;
        Ok(target.id)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aster_drive_migration_core::{
        MigrationAvatarSource, MigrationFileVersion, MigrationStorageDriver, MigrationUserRole,
        MigrationUserStatus,
    };
    use sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
        TransactionTrait,
    };

    use super::*;

    async fn database() -> Result<DatabaseConnection> {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.max_connections(1);
        let database = Database::connect(options)
            .await
            .wrap_err("connect writer test database")?;
        database
            .execute_unprepared("PRAGMA foreign_keys = ON")
            .await
            .wrap_err("enable SQLite foreign keys")?;
        aster_drive_schema_migration::Migrator::up(&database, None)
            .await
            .wrap_err("apply AsterDrive schema migrations")?;
        Ok(database)
    }

    async fn write_prerequisites(transaction: &DatabaseTransaction) -> Result<(i64, i64, i64)> {
        let now = chrono::Utc::now();
        let writer = AsterDriveWriter::new(transaction);
        let policy_id = writer
            .write_policy(
                MigrationStoragePolicy {
                    source_id: 1,
                    name: "Local".to_string(),
                    driver: MigrationStorageDriver::Local,
                    endpoint: String::new(),
                    bucket: String::new(),
                    access_key: String::new(),
                    secret_key: String::new(),
                    base_path: "/storage".to_string(),
                    max_file_size: 0,
                    allowed_types: Vec::new(),
                    s3_path_style: true,
                    extensions: BTreeMap::new(),
                    chunk_size: 0,
                    created_at: now,
                    updated_at: now,
                },
                true,
            )
            .await?;
        let user_id = writer
            .write_user(
                ResolvedUser {
                    user: MigrationUser {
                        source_id: 2,
                        username: "owner".to_string(),
                        email: "owner@example.test".to_string(),
                        display_name: "Owner".to_string(),
                        role: MigrationUserRole::User,
                        status: MigrationUserStatus::Active,
                        storage_used: 0,
                        storage_quota: 0,
                        policy_group_source_id: 0,
                        config: None,
                        avatar_source: MigrationAvatarSource::None,
                        avatar_key: None,
                        created_at: now,
                        updated_at: now,
                    },
                    policy_group_id: None,
                },
                "migration-test-password-hash",
            )
            .await?;
        let folder_id = writer
            .write_folder(ResolvedFolder {
                folder: MigrationFolder {
                    source_id: 3,
                    name: "Documents".to_string(),
                    parent_source_id: None,
                    owner_source_id: 2,
                    policy_source_id: Some(1),
                    created_at: now,
                    updated_at: now,
                },
                parent_id: None,
                owner_id: user_id,
                owner_username: "owner".to_string(),
                policy_id: Some(policy_id),
            })
            .await?;
        Ok((policy_id, user_id, folder_id))
    }

    fn blob(source_id: i64, storage_path: &str, size: i64, reference_count: i32) -> MigrationBlob {
        let now = chrono::Utc::now();
        MigrationBlob {
            source_id,
            policy_source_id: 1,
            opaque_key: format!("cloudreve-{source_id:016x}"),
            storage_path: storage_path.to_string(),
            size,
            reference_count,
            created_at: now,
            updated_at: now,
        }
    }

    fn file(source_id: i64) -> MigrationFile {
        let now = chrono::Utc::now();
        MigrationFile {
            source_id,
            name: "archive.tar.gz".to_string(),
            owner_source_id: 2,
            folder_source_id: Some(3),
            preferred_blob_source_id: Some(11),
            versions: vec![MigrationFileVersion {
                blob_source_id: 11,
                size: 512,
                created_at: now,
            }],
            created_at: now,
            updated_at: now,
        }
    }

    fn share(source_id: i64) -> ResolvedShare {
        let now = chrono::Utc::now();
        ResolvedShare {
            source_id,
            owner_id: 0,
            target: ResolvedShareTarget::Folder { target_id: 0 },
            password_hash: Some("$argon2id$test-hash".to_string()),
            expires_at: Some(now + chrono::Duration::days(1)),
            max_downloads: 10,
            download_count: 7,
            view_count: 5,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn writes_blob_file_and_versions_with_asterdrive_semantics() -> Result<()> {
        let database = database().await?;
        let transaction = database.begin().await?;
        let (policy_id, user_id, folder_id) = write_prerequisites(&transaction).await?;
        let writer = AsterDriveWriter::new(&transaction);
        let historical_blob_id = writer
            .write_blob(ResolvedBlob {
                blob: blob(10, "objects/history", 256, 1),
                policy_id,
            })
            .await?;
        let current_blob_id = writer
            .write_blob(ResolvedBlob {
                blob: blob(11, "objects/current", 512, 1),
                policy_id,
            })
            .await?;
        let historical_created_at = chrono::Utc::now() - chrono::Duration::days(1);
        let written = writer
            .write_file(ResolvedFile {
                file: file(20),
                folder_id: Some(folder_id),
                owner_id: user_id,
                owner_username: "owner".to_string(),
                primary_blob_id: current_blob_id,
                primary_blob_size: 512,
                historical_versions: vec![ResolvedFileVersion {
                    blob_id: historical_blob_id,
                    size: 256,
                    created_at: historical_created_at,
                }],
            })
            .await?;
        transaction.commit().await?;

        assert_eq!(written.version_count, 1);
        let stored_file = aster_drive_schema::entities::file::Entity::find_by_id(written.target_id)
            .one(&database)
            .await?
            .expect("written file");
        assert_eq!(stored_file.blob_id, current_blob_id);
        assert_eq!(stored_file.size, 512);
        assert_eq!(stored_file.folder_id, Some(folder_id));
        assert_eq!(stored_file.mime_type, "application/gzip");
        assert_eq!(stored_file.extension, "gz");
        assert_eq!(stored_file.compound_extension.as_deref(), Some("tar.gz"));
        assert_eq!(stored_file.file_category.as_str(), "archive");

        let versions = aster_drive_schema::entities::file_version::Entity::find()
            .all(&database)
            .await?;
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].file_id, written.target_id);
        assert_eq!(versions[0].blob_id, historical_blob_id);
        assert_eq!(versions[0].version, 1);
        assert_eq!(versions[0].size, 256);
        assert_eq!(versions[0].created_at, historical_created_at);

        let current_blob =
            aster_drive_schema::entities::file_blob::Entity::find_by_id(current_blob_id)
                .one(&database)
                .await?
                .expect("current blob");
        assert_eq!(current_blob.hash, "cloudreve-000000000000000b");
        assert_eq!(current_blob.storage_path, "objects/current");
        assert_eq!(current_blob.size, 512);
        assert_eq!(current_blob.ref_count, 1);
        assert_eq!(current_blob.thumbnail_path, None);
        assert_eq!(current_blob.thumbnail_processor, None);
        assert_eq!(current_blob.thumbnail_version, None);
        Ok(())
    }

    #[tokio::test]
    async fn file_and_versions_remain_atomic_when_a_version_blob_is_missing() -> Result<()> {
        let database = database().await?;
        let setup = database.begin().await?;
        let (policy_id, user_id, folder_id) = write_prerequisites(&setup).await?;
        let current_blob_id = AsterDriveWriter::new(&setup)
            .write_blob(ResolvedBlob {
                blob: blob(11, "objects/current", 512, 1),
                policy_id,
            })
            .await?;
        setup.commit().await?;

        let transaction = database.begin().await?;
        let result = AsterDriveWriter::new(&transaction)
            .write_file(ResolvedFile {
                file: file(21),
                folder_id: Some(folder_id),
                owner_id: user_id,
                owner_username: "owner".to_string(),
                primary_blob_id: current_blob_id,
                primary_blob_size: 512,
                historical_versions: vec![ResolvedFileVersion {
                    blob_id: i64::MAX,
                    size: 256,
                    created_at: chrono::Utc::now(),
                }],
            })
            .await;
        assert!(result.is_err());
        transaction.rollback().await?;

        assert_eq!(
            aster_drive_schema::entities::file::Entity::find()
                .count(&database)
                .await?,
            0
        );
        assert_eq!(
            aster_drive_schema::entities::file_version::Entity::find()
                .count(&database)
                .await?,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn writes_share_with_exact_target_and_counters() -> Result<()> {
        let database = database().await?;
        let transaction = database.begin().await?;
        let (_, user_id, folder_id) = write_prerequisites(&transaction).await?;
        let target_id = AsterDriveWriter::new(&transaction)
            .write_share(ResolvedShare {
                owner_id: user_id,
                target: ResolvedShareTarget::Folder {
                    target_id: folder_id,
                },
                ..share(30)
            })
            .await?;
        let duplicate_target_id = AsterDriveWriter::new(&transaction)
            .write_share(ResolvedShare {
                owner_id: user_id,
                target: ResolvedShareTarget::Folder {
                    target_id: folder_id,
                },
                ..share(31)
            })
            .await?;
        transaction.commit().await?;

        let stored = aster_drive_schema::entities::share::Entity::find_by_id(target_id)
            .one(&database)
            .await?
            .expect("written share");
        assert_eq!(stored.token.len(), 32);
        assert!(
            stored
                .token
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_eq!(stored.user_id, user_id);
        assert_eq!(stored.team_id, None);
        assert_eq!(stored.file_id, None);
        assert_eq!(stored.folder_id, Some(folder_id));
        assert_eq!(stored.password.as_deref(), Some("$argon2id$test-hash"));
        assert_eq!(stored.max_downloads, 10);
        assert_eq!(stored.download_count, 7);
        assert_eq!(stored.view_count, 5);
        let duplicate =
            aster_drive_schema::entities::share::Entity::find_by_id(duplicate_target_id)
                .one(&database)
                .await?
                .expect("duplicate target share");
        assert_ne!(stored.token, duplicate.token);
        assert_eq!(duplicate.folder_id, Some(folder_id));
        assert_eq!(
            aster_drive_schema::entities::share::Entity::find()
                .count(&database)
                .await?,
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_share_owner_rolls_back_without_partial_rows() -> Result<()> {
        let database = database().await?;
        let setup = database.begin().await?;
        let (_, _, folder_id) = write_prerequisites(&setup).await?;
        setup.commit().await?;

        let transaction = database.begin().await?;
        let result = AsterDriveWriter::new(&transaction)
            .write_share(ResolvedShare {
                owner_id: i64::MAX,
                target: ResolvedShareTarget::Folder {
                    target_id: folder_id,
                },
                password_hash: None,
                ..share(31)
            })
            .await;
        assert!(result.is_err());
        transaction.rollback().await?;
        assert_eq!(
            aster_drive_schema::entities::share::Entity::find()
                .count(&database)
                .await?,
            0
        );
        Ok(())
    }
}
