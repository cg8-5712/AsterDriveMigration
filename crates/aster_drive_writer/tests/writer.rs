use std::collections::BTreeMap;

use aster_drive_migration_core::{
    MigrationAvatarSource, MigrationBlob, MigrationDirectLink, MigrationFile, MigrationFileVersion,
    MigrationFolder, MigrationStorageDriver, MigrationStoragePolicy, MigrationUser,
    MigrationUserRole, MigrationUserStatus,
};
use aster_drive_model as aster_drive_schema;
use aster_drive_model::types::{EntityType, TagScopeType};
use aster_drive_writer::*;
use color_eyre::eyre::{Result, WrapErr};
use sea_orm::{
    ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, TransactionTrait,
};
use serde_json::Value;

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

fn direct_link(source_id: i64) -> MigrationDirectLink {
    MigrationDirectLink {
        source_id,
        file_source_id: 71,
        owner_source_id: 2,
        file_name: "report 2026.txt".to_string(),
        source_name: "legacy-name.txt".to_string(),
        source_downloads: 7,
        source_speed_limit: 1_024,
    }
}

async fn write_file_target(
    transaction: &DatabaseTransaction,
    policy_id: i64,
    user_id: i64,
    folder_id: i64,
) -> Result<i64> {
    let writer = AsterDriveWriter::new(transaction);
    let blob_id = writer
        .write_blob(ResolvedBlob {
            blob: blob(70, "objects/property-target", 64, 1),
            policy_id,
        })
        .await?;
    Ok(writer
        .write_file(ResolvedFile {
            file: file(71),
            folder_id: Some(folder_id),
            owner_id: user_id,
            owner_username: "owner".to_string(),
            primary_blob_id: blob_id,
            primary_blob_size: 64,
            historical_versions: Vec::new(),
        })
        .await?
        .target_id)
}
#[path = "writer/blob_file.rs"]
mod blob_file;
#[path = "writer/direct_link.rs"]
mod direct_link;
#[path = "writer/metadata.rs"]
mod metadata;
#[path = "writer/share.rs"]
mod share;
