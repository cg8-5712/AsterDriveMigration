mod support;

use aster_drive_migration::migration::*;
use aster_drive_model as aster_drive_schema;
use aster_drive_model::types::{BackgroundTaskKind, BackgroundTaskStatus, UserRole};
use color_eyre::eyre::Result;
use sea_orm::ConnectionTrait;
use sea_orm::{ActiveModelTrait, Database, EntityTrait, PaginatorTrait, Set};
use support::{
    create_source_schema, create_target_schema, seed_extra_blob_entities, seed_extra_files,
    seed_source, sqlite_url,
};

#[tokio::test]
async fn preflight_rejects_orphan_source_relations() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-preflight-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    source
        .execute_unprepared("PRAGMA foreign_keys = OFF")
        .await?;
    cloudreve_schema::file_entities::ActiveModel {
        file_id: Set(999_001),
        entity_id: Set(999_002),
    }
    .insert(&source)
    .await?;

    source.close().await?;

    let target_path = std::env::temp_dir().join(format!("asterdrive-preflight-{suffix}.db"));
    let target_url = sqlite_url(&target_path);
    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let report = inspect(&source_url, &target_url, false).await?;
    assert!(report.preflight.performed);
    assert!(!report.preflight.passed);
    assert!(report.preflight.checks.iter().any(|check| {
        check.name == "source_file_entity_relations" && !check.passed && check.actual == "1"
    }));

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}

#[tokio::test]
async fn migrates_minimal_cloudreve_database() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    source.close().await?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "C:/cloudreve".to_string(),
        local_policy_roots: std::collections::BTreeMap::new(),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: None,
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    })
    .await?;

    assert_eq!(report.migrated_users, 1);
    assert_eq!(report.migrated_folders, 1);
    assert_eq!(report.migrated_files, 1);
    assert_eq!(report.migrated_blobs, 1);
    assert_eq!(report.migrated_shares, 1);
    assert_eq!(report.migrated_properties, 3);
    assert_eq!(report.migrated_tags, 1);
    assert_eq!(report.migrated_tag_assignments, 1);
    assert_eq!(report.migrated_direct_links, 1);
    assert_eq!(report.migrated_tasks, 2);
    assert!(report.validation.performed);
    assert!(report.validation.passed);
    assert!(report.validation.checks.iter().all(|check| check.passed));
    assert_eq!(report.mappings.users.len(), 1);
    assert_eq!(report.mappings.folders.len(), 1);
    assert_eq!(report.mappings.files.len(), 1);
    assert_eq!(report.mappings.blobs.len(), 1);
    assert_eq!(report.mappings.shares.len(), 1);
    assert_eq!(report.mappings.tasks.len(), 2);
    assert_eq!(report.direct_links.len(), 1);
    assert!(report.direct_links[0].url.starts_with("/d/v2."));
    assert_eq!(report.tag_assignments.len(), 1);
    assert_eq!(report.tag_assignments[0].target_entity_type, "file");

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::user::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::folder::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::file::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::file_blob::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::share::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::tag::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::background_task::Entity::find()
            .count(&target)
            .await?,
        2
    );
    assert_eq!(
        aster_drive_schema::entities::entity_property::Entity::find()
            .count(&target)
            .await?,
        3
    );
    let properties = aster_drive_schema::entities::entity_property::Entity::find()
        .all(&target)
        .await?;
    assert!(
        properties
            .iter()
            .any(|property| { property.namespace == "system.tags" && property.value.is_none() })
    );
    let direct_link = properties
        .iter()
        .find(|property| property.namespace == "cloudreve.direct_links")
        .and_then(|property| property.value.as_deref())
        .expect("migrated direct link mapping");
    assert!(direct_link.contains("/d/v2."));
    let tasks = aster_drive_schema::entities::background_task::Entity::find()
        .all(&target)
        .await?;
    assert!(tasks.iter().all(|task| {
        matches!(task.status.as_str(), "succeeded" | "failed" | "canceled")
            && task.kind == BackgroundTaskKind::SystemRuntime
            && task.lease_expires_at.is_none()
    }));
    assert!(
        tasks
            .iter()
            .any(|task| task.status == BackgroundTaskStatus::Succeeded)
    );
    assert!(
        tasks
            .iter()
            .any(|task| task.status == BackgroundTaskStatus::Canceled)
    );
    let blob = aster_drive_schema::entities::file_blob::Entity::find()
        .one(&target)
        .await?
        .unwrap();
    assert_eq!(blob.storage_path, "uploads/object.bin");
    let files = aster_drive_schema::entities::file::Entity::find()
        .all(&target)
        .await?;
    let versions = aster_drive_schema::entities::file_version::Entity::find()
        .all(&target)
        .await?;
    let expected_ref_count = i32::try_from(
        files.iter().filter(|file| file.blob_id == blob.id).count()
            + versions
                .iter()
                .filter(|version| version.blob_id == blob.id)
                .count(),
    )?;
    assert_eq!(blob.ref_count, expected_ref_count);
    let user = aster_drive_schema::entities::user::Entity::find()
        .one(&target)
        .await?
        .unwrap();
    assert!(user.must_change_password);
    assert_eq!(user.role, UserRole::Admin);
    let expected_storage_used = files.iter().map(|file| file.size).sum::<i64>()
        + versions.iter().map(|version| version.size).sum::<i64>();
    assert_eq!(user.storage_used, expected_storage_used);
    assert!(
        report
            .validation
            .checks
            .iter()
            .any(|check| check.name == "blob_ref_counts_recalculated" && check.passed)
    );
    assert!(
        report
            .validation
            .checks
            .iter()
            .any(|check| check.name == "storage_usage_recalculated" && check.passed)
    );
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}

#[tokio::test]
async fn resumes_from_last_completed_stage() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let run_id = format!("resume-test-{suffix}");
    let source_path = std::env::temp_dir().join(format!("cloudreve-resume-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-resume-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    source.close().await?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target
        .execute_unprepared(
            "CREATE TRIGGER fail_folder_insert BEFORE INSERT ON folders \
             BEGIN SELECT RAISE(ABORT, 'forced folder stage failure'); END",
        )
        .await?;
    target.close().await?;

    let options = MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "C:/cloudreve".to_string(),
        local_policy_roots: std::collections::BTreeMap::new(),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: Some(run_id.clone()),
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    };

    let error = migrate(options.clone()).await.unwrap_err();
    assert!(error.to_string().contains(&run_id));

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::storage_policy::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::user::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::folder::Entity::find()
            .count(&target)
            .await?,
        0
    );
    let failed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(failed_checkpoint.status, "failed");
    assert_eq!(
        failed_checkpoint.last_completed_stage.as_deref(),
        Some("users")
    );
    target
        .execute_unprepared("DROP TRIGGER fail_folder_insert")
        .await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        resume: true,
        ..options
    })
    .await?;
    assert!(report.resumed);
    assert_eq!(report.run_id.as_deref(), Some(run_id.as_str()));
    assert!(report.validation.passed);
    assert_eq!(report.migrated_users, 1);
    assert_eq!(report.migrated_folders, 1);

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::user::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::folder::Entity::find()
            .count(&target)
            .await?,
        1
    );
    assert_eq!(
        aster_drive_schema::entities::file::Entity::find()
            .count(&target)
            .await?,
        1
    );
    let completed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(completed_checkpoint.status, "completed");
    assert_eq!(
        completed_checkpoint.last_completed_stage.as_deref(),
        Some("tasks")
    );
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}

#[tokio::test]
async fn resumes_blobs_from_last_committed_batch() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let run_id = format!("blob-resume-test-{suffix}");
    let source_path = std::env::temp_dir().join(format!("cloudreve-blob-resume-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-blob-resume-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let extra_blob_ids = seed_extra_blob_entities(&source, 3).await?;
    source.close().await?;

    let failing_blob_id = extra_blob_ids[1];
    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target
        .execute_unprepared(&format!(
            "CREATE TRIGGER fail_blob_batch BEFORE INSERT ON file_blobs \
             WHEN NEW.hash = '{}' \
             BEGIN SELECT RAISE(ABORT, 'forced blob batch failure'); END",
            format!("cloudreve-{failing_blob_id:016x}")
        ))
        .await?;
    target.close().await?;

    let options = MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "C:/cloudreve".to_string(),
        local_policy_roots: std::collections::BTreeMap::new(),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: Some(run_id.clone()),
        resume: false,
        blob_batch_size: 2,
        file_batch_size: 500,
    };

    let error = migrate(options.clone()).await.unwrap_err();
    assert!(error.to_string().contains("blobs"));

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::file_blob::Entity::find()
            .count(&target)
            .await?,
        2
    );
    let failed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(failed_checkpoint.status, "failed");
    assert_eq!(
        failed_checkpoint.last_completed_stage.as_deref(),
        Some("folders")
    );
    let failed_report = migration_run_report(&target_url, &run_id).await?;
    assert_eq!(failed_report.migrated_blobs, 2);
    target
        .execute_unprepared("DROP TRIGGER fail_blob_batch")
        .await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        resume: true,
        ..options
    })
    .await?;
    assert!(report.resumed);
    assert_eq!(report.migrated_blobs, 4);
    assert_eq!(report.mappings.blobs.len(), 4);
    assert!(report.validation.passed);

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::file_blob::Entity::find()
            .count(&target)
            .await?,
        4
    );
    let completed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(completed_checkpoint.status, "completed");
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}

#[tokio::test]
async fn resumes_files_from_last_committed_batch() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let run_id = format!("file-resume-test-{suffix}");
    let source_path = std::env::temp_dir().join(format!("cloudreve-file-resume-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-file-resume-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let extra_blob_ids = seed_extra_blob_entities(&source, 3).await?;
    let _extra_file_ids = seed_extra_files(&source, &extra_blob_ids).await?;
    source.close().await?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target
        .execute_unprepared(
            "CREATE TRIGGER fail_file_batch BEFORE INSERT ON files \
             WHEN NEW.name = 'extra-1.txt' \
             BEGIN SELECT RAISE(ABORT, 'forced file batch failure'); END",
        )
        .await?;
    target.close().await?;

    let options = MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "C:/cloudreve".to_string(),
        local_policy_roots: std::collections::BTreeMap::new(),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: Some(run_id.clone()),
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 2,
    };

    let error = migrate(options.clone()).await.unwrap_err();
    assert!(error.to_string().contains("files"));

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::file::Entity::find()
            .count(&target)
            .await?,
        2
    );
    assert_eq!(
        aster_drive_schema::entities::file_version::Entity::find()
            .count(&target)
            .await?,
        1
    );
    let failed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(failed_checkpoint.status, "failed");
    assert_eq!(
        failed_checkpoint.last_completed_stage.as_deref(),
        Some("blobs")
    );
    let failed_report = migration_run_report(&target_url, &run_id).await?;
    assert_eq!(failed_report.migrated_files, 2);
    assert_eq!(failed_report.migrated_versions, 1);
    target
        .execute_unprepared("DROP TRIGGER fail_file_batch")
        .await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        resume: true,
        ..options
    })
    .await?;
    assert!(report.resumed);
    assert_eq!(report.migrated_files, 4);
    assert_eq!(report.migrated_versions, 1);
    assert_eq!(report.mappings.files.len(), 4);
    assert!(report.validation.passed);

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        aster_drive_schema::entities::file::Entity::find()
            .count(&target)
            .await?,
        4
    );
    assert_eq!(
        aster_drive_schema::entities::file_version::Entity::find()
            .count(&target)
            .await?,
        1
    );
    let completed_checkpoint = migration_run_status(&target_url, &run_id).await?;
    assert_eq!(completed_checkpoint.status, "completed");
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}
