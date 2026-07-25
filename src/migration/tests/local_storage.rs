use super::super::*;
use super::fixtures::{create_source_schema, create_target_schema, seed_source, sqlite_url};
use sea_orm::ConnectionTrait;

#[tokio::test]
async fn reuses_and_verifies_local_storage_per_policy_root() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-local-reuse-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-local-reuse-{suffix}.db"));
    let storage_root = std::env::temp_dir().join(format!("cloudreve-local-storage-{suffix}"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let source_policy_id = cr::storage_policies::Entity::find()
        .one(&source)
        .await?
        .expect("seeded storage policy")
        .id;
    source.close().await?;
    std::fs::create_dir_all(storage_root.join("uploads"))?;
    std::fs::write(storage_root.join("uploads/object.bin"), vec![0_u8; 128])?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "unused-local-root".to_string(),
        local_policy_roots: std::collections::BTreeMap::from([(
            source_policy_id,
            storage_root.to_string_lossy().to_string(),
        )]),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: true,
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
    assert!(report.validation.passed);

    let target = Database::connect(&target_url).await?;
    let policy = ad::storage_policies::Entity::find()
        .one(&target)
        .await?
        .expect("migrated storage policy");
    assert_eq!(policy.base_path, storage_root.to_string_lossy());
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    let _ = std::fs::remove_dir_all(storage_root);
    Ok(())
}

#[tokio::test]
async fn rejects_local_storage_size_mismatch() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-local-mismatch-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-local-mismatch-{suffix}.db"));
    let storage_root =
        std::env::temp_dir().join(format!("cloudreve-local-mismatch-storage-{suffix}"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let source_policy_id = cr::storage_policies::Entity::find()
        .one(&source)
        .await?
        .expect("seeded storage policy")
        .id;
    source.close().await?;
    std::fs::create_dir_all(storage_root.join("uploads"))?;
    std::fs::write(storage_root.join("uploads/object.bin"), vec![0_u8; 127])?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let error = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "unused-local-root".to_string(),
        local_policy_roots: std::collections::BTreeMap::from([(
            source_policy_id,
            storage_root.to_string_lossy().to_string(),
        )]),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: true,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: true,
        run_id: None,
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    })
    .await
    .unwrap_err();
    assert!(format!("{error:?}").contains("size mismatch"));

    let target = Database::connect(&target_url).await?;
    assert_eq!(
        ad::storage_policies::Entity::find().count(&target).await?,
        0
    );
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    let _ = std::fs::remove_dir_all(storage_root);
    Ok(())
}

#[tokio::test]
async fn rejects_unknown_local_policy_root() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-local-policy-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-local-policy-{suffix}.db"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    source.close().await?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let error = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "unused-local-root".to_string(),
        local_policy_roots: std::collections::BTreeMap::from([(999, "C:/missing".to_string())]),
        storage_mode: StorageMode::ReuseSourceStorage,
        target_local_base_path: None,
        target_local_policy_roots: std::collections::BTreeMap::new(),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: true,
        run_id: None,
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("policy 999"));

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    Ok(())
}

#[test]
fn resumes_local_copy_from_matching_temporary_file() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let root = std::env::temp_dir().join(format!("asterdrive-copy-resume-{suffix}"));
    let source_path = root.join("source.bin");
    let target_path = root.join("target/object.bin");
    let content = b"a local object that resumes from a generated checkpoint";
    std::fs::create_dir_all(&root)?;
    std::fs::write(&source_path, content)?;
    std::fs::create_dir_all(target_path.parent().expect("target parent"))?;
    let temporary_path = temporary_copy_path(
        target_path.parent().expect("target parent"),
        "local-copy-resume",
        42,
    );
    std::fs::write(&temporary_path, &content[..17])?;

    let (sha256, created) = copy_local_object(
        &source_path,
        &target_path,
        content.len() as i64,
        "local-copy-resume",
        42,
    )?;

    assert!(created);
    assert_eq!(sha256, sha256_file(&source_path)?);
    assert_eq!(std::fs::read(&target_path)?, content);
    assert!(!temporary_path.exists());

    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[tokio::test]
async fn copies_local_objects_to_target_root_and_uses_content_hashes() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-copy-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-copy-{suffix}.db"));
    let source_root = std::env::temp_dir().join(format!("cloudreve-copy-source-{suffix}"));
    let target_root = std::env::temp_dir().join(format!("asterdrive-copy-target-{suffix}"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let source_policy_id = cr::storage_policies::Entity::find()
        .one(&source)
        .await?
        .expect("seeded storage policy")
        .id;
    source.close().await?;
    let content = vec![0x5a_u8; 128];
    std::fs::create_dir_all(source_root.join("uploads"))?;
    std::fs::create_dir_all(&target_root)?;
    std::fs::write(source_root.join("uploads/object.bin"), &content)?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target.close().await?;

    let report = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "unused-source-root".to_string(),
        local_policy_roots: BTreeMap::from([(
            source_policy_id,
            source_root.to_string_lossy().to_string(),
        )]),
        storage_mode: StorageMode::CopyLocal,
        target_local_base_path: None,
        target_local_policy_roots: BTreeMap::from([(
            source_policy_id,
            target_root.to_string_lossy().to_string(),
        )]),
        verify_local_storage: true,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: Some(format!("local-copy-{suffix}")),
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    })
    .await?;
    assert!(report.validation.passed);
    assert_eq!(
        std::fs::read(target_root.join("uploads/object.bin"))?,
        content
    );

    let target = Database::connect(&target_url).await?;
    let policy = ad::storage_policies::Entity::find()
        .one(&target)
        .await?
        .expect("copied local policy");
    assert_eq!(policy.base_path, target_root.to_string_lossy());
    let blob = ad::file_blobs::Entity::find()
        .one(&target)
        .await?
        .expect("copied blob");
    assert_eq!(blob.storage_path, "uploads/object.bin");
    assert_eq!(
        blob.hash,
        sha256_file(&source_root.join("uploads/object.bin"))?
    );
    assert!(
        report
            .validation
            .checks
            .iter()
            .any(|check| { check.name == "local_storage_runtime_readability" && check.passed })
    );
    target.close().await?;

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    let _ = std::fs::remove_dir_all(source_root);
    let _ = std::fs::remove_dir_all(target_root);
    Ok(())
}

#[tokio::test]
async fn compensates_copied_local_objects_when_blob_database_write_fails() -> Result<()> {
    let suffix = uuid::Uuid::new_v4();
    let source_path = std::env::temp_dir().join(format!("cloudreve-copy-fail-{suffix}.db"));
    let target_path = std::env::temp_dir().join(format!("asterdrive-copy-fail-{suffix}.db"));
    let source_root = std::env::temp_dir().join(format!("cloudreve-copy-fail-source-{suffix}"));
    let target_root = std::env::temp_dir().join(format!("asterdrive-copy-fail-target-{suffix}"));
    let source_url = sqlite_url(&source_path);
    let target_url = sqlite_url(&target_path);

    let source = Database::connect(&source_url).await?;
    create_source_schema(&source).await?;
    seed_source(&source).await?;
    let source_policy_id = cr::storage_policies::Entity::find()
        .one(&source)
        .await?
        .expect("seeded storage policy")
        .id;
    source.close().await?;
    std::fs::create_dir_all(source_root.join("uploads"))?;
    std::fs::create_dir_all(&target_root)?;
    std::fs::write(source_root.join("uploads/object.bin"), vec![0x4d_u8; 128])?;
    let expected_hash = sha256_file(&source_root.join("uploads/object.bin"))?;

    let target = Database::connect(&target_url).await?;
    create_target_schema(&target).await?;
    target
        .execute_unprepared(&format!(
            "CREATE TRIGGER fail_copied_blob BEFORE INSERT ON file_blobs
             WHEN NEW.hash = '{expected_hash}'
             BEGIN SELECT RAISE(ABORT, 'forced copied blob failure'); END"
        ))
        .await?;
    target.close().await?;

    let error = migrate(MigrationOptions {
        source_url: source_url.clone(),
        target_url: target_url.clone(),
        default_password: "temporary-password".to_string(),
        local_base_path: "unused-source-root".to_string(),
        local_policy_roots: BTreeMap::from([(
            source_policy_id,
            source_root.to_string_lossy().to_string(),
        )]),
        storage_mode: StorageMode::CopyLocal,
        target_local_base_path: None,
        target_local_policy_roots: BTreeMap::from([(
            source_policy_id,
            target_root.to_string_lossy().to_string(),
        )]),
        verify_local_storage: false,
        verify_remote_storage: false,
        direct_link_secret: Some("test-direct-link-secret".to_string()),
        include_deleted: false,
        allow_non_empty_target: false,
        skip_unsupported_policies: false,
        dry_run: false,
        run_id: Some(format!("local-copy-failure-{suffix}")),
        resume: false,
        blob_batch_size: 500,
        file_batch_size: 500,
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("blobs"));
    assert!(!target_root.join("uploads/object.bin").exists());

    let _ = std::fs::remove_file(source_path);
    let _ = std::fs::remove_file(target_path);
    let _ = std::fs::remove_dir_all(source_root);
    let _ = std::fs::remove_dir_all(target_root);
    Ok(())
}
