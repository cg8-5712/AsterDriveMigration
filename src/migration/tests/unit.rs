use super::super::*;
use aster_drive_model::types::DriverType;

#[test]
fn classifies_common_file_types() {
    assert_eq!(file_classification("photo.JPG").3, "image");
    assert_eq!(
        file_classification("backup.tar.gz").1.as_deref(),
        Some("tar.gz")
    );
    assert_eq!(file_classification("main.rs").3, "code");
}

#[test]
fn maps_supported_storage_drivers_conservatively() {
    assert_eq!(map_driver_type("local"), Some(DriverType::Local));
    assert_eq!(map_driver_type("oss"), Some(DriverType::S3));
    assert_eq!(map_driver_type("cos"), Some(DriverType::TencentCos));
    assert_eq!(map_driver_type("onedrive"), None);
    assert_eq!(map_driver_type("qiniu"), None);
}

#[test]
fn parses_and_normalizes_cloudreve_tags_for_aster_drive() {
    assert_eq!(tag_name("tag:Important"), Some("Important"));
    assert_eq!(tag_name("tag:  Project A  "), Some("Project A"));
    assert_eq!(tag_name("author"), None);
    assert_eq!(normalize_tag_name(" Important "), "important");
    assert_eq!(target_tag_color("#AbC"), "#aabbcc");
    assert_eq!(target_tag_color("#3B82F6"), "#3b82f6");
    assert_eq!(target_tag_color(""), "#3b82f6");
    assert_eq!(target_tag_name(&"x".repeat(80)).chars().count(), 64);
}

#[test]
fn builds_asterdrive_v2_direct_link_urls() -> Result<()> {
    let url = direct_link_url(1, 7, "hello world.txt", "test-direct-link-secret")?;
    assert!(url.starts_with("/d/v2.b."));
    assert!(url.ends_with("/hello%20world.txt"));
    assert_eq!(
        url,
        direct_link_url(1, 7, "hello world.txt", "test-direct-link-secret")?
    );
    assert_ne!(
        url,
        direct_link_url(1, 8, "hello world.txt", "test-direct-link-secret")?
    );
    Ok(())
}

#[test]
fn maps_cloudreve_tasks_to_non_executable_terminal_statuses() {
    assert_eq!(archived_task_status("completed"), "succeeded");
    assert_eq!(archived_task_status("error"), "failed");
    assert_eq!(archived_task_status("canceled"), "canceled");
    for status in ["queued", "processing", "suspending"] {
        assert!(source_task_was_active(status));
        assert_eq!(archived_task_status(status), "canceled");
    }
    assert_eq!(archived_task_status("unknown"), "canceled");
}

#[test]
fn records_skipped_objects_by_type() {
    let mut report = MigrationReport::default();
    report.record_skip("file", Some(42), "missing blob");
    report.record_skip("file", Some(43), "symbolic file");
    report.record_skip("share", None, "missing target");

    assert_eq!(report.skipped, 3);
    assert_eq!(report.skipped_by_type.get("file"), Some(&2));
    assert_eq!(report.skipped_by_type.get("share"), Some(&1));
    assert_eq!(report.skipped_objects[0].source_id, Some(42));
    assert_eq!(report.skipped_objects[0].reason, "missing blob");
}

#[test]
fn writes_structured_json_report() -> Result<()> {
    let report_path = std::env::temp_dir().join(format!(
        "asterdrive-migration-report-{}.json",
        uuid::Uuid::new_v4()
    ));
    let mut report = MigrationReport {
        migrated_users: 1,
        validation: MigrationValidation {
            performed: true,
            passed: true,
            checks: vec![ValidationCheck {
                name: "users_count".to_string(),
                passed: true,
                expected: "1".to_string(),
                actual: "1".to_string(),
                message: None,
            }],
        },
        ..Default::default()
    };
    report.mappings.users.push(IdMapping {
        source_id: 7,
        target_id: 11,
    });

    write_json_report(&report_path, &report)?;
    let value: Value = serde_json::from_slice(&std::fs::read(&report_path)?)?;
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["migrated_users"], 1);
    assert_eq!(value["mappings"]["users"][0]["source_id"], 7);
    assert_eq!(value["mappings"]["users"][0]["target_id"], 11);
    assert_eq!(value["validation"]["passed"], true);

    let _ = std::fs::remove_file(report_path);
    Ok(())
}

#[test]
fn writes_csv_mapping_report_without_capability_urls() -> Result<()> {
    let report_path = std::env::temp_dir().join(format!(
        "asterdrive-migration-mappings-{}.csv",
        uuid::Uuid::new_v4()
    ));
    let mut report = MigrationReport::default();
    report.mappings.users.push(IdMapping {
        source_id: 7,
        target_id: 11,
    });
    report.direct_links.push(DirectLinkReport {
        source_direct_link_id: 1,
        source_file_id: 2,
        target_file_id: 3,
        source_name: "secret.txt".to_string(),
        source_downloads: 0,
        source_speed_limit: 0,
        url: "/d/capability".to_string(),
    });

    write_csv_mapping_report(&report_path, &report)?;
    let contents = std::fs::read_to_string(&report_path)?;
    assert!(contents.contains("user,7,11"));
    assert!(!contents.contains("/d/capability"));
    let _ = std::fs::remove_file(report_path);
    Ok(())
}

#[test]
fn progress_timing_includes_rate_and_eta() {
    let timing = progress_timing(50, 100, Instant::now());
    assert!(timing.contains("rows_per_sec="));
    assert!(timing.contains("eta_secs="));
}
