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
    assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == "symbolic_file"));

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
    assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == "deleted_share"));

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
        assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code));
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
        assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code));
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
        assert!(matches!(conversion, Conversion::Skipped(reason) if reason.code == expected_code));
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
