use std::collections::BTreeMap;

use color_eyre::eyre::{Result, bail};
use serde_json::{Value, json};

use super::{
    CloudreveFolderRecord, CloudrevePolicyGroupRecord, CloudreveStoragePolicyRecord,
    CloudreveUserRecord,
};
use aster_drive_migration_core::{
    Conversion, ConversionContext, MigrationAvatarSource, MigrationFolder, MigrationPolicyGroup,
    MigrationStorageDriver, MigrationStoragePolicy, MigrationUser, MigrationUserRole,
    MigrationUserStatus, SkipReason, SourceConverter,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct CloudreveConverter;

fn target_time(value: chrono::DateTime<chrono::FixedOffset>) -> chrono::DateTime<chrono::Utc> {
    value.with_timezone(&chrono::Utc)
}

fn settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
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
}
