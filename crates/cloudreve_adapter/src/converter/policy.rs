use super::*;

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
