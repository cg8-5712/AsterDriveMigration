use color_eyre::eyre::{Result, WrapErr, bail};
use serde_json::Value;

const S3_COMPATIBLE_DRIVERS: &[&str] = &["s3", "oss", "ks3", "obs", "cos"];

pub(super) fn supports_s3_validation(policy: &cloudreve_schema::storage_policies::Model) -> bool {
    S3_COMPATIBLE_DRIVERS.contains(&policy.r#type.as_str()) && !encryption_enabled(policy)
}

pub(super) async fn verify_object(
    policy: &cloudreve_schema::storage_policies::Model,
    storage_path: &str,
    expected_size: i64,
    entity_id: i64,
) -> Result<()> {
    if !supports_s3_validation(policy) {
        bail!(
            "Cloudreve storage policy {} ({}) is not an S3-compatible remote policy",
            policy.id,
            policy.r#type
        );
    }
    if storage_path.is_empty() {
        bail!("Cloudreve remote entity {entity_id} has an empty object key");
    }
    let client = client(policy)?;
    let bucket = required(&policy.bucket_name, "bucket", policy.id)?;
    let head = client
        .head_object()
        .bucket(bucket)
        .key(storage_path)
        .send()
        .await
        .wrap_err_with(|| format!("HeadObject for Cloudreve entity {entity_id}"))?;
    if head.content_length() != Some(expected_size) {
        bail!(
            "Cloudreve remote entity {entity_id} size mismatch: database={expected_size}, provider={:?}",
            head.content_length()
        );
    }
    if expected_size > 0 {
        let response = client
            .get_object()
            .bucket(bucket)
            .key(storage_path)
            .range("bytes=0-0")
            .send()
            .await
            .wrap_err_with(|| format!("range read for Cloudreve entity {entity_id}"))?;
        let bytes = response
            .body
            .collect()
            .await
            .wrap_err_with(|| format!("read range response for Cloudreve entity {entity_id}"))?
            .into_bytes();
        if bytes.len() != 1 {
            bail!(
                "Cloudreve remote entity {entity_id} range read returned {} bytes instead of 1",
                bytes.len()
            );
        }
    }
    Ok(())
}

fn client(policy: &cloudreve_schema::storage_policies::Model) -> Result<aws_sdk_s3::Client> {
    let endpoint = required(&policy.server, "endpoint", policy.id)?;
    let access_key = required(&policy.access_key, "access key", policy.id)?;
    let secret_key = required(&policy.secret_key, "secret key", policy.id)?;
    let settings = policy.settings.as_ref().cloned().unwrap_or(Value::Null);
    let region = storage_region(policy, endpoint, &settings)?;
    let path_style = force_path_style(policy, &settings);
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(region.to_string()))
        .endpoint_url(endpoint)
        .force_path_style(path_style)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "cloudreve-migration",
        ))
        .build();
    Ok(aws_sdk_s3::Client::from_conf(config))
}

fn storage_region(
    policy: &cloudreve_schema::storage_policies::Model,
    endpoint: &str,
    settings: &Value,
) -> Result<String> {
    if let Some(region) = settings
        .get("region")
        .or_else(|| settings.get("s3_region"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Ok(region.trim().to_string());
    }
    if policy.r#type == "cos" {
        return cos_region_from_endpoint(endpoint).ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "Cloudreve COS policy {} needs settings.region (or settings.s3_region); it could not be derived from endpoint {endpoint}",
                policy.id
            )
        });
    }
    Ok("us-east-1".to_string())
}

fn force_path_style(policy: &cloudreve_schema::storage_policies::Model, settings: &Value) -> bool {
    if policy.r#type == "cos" {
        // Tencent COS recommends virtual-hosted-style URLs, and newer buckets require them.
        false
    } else {
        settings
            .get("s3_path_style")
            .and_then(Value::as_bool)
            .unwrap_or(true)
    }
}

fn cos_region_from_endpoint(endpoint: &str) -> Option<String> {
    let authority = endpoint
        .trim()
        .strip_prefix("https://")
        .or_else(|| endpoint.trim().strip_prefix("http://"))
        .unwrap_or(endpoint)
        .split('/')
        .next()?
        .split(':')
        .next()?;
    let labels = authority.split('.').collect::<Vec<_>>();
    let cos_index = labels.iter().position(|label| *label == "cos")?;
    let region = *labels.get(cos_index + 1)?;
    let suffix = labels.get(cos_index + 2..)?;
    (suffix == ["myqcloud", "com"] && !region.is_empty()).then(|| region.to_string())
}

fn encryption_enabled(policy: &cloudreve_schema::storage_policies::Model) -> bool {
    policy
        .settings
        .as_ref()
        .and_then(|settings| settings.get("encryption"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn required<'a>(value: &'a Option<String>, name: &str, policy_id: i64) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| color_eyre::eyre::eyre!("Cloudreve remote policy {policy_id} has no {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_allows_supported_s3_compatible_drivers() {
        let mut policy = cloudreve_schema::storage_policies::Model {
            id: 1,
            created_at: chrono::Utc::now().fixed_offset(),
            updated_at: chrono::Utc::now().fixed_offset(),
            deleted_at: None,
            name: "test".to_string(),
            r#type: "s3".to_string(),
            server: None,
            bucket_name: None,
            is_private: None,
            access_key: None,
            secret_key: None,
            max_size: None,
            dir_name_rule: None,
            file_name_rule: None,
            settings: None,
            node_id: None,
        };
        assert!(supports_s3_validation(&policy));
        policy.r#type = "cos".to_string();
        assert!(supports_s3_validation(&policy));
        policy.r#type = "qiniu".to_string();
        assert!(!supports_s3_validation(&policy));
        policy.r#type = "oss".to_string();
        policy.settings = Some(serde_json::json!({"encryption": true}));
        assert!(!supports_s3_validation(&policy));
    }

    #[test]
    fn derives_cos_region_and_uses_virtual_hosted_style() -> Result<()> {
        let policy = cloudreve_schema::storage_policies::Model {
            id: 7,
            created_at: chrono::Utc::now().fixed_offset(),
            updated_at: chrono::Utc::now().fixed_offset(),
            deleted_at: None,
            name: "COS".to_string(),
            r#type: "cos".to_string(),
            server: Some("https://example-1250000000.cos.ap-guangzhou.myqcloud.com".to_string()),
            bucket_name: Some("example-1250000000".to_string()),
            is_private: Some(true),
            access_key: Some("secret-id".to_string()),
            secret_key: Some("secret-key".to_string()),
            max_size: None,
            dir_name_rule: None,
            file_name_rule: None,
            settings: None,
            node_id: None,
        };

        assert_eq!(
            storage_region(
                &policy,
                policy.server.as_deref().expect("COS endpoint"),
                &Value::Null,
            )?,
            "ap-guangzhou"
        );
        assert!(!force_path_style(&policy, &Value::Null));
        assert!(storage_region(&policy, "https://cos.invalid.example", &Value::Null).is_err());
        Ok(())
    }
}
