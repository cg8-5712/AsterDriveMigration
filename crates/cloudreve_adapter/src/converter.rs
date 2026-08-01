use std::collections::BTreeMap;

use color_eyre::eyre::{Result, bail};
use serde_json::{Value, json};
use url::Url;

use super::{
    CloudreveBlobRecord, CloudreveDirectLinkRecord, CloudreveFileRecord, CloudreveFolderRecord,
    CloudreveMetadataRecord, CloudrevePolicyGroupRecord, CloudreveShareRecord,
    CloudreveStoragePolicyRecord, CloudreveUserRecord,
};
use aster_drive_migration_core::{
    Conversion, ConversionContext, MigrationAvatarSource, MigrationBlob, MigrationDirectLink,
    MigrationEntityKind, MigrationEntityRef, MigrationFile, MigrationFileVersion, MigrationFolder,
    MigrationMetadata, MigrationObjectStorageDownloadStrategy,
    MigrationObjectStorageUploadStrategy, MigrationPolicyGroup, MigrationProperty, MigrationShare,
    MigrationShareTarget, MigrationStorageDriver, MigrationStoragePolicy, MigrationTagAssignment,
    MigrationUser, MigrationUserRole, MigrationUserStatus, SkipReason, SourceConverter,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct CloudreveConverter;

fn target_time(value: chrono::DateTime<chrono::FixedOffset>) -> chrono::DateTime<chrono::Utc> {
    value.with_timezone(&chrono::Utc)
}

fn settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
}

pub fn storage_policy_skip_reason(
    policy: &cloudreve_schema::storage_policies::Model,
) -> Option<SkipReason> {
    if settings(&policy.settings)
        .get("encryption")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Some(SkipReason {
            code: "cloudreve_storage_encryption",
            message: format!("{} (Cloudreve encryption enabled)", policy.r#type),
        });
    }

    match policy.r#type.as_str() {
        "local" => None,
        "s3" | "ks3" => static_object_storage_skip_reason(policy),
        "cos" => cos_policy_skip_reason(policy),
        "oss" => Some(SkipReason {
            code: "unsupported_storage_driver",
            message: "oss (native Alibaba OSS signing is not supported by AsterDrive)".to_string(),
        }),
        "obs" => Some(SkipReason {
            code: "unsupported_storage_driver",
            message: "obs (native Huawei OBS signing is not supported by AsterDrive)".to_string(),
        }),
        unsupported => Some(SkipReason {
            code: "unsupported_storage_driver",
            message: unsupported.to_string(),
        }),
    }
}

fn static_object_storage_skip_reason(
    policy: &cloudreve_schema::storage_policies::Model,
) -> Option<SkipReason> {
    for (field, value) in [
        ("bucket", policy.bucket_name.as_deref()),
        ("access key", policy.access_key.as_deref()),
        ("secret key", policy.secret_key.as_deref()),
    ] {
        if value.is_none_or(|value| value.trim().is_empty()) {
            return Some(SkipReason {
                code: "unsupported_storage_configuration",
                message: format!("{} ({field} is required)", policy.r#type),
            });
        }
    }
    None
}

fn cos_policy_skip_reason(
    policy: &cloudreve_schema::storage_policies::Model,
) -> Option<SkipReason> {
    if let Some(reason) = static_object_storage_skip_reason(policy) {
        return Some(reason);
    }
    let endpoint = policy.server.as_deref().unwrap_or_default().trim();
    let bucket = policy.bucket_name.as_deref().unwrap_or_default().trim();
    if endpoint.is_empty() {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint is required)".to_string(),
        });
    }

    let Ok(endpoint) = Url::parse(endpoint) else {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint is not a valid URL)".to_string(),
        });
    };
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint must use http or https)".to_string(),
        });
    }
    let Some(host) = endpoint.host_str() else {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint has no host)".to_string(),
        });
    };
    let host = host.to_ascii_lowercase();
    if !host.ends_with(".myqcloud.com") || !host.contains(".cos.") {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint must use a Tencent COS myqcloud.com host)".to_string(),
        });
    }
    let expected_prefix = format!("{}.", bucket.to_ascii_lowercase());
    let Some(provider_host) = host.strip_prefix(&expected_prefix) else {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint host does not match bucket)".to_string(),
        });
    };
    let Some(region) = provider_host
        .strip_prefix("cos.")
        .and_then(|value| value.strip_suffix(".myqcloud.com"))
    else {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint has an invalid provider host)".to_string(),
        });
    };
    if region.is_empty() || region.contains('.') {
        return Some(SkipReason {
            code: "unsupported_storage_configuration",
            message: "cos (endpoint has an invalid region)".to_string(),
        });
    }
    None
}

const ASTER_DRIVE_PROPERTY_NAME_MAX_CHARS: usize = 255;
const ASTER_DRIVE_PROPERTY_VALUE_MAX_BYTES: usize = 65_536;
const ASTER_DRIVE_TAG_NAME_MAX_CHARS: usize = 64;
const DEFAULT_TAG_COLOR: &str = "#3b82f6";

fn metadata_target(target: &cloudreve_schema::files::Model) -> Option<MigrationEntityRef> {
    let kind = match target.r#type {
        0 => MigrationEntityKind::File,
        1 => MigrationEntityKind::Folder,
        _ => return None,
    };
    Some(MigrationEntityRef {
        kind,
        source_id: target.id,
    })
}

fn tag_name(metadata_name: &str) -> Option<&str> {
    metadata_name.strip_prefix("tag:").map(str::trim)
}

fn target_tag_name(name: &str) -> String {
    name.trim()
        .chars()
        .take(ASTER_DRIVE_TAG_NAME_MAX_CHARS)
        .collect()
}

fn target_tag_color(color: &str) -> String {
    let color = color.trim().to_ascii_lowercase();
    if color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return color;
    }
    if color.len() == 4
        && color.starts_with('#')
        && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        let mut expanded = String::with_capacity(7);
        expanded.push('#');
        for character in color[1..].chars() {
            expanded.push(character);
            expanded.push(character);
        }
        return expanded;
    }
    DEFAULT_TAG_COLOR.to_string()
}

mod blob;
mod direct_link;
mod file;
mod folder;
mod metadata;
mod policy;
mod share;
mod user;

#[cfg(test)]
mod tests;
