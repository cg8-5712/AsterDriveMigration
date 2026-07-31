use std::collections::BTreeMap;

use color_eyre::eyre::{Result, bail};
use serde_json::{Value, json};

use super::{
    CloudreveBlobRecord, CloudreveDirectLinkRecord, CloudreveFileRecord, CloudreveFolderRecord,
    CloudreveMetadataRecord, CloudrevePolicyGroupRecord, CloudreveShareRecord,
    CloudreveStoragePolicyRecord, CloudreveUserRecord,
};
use aster_drive_migration_core::{
    Conversion, ConversionContext, MigrationAvatarSource, MigrationBlob, MigrationDirectLink,
    MigrationEntityKind, MigrationEntityRef, MigrationFile, MigrationFileVersion, MigrationFolder,
    MigrationMetadata, MigrationPolicyGroup, MigrationProperty, MigrationShare,
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
