//! Source-neutral objects exchanged between source adapters and target writers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStorageDriver {
    Local,
    S3,
    TencentCos,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MigrationStoragePolicy {
    pub source_id: i64,
    pub name: String,
    pub driver: MigrationStorageDriver,
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub base_path: String,
    pub max_file_size: i64,
    pub allowed_types: Vec<String>,
    pub s3_path_style: bool,
    pub extensions: BTreeMap<String, Value>,
    pub chunk_size: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPolicyGroup {
    pub source_id: i64,
    pub name: String,
    pub description: String,
    pub policy_source_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationUserRole {
    User,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationUserStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationAvatarSource {
    None,
    Gravatar,
    Upload,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MigrationUser {
    pub source_id: i64,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub role: MigrationUserRole,
    pub status: MigrationUserStatus,
    pub storage_used: i64,
    pub storage_quota: i64,
    pub policy_group_source_id: i64,
    pub config: Option<Value>,
    pub avatar_source: MigrationAvatarSource,
    pub avatar_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationFolder {
    pub source_id: i64,
    pub name: String,
    pub parent_source_id: Option<i64>,
    pub owner_source_id: i64,
    pub policy_source_id: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
