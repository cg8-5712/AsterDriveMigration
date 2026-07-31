use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Write};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use base64::Engine;
use color_eyre::eyre::{Result, WrapErr, bail};
use hmac::{Hmac, Mac};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, DatabaseTransaction, EntityTrait,
    IntoActiveModel, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use aster_drive_model as aster_drive_schema;
use aster_drive_model::types::{
    BackgroundTaskKind, BackgroundTaskStatus, DriverType, EntityType, StoredTaskPayload,
    StoredTaskResult, StoredTaskRuntime, StoredTaskSteps, TagScopeType,
};
use aster_drive_schema_migration::{MigrationTrack, inspect_migration_history};

fn target_time(value: chrono::DateTime<chrono::FixedOffset>) -> chrono::DateTime<chrono::Utc> {
    value.with_timezone(&chrono::Utc)
}

fn target_optional_time(
    value: Option<chrono::DateTime<chrono::FixedOffset>>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    value.map(target_time)
}

mod checkpoint;
mod engine;
mod local_storage;
mod model;
mod phases;
mod remote;
mod report;
mod validation;

use local_storage::*;
use model::*;
use phases::*;
use validation::*;

pub use engine::{
    abort_migration_run, cleanup_completed_migration_run, inspect, list_migration_runs, migrate,
    migration_run_report, migration_run_status,
};
pub use report::{
    DirectLinkReport, IdMapping, MigrationMappings, MigrationOptions, MigrationPreflight,
    MigrationReport, MigrationRunSummary, MigrationValidation, SkippedObject, TagAssignmentReport,
    ValidationCheck, write_csv_mapping_report, write_json_report,
};
