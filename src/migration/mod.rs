use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Write};
use std::path::Path;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use base64::Engine;
use color_eyre::eyre::{Result, WrapErr, bail};
use hmac::{Hmac, Mac};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, Set, TransactionTrait,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use asterdrive_entities as ad;
use cloudreve_entities as cr;

#[derive(Debug, Clone)]
pub struct MigrationOptions {
    pub source_url: String,
    pub target_url: String,
    pub default_password: String,
    pub local_base_path: String,
    pub direct_link_secret: Option<String>,
    pub include_deleted: bool,
    pub allow_non_empty_target: bool,
    pub skip_unsupported_policies: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigrationReport {
    pub schema_version: u32,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub source_users: u64,
    pub source_groups: u64,
    pub source_policies: u64,
    pub source_folders: u64,
    pub source_files: u64,
    pub source_entities: u64,
    pub source_shares: u64,
    pub source_direct_links: u64,
    pub source_tag_assignments: u64,
    pub source_tasks: u64,
    pub migrated_users: usize,
    pub migrated_policy_groups: usize,
    pub migrated_policies: usize,
    pub migrated_folders: usize,
    pub migrated_files: usize,
    pub migrated_blobs: usize,
    pub migrated_versions: usize,
    pub migrated_shares: usize,
    pub migrated_properties: usize,
    pub migrated_tags: usize,
    pub migrated_tag_assignments: usize,
    pub migrated_direct_links: usize,
    pub migrated_tasks: usize,
    pub skipped: usize,
    pub dry_run: bool,
    pub warnings: Vec<String>,
    pub skipped_by_type: BTreeMap<String, usize>,
    pub skipped_objects: Vec<SkippedObject>,
    pub mappings: MigrationMappings,
    pub direct_links: Vec<DirectLinkReport>,
    pub tag_assignments: Vec<TagAssignmentReport>,
    pub validation: MigrationValidation,
}

impl Default for MigrationReport {
    fn default() -> Self {
        Self {
            schema_version: 1,
            generated_at: chrono::Utc::now(),
            source_users: 0,
            source_groups: 0,
            source_policies: 0,
            source_folders: 0,
            source_files: 0,
            source_entities: 0,
            source_shares: 0,
            source_direct_links: 0,
            source_tag_assignments: 0,
            source_tasks: 0,
            migrated_users: 0,
            migrated_policy_groups: 0,
            migrated_policies: 0,
            migrated_folders: 0,
            migrated_files: 0,
            migrated_blobs: 0,
            migrated_versions: 0,
            migrated_shares: 0,
            migrated_properties: 0,
            migrated_tags: 0,
            migrated_tag_assignments: 0,
            migrated_direct_links: 0,
            migrated_tasks: 0,
            skipped: 0,
            dry_run: false,
            warnings: Vec::new(),
            skipped_by_type: BTreeMap::new(),
            skipped_objects: Vec::new(),
            mappings: MigrationMappings::default(),
            direct_links: Vec::new(),
            tag_assignments: Vec::new(),
            validation: MigrationValidation::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedObject {
    pub object_type: String,
    pub source_id: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct MigrationMappings {
    pub policies: Vec<IdMapping>,
    pub policy_groups: Vec<IdMapping>,
    pub users: Vec<IdMapping>,
    pub folders: Vec<IdMapping>,
    pub blobs: Vec<IdMapping>,
    pub files: Vec<IdMapping>,
    pub shares: Vec<IdMapping>,
    pub tasks: Vec<IdMapping>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IdMapping {
    pub source_id: i64,
    pub target_id: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectLinkReport {
    pub source_direct_link_id: i64,
    pub source_file_id: i64,
    pub target_file_id: i64,
    pub source_name: String,
    pub source_downloads: i64,
    pub source_speed_limit: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TagAssignmentReport {
    pub source_metadata_id: i64,
    pub source_entity_id: i64,
    pub target_entity_type: String,
    pub target_entity_id: i64,
    pub target_tag_id: i64,
    pub tag_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigrationValidation {
    pub performed: bool,
    pub passed: bool,
    pub checks: Vec<ValidationCheck>,
}

impl Default for MigrationValidation {
    fn default() -> Self {
        Self {
            performed: false,
            passed: true,
            checks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationCheck {
    pub name: String,
    pub passed: bool,
    pub expected: String,
    pub actual: String,
    pub message: Option<String>,
}

impl MigrationReport {
    fn record_skip(
        &mut self,
        object_type: &str,
        source_id: Option<i64>,
        reason: impl Into<String>,
    ) {
        self.skipped += 1;
        *self
            .skipped_by_type
            .entry(object_type.to_string())
            .or_default() += 1;
        self.skipped_objects.push(SkippedObject {
            object_type: object_type.to_string(),
            source_id,
            reason: reason.into(),
        });
    }

    fn set_mappings(&mut self, context: &MigrationContext) {
        self.mappings = MigrationMappings {
            policies: sorted_id_mappings(&context.policies),
            policy_groups: sorted_id_mappings(&context.policy_groups),
            users: sorted_id_mappings(&context.users),
            folders: sorted_id_mappings(&context.folders),
            blobs: sorted_id_mappings(&context.blobs),
            files: sorted_id_mappings(&context.files),
            shares: sorted_id_mappings(&context.shares),
            tasks: sorted_id_mappings(&context.tasks),
        };
    }
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        writeln!(output, "Cloudreve -> AsterDrive migration report")?;
        writeln!(
            output,
            "source: users={}, groups={}, policies={}, folders={}, files={}, entities={}, shares={}, direct_links={}, tag_assignments={}, tasks={}",
            self.source_users,
            self.source_groups,
            self.source_policies,
            self.source_folders,
            self.source_files,
            self.source_entities,
            self.source_shares,
            self.source_direct_links,
            self.source_tag_assignments,
            self.source_tasks
        )?;
        if self.dry_run {
            writeln!(output, "mode: dry-run (target was not modified)")?;
        } else {
            writeln!(
                output,
                "migrated: users={}, policy_groups={}, policies={}, folders={}, files={}, blobs={}, versions={}, shares={}, properties={}, tags={}, tag_assignments={}, direct_links={}, archived_tasks={}",
                self.migrated_users,
                self.migrated_policy_groups,
                self.migrated_policies,
                self.migrated_folders,
                self.migrated_files,
                self.migrated_blobs,
                self.migrated_versions,
                self.migrated_shares,
                self.migrated_properties,
                self.migrated_tags,
                self.migrated_tag_assignments,
                self.migrated_direct_links,
                self.migrated_tasks
            )?;
            writeln!(output, "skipped: {}", self.skipped)?;
            if !self.skipped_by_type.is_empty() {
                let categories = self
                    .skipped_by_type
                    .iter()
                    .map(|(object_type, count)| format!("{object_type}={count}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(output, "skipped_by_type: {categories}")?;
            }
            if self.validation.performed {
                writeln!(
                    output,
                    "validation: {} ({} checks)",
                    if self.validation.passed {
                        "passed"
                    } else {
                        "failed"
                    },
                    self.validation.checks.len()
                )?;
            }
        }
        if !self.warnings.is_empty() {
            writeln!(output, "warnings:")?;
            for warning in &self.warnings {
                writeln!(output, "- {warning}")?;
            }
        }
        formatter.write_str(output.trim_end())
    }
}

pub fn write_json_report(path: impl AsRef<Path>, report: &MigrationReport) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create report directory {}", parent.display()))?;
    }
    let contents = serde_json::to_vec_pretty(report).wrap_err("serialize migration report")?;
    std::fs::write(path, contents)
        .wrap_err_with(|| format!("write migration report {}", path.display()))
}

pub async fn inspect(
    source_url: &str,
    target_url: &str,
    include_deleted: bool,
) -> Result<MigrationReport> {
    let source = connect(source_url, "Cloudreve").await?;
    let target = connect(target_url, "AsterDrive").await?;
    let source_data = SourceData::load(&source, include_deleted).await?;
    validate_target_schema(&target).await?;
    let mut report = source_data.report();
    report.dry_run = true;
    report.warnings.extend(source_data.compatibility_warnings());
    Ok(report)
}

pub async fn migrate(options: MigrationOptions) -> Result<MigrationReport> {
    if options.default_password.chars().count() < 8 {
        bail!("--default-password must contain at least 8 characters");
    }
    if options
        .direct_link_secret
        .as_deref()
        .is_some_and(|secret| secret.chars().count() < 16)
    {
        bail!("--direct-link-secret must contain at least 16 characters");
    }

    let source = connect(&options.source_url, "Cloudreve").await?;
    let target = connect(&options.target_url, "AsterDrive").await?;
    let source_data = SourceData::load(&source, options.include_deleted).await?;
    validate_target_schema(&target).await?;
    ensure_target_safe(&target, options.allow_non_empty_target).await?;
    let target_before = TargetCounts::load(&target).await?;

    let unsupported = source_data.unsupported_policy_types();
    if !unsupported.is_empty() && !options.skip_unsupported_policies {
        bail!(
            "unsupported Cloudreve storage policy types: {}; rerun with --skip-unsupported-policies to omit their files",
            unsupported.join(", ")
        );
    }

    let mut report = source_data.report();
    report.dry_run = options.dry_run;
    report.warnings.extend(source_data.compatibility_warnings());
    if options.dry_run {
        return Ok(report);
    }

    let password_hash = hash_password(&options.default_password)?;
    let transaction = target
        .begin()
        .await
        .wrap_err("begin AsterDrive transaction")?;
    let mut context = MigrationContext::default();

    migrate_policies(
        &transaction,
        &source_data,
        &options,
        &mut context,
        &mut report,
    )
    .await?;
    migrate_policy_groups(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_users(
        &transaction,
        &source_data,
        &password_hash,
        &mut context,
        &mut report,
    )
    .await?;
    migrate_folders(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_blobs(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_files(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_metadata(&transaction, &source_data, &context, &mut report).await?;
    migrate_shares(&transaction, &source_data, &mut context, &mut report).await?;
    migrate_direct_links(
        &transaction,
        &source_data,
        &context,
        options.direct_link_secret.as_deref(),
        &mut report,
    )
    .await?;
    migrate_tasks(&transaction, &source_data, &mut context, &mut report).await?;

    transaction
        .commit()
        .await
        .wrap_err("commit AsterDrive migration transaction")?;
    report.set_mappings(&context);
    report.validation = validate_migration_result(&target, &target_before, &report).await?;
    report.generated_at = chrono::Utc::now();
    Ok(report)
}

async fn connect(url: &str, label: &str) -> Result<DatabaseConnection> {
    Database::connect(url)
        .await
        .wrap_err_with(|| format!("connect to {label} database"))
}

async fn validate_target_schema(db: &DatabaseConnection) -> Result<()> {
    ad::users::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive schema is unavailable; run AD database migrations first")?;
    ad::storage_policies::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive storage_policies table is unavailable")?;
    ad::files::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive files table is unavailable")?;
    ad::entity_properties::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive entity_properties table is unavailable")?;
    ad::tags::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive tags table is unavailable")?;
    ad::background_tasks::Entity::find()
        .count(db)
        .await
        .wrap_err("AsterDrive background_tasks table is unavailable")?;
    Ok(())
}

async fn ensure_target_safe(db: &DatabaseConnection, allow_non_empty: bool) -> Result<()> {
    if allow_non_empty {
        return Ok(());
    }
    let counts = [
        ("users", ad::users::Entity::find().count(db).await?),
        ("folders", ad::folders::Entity::find().count(db).await?),
        ("files", ad::files::Entity::find().count(db).await?),
        (
            "file_blobs",
            ad::file_blobs::Entity::find().count(db).await?,
        ),
        ("shares", ad::shares::Entity::find().count(db).await?),
        (
            "entity_properties",
            ad::entity_properties::Entity::find().count(db).await?,
        ),
        ("tags", ad::tags::Entity::find().count(db).await?),
        (
            "background_tasks",
            ad::background_tasks::Entity::find().count(db).await?,
        ),
    ];
    let occupied: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(table, count)| format!("{table}={count}"))
        .collect();
    if !occupied.is_empty() {
        bail!(
            "target AD database is not empty ({}); use a freshly migrated database or pass --allow-non-empty-target",
            occupied.join(", ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct TargetCounts {
    policies: u64,
    policy_groups: u64,
    users: u64,
    user_profiles: u64,
    folders: u64,
    blobs: u64,
    files: u64,
    versions: u64,
    shares: u64,
    properties: u64,
    tags: u64,
    tasks: u64,
}

impl TargetCounts {
    async fn load(db: &DatabaseConnection) -> Result<Self> {
        Ok(Self {
            policies: ad::storage_policies::Entity::find().count(db).await?,
            policy_groups: ad::storage_policy_groups::Entity::find().count(db).await?,
            users: ad::users::Entity::find().count(db).await?,
            user_profiles: ad::user_profiles::Entity::find().count(db).await?,
            folders: ad::folders::Entity::find().count(db).await?,
            blobs: ad::file_blobs::Entity::find().count(db).await?,
            files: ad::files::Entity::find().count(db).await?,
            versions: ad::file_versions::Entity::find().count(db).await?,
            shares: ad::shares::Entity::find().count(db).await?,
            properties: ad::entity_properties::Entity::find().count(db).await?,
            tags: ad::tags::Entity::find().count(db).await?,
            tasks: ad::background_tasks::Entity::find().count(db).await?,
        })
    }
}

fn count_check(name: &str, before: u64, migrated: usize, actual: u64) -> ValidationCheck {
    let migrated = u64::try_from(migrated).unwrap_or(u64::MAX);
    let expected = before.saturating_add(migrated);
    ValidationCheck {
        name: name.to_string(),
        passed: actual == expected,
        expected: expected.to_string(),
        actual: actual.to_string(),
        message: (actual != expected)
            .then(|| format!("expected baseline {before} plus {migrated} migrated records")),
    }
}

fn invariant_check(name: &str, expected: usize, actual: usize, message: &str) -> ValidationCheck {
    ValidationCheck {
        name: name.to_string(),
        passed: actual == expected,
        expected: expected.to_string(),
        actual: actual.to_string(),
        message: (actual != expected).then(|| message.to_string()),
    }
}

async fn validate_migration_result(
    db: &DatabaseConnection,
    before: &TargetCounts,
    report: &MigrationReport,
) -> Result<MigrationValidation> {
    let after = TargetCounts::load(db).await?;
    let mut checks = vec![
        count_check(
            "storage_policies_count",
            before.policies,
            report.migrated_policies,
            after.policies,
        ),
        count_check(
            "storage_policy_groups_count",
            before.policy_groups,
            report.migrated_policy_groups,
            after.policy_groups,
        ),
        count_check(
            "users_count",
            before.users,
            report.migrated_users,
            after.users,
        ),
        count_check(
            "user_profiles_count",
            before.user_profiles,
            report.migrated_users,
            after.user_profiles,
        ),
        count_check(
            "folders_count",
            before.folders,
            report.migrated_folders,
            after.folders,
        ),
        count_check(
            "file_blobs_count",
            before.blobs,
            report.migrated_blobs,
            after.blobs,
        ),
        count_check(
            "files_count",
            before.files,
            report.migrated_files,
            after.files,
        ),
        count_check(
            "file_versions_count",
            before.versions,
            report.migrated_versions,
            after.versions,
        ),
        count_check(
            "shares_count",
            before.shares,
            report.migrated_shares,
            after.shares,
        ),
        count_check(
            "entity_properties_count",
            before.properties,
            report.migrated_properties,
            after.properties,
        ),
        count_check("tags_count", before.tags, report.migrated_tags, after.tags),
        count_check(
            "background_tasks_count",
            before.tasks,
            report.migrated_tasks,
            after.tasks,
        ),
        invariant_check(
            "policy_mappings_count",
            report.migrated_policies,
            report.mappings.policies.len(),
            "storage policy source-to-target mappings are incomplete",
        ),
        invariant_check(
            "policy_group_mappings_count",
            report.migrated_policy_groups,
            report.mappings.policy_groups.len(),
            "policy group source-to-target mappings are incomplete",
        ),
        invariant_check(
            "user_mappings_count",
            report.migrated_users,
            report.mappings.users.len(),
            "user source-to-target mappings are incomplete",
        ),
        invariant_check(
            "folder_mappings_count",
            report.migrated_folders,
            report.mappings.folders.len(),
            "folder source-to-target mappings are incomplete",
        ),
        invariant_check(
            "blob_mappings_count",
            report.migrated_blobs,
            report.mappings.blobs.len(),
            "blob source-to-target mappings are incomplete",
        ),
        invariant_check(
            "file_mappings_count",
            report.migrated_files,
            report.mappings.files.len(),
            "file source-to-target mappings are incomplete",
        ),
        invariant_check(
            "share_mappings_count",
            report.migrated_shares,
            report.mappings.shares.len(),
            "share source-to-target mappings are incomplete",
        ),
        invariant_check(
            "task_mappings_count",
            report.migrated_tasks,
            report.mappings.tasks.len(),
            "task source-to-target mappings are incomplete",
        ),
    ];

    let task_ids = report
        .mappings
        .tasks
        .iter()
        .map(|mapping| mapping.target_id)
        .collect::<Vec<_>>();
    let mut imported_tasks = Vec::new();
    for chunk in task_ids.chunks(500) {
        imported_tasks.extend(
            ad::background_tasks::Entity::find()
                .filter(ad::background_tasks::Column::Id.is_in(chunk.iter().copied()))
                .all(db)
                .await?,
        );
    }
    checks.push(invariant_check(
        "imported_tasks_exist",
        task_ids.len(),
        imported_tasks.len(),
        "one or more imported task IDs are missing",
    ));
    let terminal_tasks = imported_tasks
        .iter()
        .filter(|task| {
            matches!(task.status.as_str(), "succeeded" | "failed" | "canceled")
                && task.lease_expires_at.is_none()
        })
        .count();
    checks.push(invariant_check(
        "imported_tasks_are_terminal",
        imported_tasks.len(),
        terminal_tasks,
        "imported tasks must be terminal and have no active lease",
    ));

    let tag_properties = ad::entity_properties::Entity::find()
        .filter(ad::entity_properties::Column::Namespace.eq("system.tags"))
        .all(db)
        .await?;
    let tag_binding_keys = tag_properties
        .into_iter()
        .map(|property| (property.entity_type, property.entity_id, property.name))
        .collect::<HashSet<_>>();
    let valid_tag_assignments = report
        .tag_assignments
        .iter()
        .filter(|assignment| {
            tag_binding_keys.contains(&(
                assignment.target_entity_type.clone(),
                assignment.target_entity_id,
                assignment.target_tag_id.to_string(),
            ))
        })
        .count();
    checks.push(invariant_check(
        "tag_assignments_exist",
        report.tag_assignments.len(),
        valid_tag_assignments,
        "one or more system.tags bindings are missing",
    ));

    let direct_link_properties = ad::entity_properties::Entity::find()
        .filter(ad::entity_properties::Column::Namespace.eq("cloudreve.direct_links"))
        .all(db)
        .await?;
    let direct_link_values = direct_link_properties
        .into_iter()
        .map(|property| ((property.entity_id, property.name), property.value))
        .collect::<HashMap<_, _>>();
    let valid_direct_links = report
        .direct_links
        .iter()
        .filter(|link| {
            direct_link_values
                .get(&(link.target_file_id, link.source_direct_link_id.to_string()))
                .and_then(|value| value.as_deref())
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
                .and_then(|value| value.get("url").and_then(Value::as_str).map(str::to_string))
                .is_some_and(|url| url == link.url)
        })
        .count();
    checks.push(invariant_check(
        "direct_link_mappings_exist",
        report.direct_links.len(),
        valid_direct_links,
        "one or more cloudreve.direct_links properties are missing or changed",
    ));

    Ok(MigrationValidation {
        performed: true,
        passed: checks.iter().all(|check| check.passed),
        checks,
    })
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("create password salt: {error}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| color_eyre::eyre::eyre!("hash temporary AD password: {error}"))
}

#[derive(Default)]
struct MigrationContext {
    policies: HashMap<i64, i64>,
    policy_groups: HashMap<i64, i64>,
    users: HashMap<i64, i64>,
    usernames: HashMap<i64, String>,
    folders: HashMap<i64, i64>,
    blobs: HashMap<i64, i64>,
    files: HashMap<i64, i64>,
    shares: HashMap<i64, i64>,
    tasks: HashMap<i64, i64>,
}

fn sorted_id_mappings(values: &HashMap<i64, i64>) -> Vec<IdMapping> {
    let mut mappings = values
        .iter()
        .map(|(source_id, target_id)| IdMapping {
            source_id: *source_id,
            target_id: *target_id,
        })
        .collect::<Vec<_>>();
    mappings.sort_by_key(|mapping| mapping.source_id);
    mappings
}

struct SourceData {
    groups: Vec<cr::groups::Model>,
    users: Vec<cr::users::Model>,
    policies: Vec<cr::storage_policies::Model>,
    files: Vec<cr::files::Model>,
    entities: Vec<cr::entities::Model>,
    file_entities: Vec<cr::file_entities::Model>,
    shares: Vec<cr::shares::Model>,
    metadata: Vec<cr::metadata::Model>,
    direct_links: Vec<cr::direct_links::Model>,
    tasks: Vec<cr::tasks::Model>,
}

impl SourceData {
    async fn load(db: &DatabaseConnection, include_deleted: bool) -> Result<Self> {
        let groups = cr::groups::Entity::find().all(db).await?;
        let users = cr::users::Entity::find().all(db).await?;
        let policies = cr::storage_policies::Entity::find().all(db).await?;
        let files = cr::files::Entity::find().all(db).await?;
        let entities = cr::entities::Entity::find().all(db).await?;
        let file_entities = cr::file_entities::Entity::find().all(db).await?;
        let shares = cr::shares::Entity::find().all(db).await?;
        let metadata = cr::metadata::Entity::find().all(db).await?;
        let direct_links = cr::direct_links::Entity::find().all(db).await?;
        let tasks = cr::tasks::Entity::find().all(db).await?;

        Ok(Self {
            groups: filter_deleted(groups, include_deleted, |model| model.deleted_at.is_some()),
            users: filter_deleted(users, include_deleted, |model| model.deleted_at.is_some()),
            policies: filter_deleted(policies, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            files,
            entities: filter_deleted(entities, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            file_entities,
            shares: filter_deleted(shares, include_deleted, |model| model.deleted_at.is_some()),
            metadata: filter_deleted(metadata, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            direct_links: filter_deleted(direct_links, include_deleted, |model| {
                model.deleted_at.is_some()
            }),
            tasks: filter_deleted(tasks, include_deleted, |model| model.deleted_at.is_some()),
        })
    }

    fn report(&self) -> MigrationReport {
        MigrationReport {
            source_users: self.users.len() as u64,
            source_groups: self.groups.len() as u64,
            source_policies: self.policies.len() as u64,
            source_folders: self.files.iter().filter(|file| file.r#type == 1).count() as u64,
            source_files: self.files.iter().filter(|file| file.r#type == 0).count() as u64,
            source_entities: self.entities.len() as u64,
            source_shares: self.shares.len() as u64,
            source_direct_links: self.direct_links.len() as u64,
            source_tag_assignments: self
                .metadata
                .iter()
                .filter(|metadata| tag_name(&metadata.name).is_some())
                .count() as u64,
            source_tasks: self.tasks.len() as u64,
            ..Default::default()
        }
    }

    fn unsupported_policy_types(&self) -> Vec<String> {
        let mut values: Vec<String> = self
            .policies
            .iter()
            .filter_map(unsupported_policy_reason)
            .collect();
        values.sort();
        values.dedup();
        values
    }

    fn compatibility_warnings(&self) -> Vec<String> {
        let mut warnings = vec![
            "Cloudreve user passwords use SHA/legacy MD5 formats and are replaced by the supplied temporary Argon2 password; every migrated user is marked must_change_password".to_string(),
            "OAuth grants, login sessions and Cloudreve filesystem events are intentionally not migrated".to_string(),
            "Cloudreve Passkeys, WebDAV credentials and two-factor secrets are not portable to AD and must be enrolled again".to_string(),
            "file objects are reused in their existing local/object-storage locations; the migration does not duplicate object bytes".to_string(),
            "Cloudreve tasks are archived as terminal AD system_runtime records; queued, processing and suspending tasks are canceled instead of resumed".to_string(),
        ];
        let symbolic = self.files.iter().filter(|file| file.is_symbolic).count();
        if symbolic > 0 {
            warnings.push(format!(
                "{symbolic} symbolic/placeholder Cloudreve files cannot be represented in AD and will be skipped"
            ));
        }
        let unsupported = self.unsupported_policy_types();
        if !unsupported.is_empty() {
            warnings.push(format!(
                "unsupported storage policy types detected: {}",
                unsupported.join(", ")
            ));
        }
        if !self.direct_links.is_empty() {
            warnings.push("Cloudreve direct links require --direct-link-secret to regenerate AD v2 URLs; old /f/... URLs, per-link counters, speed limits and revocation semantics cannot be preserved".to_string());
        }
        warnings
    }
}

fn filter_deleted<T, F>(items: Vec<T>, include_deleted: bool, deleted: F) -> Vec<T>
where
    F: Fn(&T) -> bool,
{
    if include_deleted {
        items
    } else {
        items.into_iter().filter(|item| !deleted(item)).collect()
    }
}

fn map_driver_type(source: &str) -> Option<&'static str> {
    match source {
        "local" => Some("local"),
        "s3" | "oss" | "ks3" | "obs" => Some("s3"),
        "cos" => Some("tencent_cos"),
        _ => None,
    }
}

fn unsupported_policy_reason(policy: &cr::storage_policies::Model) -> Option<String> {
    if map_driver_type(&policy.r#type).is_none() {
        return Some(policy.r#type.clone());
    }
    if source_settings(&policy.settings)
        .get("encryption")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Some(format!("{} (Cloudreve encryption enabled)", policy.r#type));
    }
    None
}

fn source_settings(value: &Option<Value>) -> Value {
    value.clone().unwrap_or_else(|| json!({}))
}

fn policy_options(policy: &cr::storage_policies::Model) -> String {
    let settings = source_settings(&policy.settings);
    let path_style = settings
        .get("s3_path_style")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    json!({
        "s3_path_style": path_style,
        "object_storage_upload_strategy": "relay_stream",
        "object_storage_download_strategy": "relay_stream",
        "cloudreve_source": settings,
        "cloudreve_policy_type": policy.r#type,
    })
    .to_string()
}

fn allowed_types(policy: &cr::storage_policies::Model) -> String {
    source_settings(&policy.settings)
        .get("file_type")
        .cloned()
        .unwrap_or_else(|| json!([]))
        .to_string()
}

fn chunk_size(policy: &cr::storage_policies::Model) -> i64 {
    source_settings(&policy.settings)
        .get("chunk_size")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn group_is_admin(group: &cr::groups::Model) -> bool {
    group
        .permissions
        .first()
        .is_some_and(|permissions| permissions & 1 == 1)
}

fn opaque_blob_key(entity_id: i64) -> String {
    format!("cloudreve-{entity_id:016x}")
}

fn share_token(share_id: i64) -> String {
    let digest = Sha256::digest(format!("cloudreve-share-{share_id}").as_bytes());
    format!("cr-{share_id}-{}", &format!("{digest:x}")[..16])
}

fn tag_name(metadata_name: &str) -> Option<&str> {
    metadata_name
        .strip_prefix("tag:")
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn normalize_tag_name(name: &str) -> String {
    name.trim().to_lowercase()
}

fn target_tag_name(name: &str) -> String {
    name.trim().chars().take(64).collect()
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
    "#3b82f6".to_string()
}

fn encode_base62(mut value: u64) -> String {
    const BASE62: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if value == 0 {
        return "a".to_string();
    }
    let mut encoded = Vec::new();
    while value > 0 {
        encoded.push(char::from(BASE62[(value % 62) as usize]));
        value /= 62;
    }
    encoded.iter().rev().collect()
}

fn direct_link_url(
    file_id: i64,
    owner_user_id: i64,
    file_name: &str,
    secret: &str,
) -> Result<String> {
    let file_id = u64::try_from(file_id).wrap_err("AD direct link file ID must be non-negative")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| color_eyre::eyre::eyre!("initialize direct link HMAC: {error}"))?;
    mac.update(b"direct_link:v2:");
    mac.update(format!("user:{owner_user_id}").as_bytes());
    mac.update(b":");
    mac.update(file_id.to_string().as_bytes());
    let signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!(
        "/d/v2.{}.{}/{}",
        encode_base62(file_id),
        signature,
        urlencoding::encode(file_name)
    ))
}

fn archived_task_status(source_status: &str) -> &'static str {
    match source_status {
        "completed" => "succeeded",
        "error" => "failed",
        "canceled" | "queued" | "processing" | "suspending" => "canceled",
        _ => "canceled",
    }
}

fn source_task_was_active(source_status: &str) -> bool {
    matches!(source_status, "queued" | "processing" | "suspending")
}

fn unique_username(source: &str, source_id: i64, used: &mut HashSet<String>) -> String {
    let mut base: String = source
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect();
    if base.is_empty() {
        base = format!("cloudreve-user-{source_id}");
    }
    if used.insert(base.clone()) {
        return base;
    }
    let suffix = format!("-{source_id}");
    let keep = 64usize.saturating_sub(suffix.chars().count());
    let mut candidate: String = base.chars().take(keep).collect();
    candidate.push_str(&suffix);
    let mut discriminator = 2;
    while !used.insert(candidate.clone()) {
        let suffix = format!("-{source_id}-{discriminator}");
        let keep = 64usize.saturating_sub(suffix.chars().count());
        candidate = base.chars().take(keep).collect();
        candidate.push_str(&suffix);
        discriminator += 1;
    }
    candidate
}

fn file_classification(name: &str) -> (String, Option<String>, String, String) {
    let mime = mime_guess::from_path(name)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let lowercase = name.to_ascii_lowercase();
    let extension = lowercase
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_string())
        .unwrap_or_default();
    let compound_extension = ["tar.gz", "tar.bz2", "tar.xz", "user.js"]
        .into_iter()
        .find(|candidate| lowercase.ends_with(candidate))
        .map(str::to_string);
    let category = if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else if mime.starts_with("audio/") {
        "audio"
    } else if ["zip", "rar", "7z", "gz", "bz2", "xz", "tar"].contains(&extension.as_str()) {
        "archive"
    } else if ["xls", "xlsx", "csv", "ods"].contains(&extension.as_str()) {
        "spreadsheet"
    } else if ["ppt", "pptx", "odp"].contains(&extension.as_str()) {
        "presentation"
    } else if [
        "rs", "go", "js", "ts", "py", "java", "c", "cpp", "html", "css", "json", "yaml", "yml",
        "toml",
    ]
    .contains(&extension.as_str())
    {
        "code"
    } else if mime.starts_with("text/")
        || ["pdf", "doc", "docx", "odt", "md"].contains(&extension.as_str())
    {
        "document"
    } else {
        "other"
    };
    (mime, compound_extension, extension, category.to_string())
}

mod phases;
use phases::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, DbBackend, Schema};

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
        assert_eq!(map_driver_type("local"), Some("local"));
        assert_eq!(map_driver_type("oss"), Some("s3"));
        assert_eq!(map_driver_type("cos"), Some("tencent_cos"));
        assert_eq!(map_driver_type("onedrive"), None);
        assert_eq!(map_driver_type("qiniu"), None);
    }

    #[test]
    fn parses_and_normalizes_cloudreve_tags_for_ad() {
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

    #[tokio::test]
    async fn migrates_minimal_cloudreve_database() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        source.close().await?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "C:/cloudreve".to_string(),
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
        })
        .await?;

        assert_eq!(report.migrated_users, 1);
        assert_eq!(report.migrated_folders, 1);
        assert_eq!(report.migrated_files, 1);
        assert_eq!(report.migrated_blobs, 1);
        assert_eq!(report.migrated_shares, 1);
        assert_eq!(report.migrated_properties, 3);
        assert_eq!(report.migrated_tags, 1);
        assert_eq!(report.migrated_tag_assignments, 1);
        assert_eq!(report.migrated_direct_links, 1);
        assert_eq!(report.migrated_tasks, 2);
        assert!(report.validation.performed);
        assert!(report.validation.passed);
        assert!(report.validation.checks.iter().all(|check| check.passed));
        assert_eq!(report.mappings.users.len(), 1);
        assert_eq!(report.mappings.folders.len(), 1);
        assert_eq!(report.mappings.files.len(), 1);
        assert_eq!(report.mappings.blobs.len(), 1);
        assert_eq!(report.mappings.shares.len(), 1);
        assert_eq!(report.mappings.tasks.len(), 2);
        assert_eq!(report.direct_links.len(), 1);
        assert!(report.direct_links[0].url.starts_with("/d/v2."));
        assert_eq!(report.tag_assignments.len(), 1);
        assert_eq!(report.tag_assignments[0].target_entity_type, "file");

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::users::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::folders::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::files::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::file_blobs::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::shares::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::tags::Entity::find().count(&target).await?, 1);
        assert_eq!(
            ad::background_tasks::Entity::find().count(&target).await?,
            2
        );
        assert_eq!(
            ad::entity_properties::Entity::find().count(&target).await?,
            3
        );
        let properties = ad::entity_properties::Entity::find().all(&target).await?;
        assert!(
            properties.iter().any(|property| {
                property.namespace == "system.tags" && property.value.is_none()
            })
        );
        let direct_link = properties
            .iter()
            .find(|property| property.namespace == "cloudreve.direct_links")
            .and_then(|property| property.value.as_deref())
            .expect("migrated direct link mapping");
        assert!(direct_link.contains("/d/v2."));
        let tasks = ad::background_tasks::Entity::find().all(&target).await?;
        assert!(tasks.iter().all(|task| {
            matches!(task.status.as_str(), "succeeded" | "failed" | "canceled")
                && task.kind == "system_runtime"
                && task.lease_expires_at.is_none()
        }));
        assert!(tasks.iter().any(|task| task.status == "succeeded"));
        assert!(tasks.iter().any(|task| task.status == "canceled"));
        let blob = ad::file_blobs::Entity::find().one(&target).await?.unwrap();
        assert_eq!(blob.storage_path, "uploads/object.bin");
        let user = ad::users::Entity::find().one(&target).await?.unwrap();
        assert!(user.must_change_password);
        assert_eq!(user.role, "admin");
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    fn sqlite_url(path: &std::path::Path) -> String {
        format!(
            "sqlite://{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        )
    }

    async fn create_table<E: EntityTrait>(db: &DatabaseConnection, entity: E) -> Result<()> {
        let schema = Schema::new(DbBackend::Sqlite);
        db.execute(&schema.create_table_from_entity(entity)).await?;
        Ok(())
    }

    async fn create_source_schema(db: &DatabaseConnection) -> Result<()> {
        create_table(db, cr::nodes::Entity).await?;
        create_table(db, cr::groups::Entity).await?;
        create_table(db, cr::users::Entity).await?;
        create_table(db, cr::storage_policies::Entity).await?;
        create_table(db, cr::files::Entity).await?;
        create_table(db, cr::entities::Entity).await?;
        create_table(db, cr::file_entities::Entity).await?;
        create_table(db, cr::shares::Entity).await?;
        create_table(db, cr::metadata::Entity).await?;
        create_table(db, cr::direct_links::Entity).await?;
        create_table(db, cr::tasks::Entity).await?;
        Ok(())
    }

    async fn create_target_schema(db: &DatabaseConnection) -> Result<()> {
        create_table(db, ad::managed_followers::Entity).await?;
        create_table(db, ad::storage_policy_groups::Entity).await?;
        create_table(db, ad::storage_policies::Entity).await?;
        create_table(db, ad::storage_policy_group_items::Entity).await?;
        create_table(db, ad::users::Entity).await?;
        create_table(db, ad::user_profiles::Entity).await?;
        create_table(db, ad::folders::Entity).await?;
        create_table(db, ad::file_blobs::Entity).await?;
        create_table(db, ad::files::Entity).await?;
        create_table(db, ad::file_versions::Entity).await?;
        create_table(db, ad::entity_properties::Entity).await?;
        create_table(db, ad::shares::Entity).await?;
        create_table(db, ad::teams::Entity).await?;
        create_table(db, ad::tags::Entity).await?;
        create_table(db, ad::background_tasks::Entity).await?;
        Ok(())
    }

    async fn seed_source(db: &DatabaseConnection) -> Result<()> {
        let now = chrono::Utc::now().fixed_offset();
        let policy = cr::storage_policies::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            name: Set("Local".to_string()),
            r#type: Set("local".to_string()),
            server: Set(None),
            bucket_name: Set(None),
            is_private: Set(Some(true)),
            access_key: Set(None),
            secret_key: Set(None),
            max_size: Set(None),
            dir_name_rule: Set(None),
            file_name_rule: Set(None),
            settings: Set(Some(json!({"chunk_size": 0}))),
            node_id: Set(None),
            ..Default::default()
        }
        .insert(db)
        .await?;
        let group = cr::groups::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            name: Set("Administrators".to_string()),
            max_storage: Set(Some(1024 * 1024)),
            speed_limit: Set(None),
            permissions: Set(vec![1]),
            settings: Set(None),
            storage_policy_id: Set(Some(policy.id)),
            ..Default::default()
        }
        .insert(db)
        .await?;
        let user = cr::users::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            email: Set("admin@example.test".to_string()),
            nick: Set("admin".to_string()),
            password: Set(Some("legacy:hash".to_string())),
            status: Set("active".to_string()),
            storage: Set(128),
            two_factor_secret: Set(None),
            avatar: Set(None),
            settings: Set(None),
            group_users: Set(group.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        let folder = cr::files::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            r#type: Set(1),
            name: Set("Documents".to_string()),
            size: Set(0),
            primary_entity: Set(None),
            is_symbolic: Set(false),
            props: Set(None),
            file_children: Set(None),
            storage_policy_files: Set(Some(policy.id)),
            owner_id: Set(user.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        let entity = cr::entities::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            r#type: Set(0),
            source: Set("uploads/object.bin".to_string()),
            size: Set(128),
            reference_count: Set(1),
            upload_session_id: Set(None),
            recycle_options: Set(None),
            storage_policy_entities: Set(policy.id),
            created_by: Set(Some(user.id)),
            ..Default::default()
        }
        .insert(db)
        .await?;
        let file = cr::files::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            r#type: Set(0),
            name: Set("hello.txt".to_string()),
            size: Set(128),
            primary_entity: Set(Some(entity.id)),
            is_symbolic: Set(false),
            props: Set(None),
            file_children: Set(Some(folder.id)),
            storage_policy_files: Set(Some(policy.id)),
            owner_id: Set(user.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        cr::file_entities::ActiveModel {
            file_id: Set(file.id),
            entity_id: Set(entity.id),
        }
        .insert(db)
        .await?;
        cr::metadata::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            name: Set("author".to_string()),
            value: Set("Cloudreve".to_string()),
            is_public: Set(true),
            file_id: Set(file.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        cr::metadata::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            name: Set("tag:Important".to_string()),
            value: Set("#abc".to_string()),
            is_public: Set(true),
            file_id: Set(file.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        cr::shares::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            password: Set(Some("share-password".to_string())),
            views: Set(4),
            downloads: Set(2),
            expires: Set(None),
            remain_downloads: Set(Some(3)),
            file_shares: Set(Some(file.id)),
            user_shares: Set(Some(user.id)),
            props: Set(None),
            ..Default::default()
        }
        .insert(db)
        .await?;
        cr::direct_links::ActiveModel {
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
            name: Set("legacy-name.txt".to_string()),
            downloads: Set(7),
            speed: Set(1024),
            file_id: Set(file.id),
            ..Default::default()
        }
        .insert(db)
        .await?;
        for status in ["completed", "processing"] {
            cr::tasks::ActiveModel {
                created_at: Set(now),
                updated_at: Set(now),
                deleted_at: Set(None),
                r#type: Set("remote_download".to_string()),
                status: Set(status.to_string()),
                public_state: Set(json!({"progress": 50})),
                private_state: Set(Some("legacy-private-state".to_string())),
                correlation_id: Set(None),
                user_tasks: Set(Some(user.id)),
                ..Default::default()
            }
            .insert(db)
            .await?;
        }
        Ok(())
    }
}
