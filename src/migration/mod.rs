use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Write};
use std::io::{Read, Write as IoWrite};
use std::path::{Component, Path, PathBuf};

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use base64::Engine;
use color_eyre::eyre::{Result, WrapErr, bail};
use hmac::{Hmac, Mac};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use asterdrive_entities as ad;
use cloudreve_entities as cr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StorageMode {
    #[value(name = "reuse-source-storage")]
    ReuseSourceStorage,
    #[value(name = "copy-local")]
    CopyLocal,
}

#[derive(Debug, Clone)]
pub struct MigrationOptions {
    pub source_url: String,
    pub target_url: String,
    pub default_password: String,
    pub local_base_path: String,
    pub local_policy_roots: BTreeMap<i64, String>,
    pub storage_mode: StorageMode,
    pub target_local_base_path: Option<String>,
    pub target_local_policy_roots: BTreeMap<i64, String>,
    pub verify_local_storage: bool,
    pub direct_link_secret: Option<String>,
    pub include_deleted: bool,
    pub allow_non_empty_target: bool,
    pub skip_unsupported_policies: bool,
    pub dry_run: bool,
    pub run_id: Option<String>,
    pub resume: bool,
    pub blob_batch_size: usize,
    pub file_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub run_id: Option<String>,
    pub resumed: bool,
    pub completed_stages: Vec<String>,
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
            dry_run: true,
            warnings: Vec::new(),
            skipped_by_type: BTreeMap::new(),
            skipped_objects: Vec::new(),
            mappings: MigrationMappings::default(),
            direct_links: Vec::new(),
            tag_assignments: Vec::new(),
            validation: MigrationValidation::default(),
            run_id: None,
            resumed: false,
            completed_stages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedObject {
    pub object_type: String,
    pub source_id: Option<i64>,
    pub reason: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdMapping {
    pub source_id: i64,
    pub target_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectLinkReport {
    pub source_direct_link_id: i64,
    pub source_file_id: i64,
    pub target_file_id: i64,
    pub source_name: String,
    pub source_downloads: i64,
    pub source_speed_limit: i64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagAssignmentReport {
    pub source_metadata_id: i64,
    pub source_entity_id: i64,
    pub target_entity_type: String,
    pub target_entity_id: i64,
    pub target_tag_id: i64,
    pub tag_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    fn set_mappings(
        &mut self,
        context: &MigrationContext,
        blobs: &HashMap<i64, i64>,
        files: &HashMap<i64, i64>,
    ) {
        self.mappings = MigrationMappings {
            policies: sorted_id_mappings(&context.policies),
            policy_groups: sorted_id_mappings(&context.policy_groups),
            users: sorted_id_mappings(&context.users),
            folders: sorted_id_mappings(&context.folders),
            blobs: sorted_id_mappings(blobs),
            files: sorted_id_mappings(files),
            shares: sorted_id_mappings(&context.shares),
            tasks: sorted_id_mappings(&context.tasks),
        };
    }
}

impl fmt::Display for MigrationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        writeln!(output, "Cloudreve -> AsterDrive migration report")?;
        if let Some(run_id) = &self.run_id {
            writeln!(
                output,
                "run: {run_id}{}",
                if self.resumed { " (resumed)" } else { "" }
            )?;
        }
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
            if !self.completed_stages.is_empty() {
                writeln!(
                    output,
                    "completed_stages: {}",
                    self.completed_stages.join(",")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationStage {
    Policies,
    PolicyGroups,
    Users,
    Folders,
    Blobs,
    Files,
    Metadata,
    Shares,
    DirectLinks,
    Tasks,
}

impl MigrationStage {
    const ALL: [Self; 10] = [
        Self::Policies,
        Self::PolicyGroups,
        Self::Users,
        Self::Folders,
        Self::Blobs,
        Self::Files,
        Self::Metadata,
        Self::Shares,
        Self::DirectLinks,
        Self::Tasks,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Policies => "policies",
            Self::PolicyGroups => "policy_groups",
            Self::Users => "users",
            Self::Folders => "folders",
            Self::Blobs => "blobs",
            Self::Files => "files",
            Self::Metadata => "metadata",
            Self::Shares => "shares",
            Self::DirectLinks => "direct_links",
            Self::Tasks => "tasks",
        }
    }

    fn should_run_after(self, last_completed_stage: Option<&str>) -> Result<bool> {
        let Some(last_completed_stage) = last_completed_stage else {
            return Ok(true);
        };
        let last_index = Self::ALL
            .iter()
            .position(|stage| stage.as_str() == last_completed_stage)
            .ok_or_else(|| {
                color_eyre::eyre::eyre!("checkpoint contains unknown stage {last_completed_stage}")
            })?;
        let current_index = Self::ALL
            .iter()
            .position(|stage| *stage == self)
            .expect("migration stage must exist in ALL");
        Ok(current_index > last_index)
    }
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
    if options.resume && options.run_id.is_none() {
        bail!("--resume requires --run-id");
    }
    if options.resume && options.dry_run {
        bail!("--resume cannot be combined with --dry-run");
    }
    if let Some(run_id) = options.run_id.as_deref() {
        validate_run_id(run_id)?;
    }
    if !(1..=10_000).contains(&options.blob_batch_size) {
        bail!("--blob-batch-size must be between 1 and 10000");
    }
    if !(1..=10_000).contains(&options.file_batch_size) {
        bail!("--file-batch-size must be between 1 and 10000");
    }

    let source = connect(&options.source_url, "Cloudreve").await?;
    let target = connect(&options.target_url, "AsterDrive").await?;
    let source_data = SourceData::load(&source, options.include_deleted).await?;
    validate_target_schema(&target).await?;

    let unsupported = source_data.unsupported_policy_types();
    if !unsupported.is_empty() && !options.skip_unsupported_policies {
        bail!(
            "unsupported Cloudreve storage policy types: {}; rerun with --skip-unsupported-policies to omit their files",
            unsupported.join(", ")
        );
    }
    validate_local_policy_roots(&source_data, &options)?;
    if options.verify_local_storage || options.storage_mode == StorageMode::CopyLocal {
        verify_local_storage_roots(&source_data, &options)?;
    }
    if options.storage_mode == StorageMode::CopyLocal {
        verify_target_local_storage_roots(&source_data, &options)?;
    }
    if options.dry_run
        && (options.verify_local_storage || options.storage_mode == StorageMode::CopyLocal)
    {
        verify_all_local_source_objects(&source, &source_data, &options).await?;
    }

    let mut report = source_data.report();
    report.dry_run = options.dry_run;
    report.warnings.extend(source_data.compatibility_warnings());
    if options.dry_run {
        report.run_id = options.run_id.clone();
        return Ok(report);
    }

    checkpoint::ensure_table(&target).await?;
    let run_id = options
        .run_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let source_fingerprint = source_fingerprint(&options.source_url, &source_data);
    let target_fingerprint = hash_fingerprint(&options.target_url);
    let plan_fingerprint = plan_fingerprint(&options);

    let (mut context, target_before, mut last_completed_stage) = if options.resume {
        let loaded = checkpoint::load(
            &target,
            &run_id,
            &source_fingerprint,
            &target_fingerprint,
            &plan_fingerprint,
        )
        .await?;
        if !matches!(
            loaded.status.as_str(),
            "running" | "failed" | "validation_failed" | "completed"
        ) {
            bail!(
                "migration run {run_id} has unsupported status {}",
                loaded.status
            );
        }
        report = loaded.report;
        report.resumed = true;
        report.run_id = Some(run_id.clone());
        (loaded.context, loaded.baseline, loaded.last_completed_stage)
    } else {
        ensure_target_safe(&target, options.allow_non_empty_target).await?;
        let baseline = TargetCounts::load(&target).await?;
        report.run_id = Some(run_id.clone());
        let context = MigrationContext::default();
        checkpoint::create(
            &target,
            checkpoint::NewCheckpoint {
                run_id: &run_id,
                source_fingerprint: &source_fingerprint,
                target_fingerprint: &target_fingerprint,
                plan_fingerprint: &plan_fingerprint,
                context: &context,
                report: &report,
                baseline: &baseline,
            },
        )
        .await?;
        (context, baseline, None)
    };
    let mut blob_mappings = checkpoint::load_object_mappings(&target, &run_id, "blob").await?;
    if blob_mappings.is_empty() && !context.blobs.is_empty() {
        let legacy_mappings = context
            .blobs
            .iter()
            .map(|(source_id, target_id)| (*source_id, *target_id))
            .collect::<Vec<_>>();
        checkpoint::save_object_mappings(&target, &run_id, "blob", &legacy_mappings).await?;
        blob_mappings.extend(legacy_mappings);
        context.blobs.clear();
    }
    if report.migrated_blobs != blob_mappings.len() {
        bail!(
            "migration run {run_id} blob mapping count {} does not match migrated blob count {}; restore the checkpoint tables before resuming",
            blob_mappings.len(),
            report.migrated_blobs
        );
    }
    let mut file_mappings = checkpoint::load_object_mappings(&target, &run_id, "file").await?;
    if file_mappings.is_empty() && !context.files.is_empty() {
        let legacy_mappings = context
            .files
            .iter()
            .map(|(source_id, target_id)| (*source_id, *target_id))
            .collect::<Vec<_>>();
        checkpoint::save_object_mappings(&target, &run_id, "file", &legacy_mappings).await?;
        file_mappings.extend(legacy_mappings);
        context.files.clear();
    }
    if report.migrated_files != file_mappings.len() {
        bail!(
            "migration run {run_id} file mapping count {} does not match migrated file count {}; restore the checkpoint tables before resuming",
            file_mappings.len(),
            report.migrated_files
        );
    }

    let password_hash = hash_password(&options.default_password)?;

    for stage in MigrationStage::ALL {
        if !stage.should_run_after(last_completed_stage.as_deref())? {
            continue;
        }
        if stage == MigrationStage::Blobs {
            let inputs = BlobBatchInputs {
                source: &source,
                target: &target,
                run_id: &run_id,
                source_data: &source_data,
                options: &options,
                context: &context,
                file_mappings: &file_mappings,
            };
            if let Err(error) =
                migrate_blobs_batched(&inputs, &mut blob_mappings, &mut report).await
            {
                let _ = checkpoint::mark_failed(&target, &run_id, &error.to_string()).await;
                return Err(error).wrap_err_with(|| {
                    format!(
                        "migration run {run_id} failed at stage {}; rerun with --resume --run-id {run_id}",
                        stage.as_str()
                    )
                });
            }
            last_completed_stage = Some(stage.as_str().to_string());
            continue;
        }
        if stage == MigrationStage::Files {
            let inputs = FileBatchInputs {
                source: &source,
                target: &target,
                run_id: &run_id,
                source_data: &source_data,
                options: &options,
                context: &context,
                blob_mappings: &blob_mappings,
            };
            if let Err(error) =
                migrate_files_batched(&inputs, &mut file_mappings, &mut report).await
            {
                let _ = checkpoint::mark_failed(&target, &run_id, &error.to_string()).await;
                return Err(error).wrap_err_with(|| {
                    format!(
                        "migration run {run_id} failed at stage {}; rerun with --resume --run-id {run_id}",
                        stage.as_str()
                    )
                });
            }
            last_completed_stage = Some(stage.as_str().to_string());
            continue;
        }
        let transaction = target
            .begin()
            .await
            .wrap_err_with(|| format!("begin migration stage {}", stage.as_str()))?;
        let stage_result: Result<()> = async {
            let inputs = StageInputs {
                source_db: &source,
                source_data: &source_data,
                options: &options,
                password_hash: &password_hash,
                file_mappings: &file_mappings,
            };
            execute_stage(stage, &transaction, &inputs, &mut context, &mut report).await?;
            report.set_mappings(&context, &blob_mappings, &file_mappings);
            if !report
                .completed_stages
                .iter()
                .any(|completed| completed == stage.as_str())
            {
                report.completed_stages.push(stage.as_str().to_string());
            }
            checkpoint::save_stage(&transaction, &run_id, stage.as_str(), &context, &report).await
        }
        .await;
        if let Err(error) = stage_result {
            drop(transaction);
            let _ = checkpoint::mark_failed(&target, &run_id, &error.to_string()).await;
            return Err(error).wrap_err_with(|| {
                format!(
                    "migration run {run_id} failed at stage {}; rerun with --resume --run-id {run_id}",
                    stage.as_str()
                )
            });
        }
        if let Err(error) = transaction.commit().await {
            let _ = checkpoint::mark_failed(&target, &run_id, &error.to_string()).await;
            return Err(error).wrap_err_with(|| {
                format!(
                    "commit migration run {run_id} stage {}; resume with the same run ID",
                    stage.as_str()
                )
            });
        }
        last_completed_stage = Some(stage.as_str().to_string());
    }

    report.set_mappings(&context, &blob_mappings, &file_mappings);
    report.validation = match validate_migration_result(&target, &target_before, &report).await {
        Ok(validation) => validation,
        Err(error) => {
            let _ = checkpoint::mark_failed(&target, &run_id, &error.to_string()).await;
            return Err(error)
                .wrap_err_with(|| format!("validate completed migration run {run_id}"));
        }
    };
    report.generated_at = chrono::Utc::now();
    checkpoint::finish(
        &target,
        &run_id,
        if report.validation.passed {
            "completed"
        } else {
            "validation_failed"
        },
        &context,
        &report,
    )
    .await?;
    Ok(report)
}

struct StageInputs<'a> {
    source_db: &'a DatabaseConnection,
    source_data: &'a SourceData,
    options: &'a MigrationOptions,
    password_hash: &'a str,
    file_mappings: &'a HashMap<i64, i64>,
}

async fn execute_stage(
    stage: MigrationStage,
    transaction: &sea_orm::DatabaseTransaction,
    inputs: &StageInputs<'_>,
    context: &mut MigrationContext,
    report: &mut MigrationReport,
) -> Result<()> {
    match stage {
        MigrationStage::Policies => {
            migrate_policies(
                transaction,
                inputs.source_data,
                inputs.options,
                context,
                report,
            )
            .await
        }
        MigrationStage::PolicyGroups => {
            migrate_policy_groups(transaction, inputs.source_data, context, report).await
        }
        MigrationStage::Users => {
            migrate_users(
                transaction,
                inputs.source_data,
                inputs.password_hash,
                context,
                report,
            )
            .await
        }
        MigrationStage::Folders => {
            migrate_folders(transaction, inputs.source_data, context, report).await
        }
        MigrationStage::Blobs => bail!("blobs stage must use the batched runner"),
        MigrationStage::Files => bail!("files stage must use the batched runner"),
        MigrationStage::Metadata => {
            migrate_metadata(
                transaction,
                inputs.source_db,
                inputs.source_data,
                inputs.file_mappings,
                context,
                report,
            )
            .await
        }
        MigrationStage::Shares => {
            migrate_shares(
                transaction,
                inputs.source_db,
                inputs.source_data,
                inputs.file_mappings,
                context,
                report,
            )
            .await
        }
        MigrationStage::DirectLinks => {
            migrate_direct_links(
                transaction,
                inputs.source_db,
                inputs.source_data,
                inputs.file_mappings,
                context,
                inputs.options.direct_link_secret.as_deref(),
                report,
            )
            .await
        }
        MigrationStage::Tasks => {
            migrate_tasks(transaction, inputs.source_data, context, report).await
        }
    }
}

struct BlobBatchInputs<'a> {
    source: &'a DatabaseConnection,
    target: &'a DatabaseConnection,
    run_id: &'a str,
    source_data: &'a SourceData,
    options: &'a MigrationOptions,
    context: &'a MigrationContext,
    file_mappings: &'a HashMap<i64, i64>,
}

async fn migrate_blobs_batched(
    inputs: &BlobBatchInputs<'_>,
    blob_mappings: &mut HashMap<i64, i64>,
    report: &mut MigrationReport,
) -> Result<()> {
    let cursor =
        checkpoint::load_stage_cursor(inputs.target, inputs.run_id, MigrationStage::Blobs.as_str())
            .await?;
    let mut cursor_value = cursor.as_ref().map_or(0, |cursor| cursor.cursor_value);
    let mut processed_count = cursor.as_ref().map_or(0, |cursor| cursor.processed_count);

    loop {
        let mut query = cr::entities::Entity::find()
            .filter(cr::entities::Column::Type.eq(0))
            .filter(cr::entities::Column::Id.gt(cursor_value))
            .order_by_asc(cr::entities::Column::Id)
            .limit(inputs.options.blob_batch_size as u64);
        if !inputs.source_data.include_deleted {
            query = query.filter(cr::entities::Column::DeletedAt.is_null());
        }
        let entities = query.all(inputs.source).await?;
        if entities.is_empty() {
            let transaction = inputs
                .target
                .begin()
                .await
                .wrap_err("begin blobs completion")?;
            report.set_mappings(inputs.context, blob_mappings, inputs.file_mappings);
            if !report
                .completed_stages
                .iter()
                .any(|completed| completed == MigrationStage::Blobs.as_str())
            {
                report
                    .completed_stages
                    .push(MigrationStage::Blobs.as_str().to_string());
            }
            checkpoint::save_stage(
                &transaction,
                inputs.run_id,
                MigrationStage::Blobs.as_str(),
                inputs.context,
                report,
            )
            .await?;
            transaction
                .commit()
                .await
                .wrap_err("commit blobs completion")?;
            return Ok(());
        }

        if inputs.options.verify_local_storage {
            verify_local_blob_batch(
                &entities,
                inputs.source_data,
                inputs.options,
                inputs.context,
            )?;
        }

        let entity_ids = entities.iter().map(|entity| entity.id).collect::<Vec<_>>();
        let association_info = load_blob_association_info(inputs.source, &entity_ids).await?;
        let last_entity_id = entities.last().expect("non-empty blob batch").id;
        let copied_objects = copy_local_blob_batch(
            &entities,
            inputs.source_data,
            inputs.options,
            inputs.context,
            inputs.run_id,
        )?;
        let transaction = inputs.target.begin().await.wrap_err("begin blobs batch")?;
        let report_before_batch = report.clone();
        let batch_result: Result<Vec<(i64, i64)>> = async {
            let mappings = migrate_blob_batch(
                &transaction,
                &entities,
                &association_info.reference_counts,
                &association_info.thumbnail_paths,
                &copied_objects.objects,
                inputs.context,
                report,
            )
            .await?;
            checkpoint::save_object_mappings(&transaction, inputs.run_id, "blob", &mappings)
                .await?;
            processed_count += entities.len() as i64;
            checkpoint::save_stage_cursor(
                &transaction,
                inputs.run_id,
                MigrationStage::Blobs.as_str(),
                last_entity_id,
                processed_count,
            )
            .await?;
            checkpoint::save_progress(&transaction, inputs.run_id, inputs.context, report).await?;
            Ok(mappings)
        }
        .await;
        let mappings = match batch_result {
            Ok(mappings) => mappings,
            Err(error) => {
                let _ = transaction.rollback().await;
                *report = report_before_batch;
                copied_objects.compensate()?;
                return Err(error);
            }
        };
        if let Err(error) = transaction.commit().await {
            return Err(error).wrap_err("commit blobs batch");
        }
        blob_mappings.extend(mappings);
        cursor_value = last_entity_id;
    }
}

struct FileBatchInputs<'a> {
    source: &'a DatabaseConnection,
    target: &'a DatabaseConnection,
    run_id: &'a str,
    source_data: &'a SourceData,
    options: &'a MigrationOptions,
    context: &'a MigrationContext,
    blob_mappings: &'a HashMap<i64, i64>,
}

async fn migrate_files_batched(
    inputs: &FileBatchInputs<'_>,
    file_mappings: &mut HashMap<i64, i64>,
    report: &mut MigrationReport,
) -> Result<()> {
    let cursor =
        checkpoint::load_stage_cursor(inputs.target, inputs.run_id, MigrationStage::Files.as_str())
            .await?;
    let mut cursor_value = cursor.as_ref().map_or(0, |cursor| cursor.cursor_value);
    let mut processed_count = cursor.as_ref().map_or(0, |cursor| cursor.processed_count);

    loop {
        let files = cr::files::Entity::find()
            .filter(cr::files::Column::Type.eq(0))
            .filter(cr::files::Column::Id.gt(cursor_value))
            .order_by_asc(cr::files::Column::Id)
            .limit(inputs.options.file_batch_size as u64)
            .all(inputs.source)
            .await?;
        if files.is_empty() {
            let transaction = inputs
                .target
                .begin()
                .await
                .wrap_err("begin files completion")?;
            report.set_mappings(inputs.context, inputs.blob_mappings, file_mappings);
            if !report
                .completed_stages
                .iter()
                .any(|completed| completed == MigrationStage::Files.as_str())
            {
                report
                    .completed_stages
                    .push(MigrationStage::Files.as_str().to_string());
            }
            checkpoint::save_stage(
                &transaction,
                inputs.run_id,
                MigrationStage::Files.as_str(),
                inputs.context,
                report,
            )
            .await?;
            transaction
                .commit()
                .await
                .wrap_err("commit files completion")?;
            return Ok(());
        }

        let (associations, entities) =
            load_file_batch_data(inputs.source, inputs.source_data.include_deleted, &files).await?;
        let last_file_id = files.last().expect("non-empty file batch").id;
        let transaction = inputs.target.begin().await.wrap_err("begin files batch")?;
        let mappings = migrate_file_batch(
            &transaction,
            &files,
            &associations,
            &entities,
            inputs.blob_mappings,
            inputs.context,
            report,
        )
        .await?;
        checkpoint::save_object_mappings(&transaction, inputs.run_id, "file", &mappings).await?;
        processed_count += files.len() as i64;
        checkpoint::save_stage_cursor(
            &transaction,
            inputs.run_id,
            MigrationStage::Files.as_str(),
            last_file_id,
            processed_count,
        )
        .await?;
        checkpoint::save_progress(&transaction, inputs.run_id, inputs.context, report).await?;
        transaction.commit().await.wrap_err("commit files batch")?;
        file_mappings.extend(mappings);
        cursor_value = last_file_id;
    }
}

async fn load_file_batch_data(
    source: &DatabaseConnection,
    include_deleted: bool,
    files: &[cr::files::Model],
) -> Result<(HashMap<i64, Vec<i64>>, HashMap<i64, cr::entities::Model>)> {
    const QUERY_ID_BATCH_SIZE: usize = 500;

    let file_ids = files.iter().map(|file| file.id).collect::<Vec<_>>();
    let mut file_entities = Vec::new();
    for file_ids in file_ids.chunks(QUERY_ID_BATCH_SIZE) {
        file_entities.extend(
            cr::file_entities::Entity::find()
                .filter(cr::file_entities::Column::FileId.is_in(file_ids.iter().copied()))
                .all(source)
                .await?,
        );
    }
    let mut entity_ids = file_entities
        .iter()
        .map(|relation| relation.entity_id)
        .collect::<HashSet<_>>();
    entity_ids.extend(files.iter().filter_map(|file| file.primary_entity));
    let entity_ids = entity_ids.into_iter().collect::<Vec<_>>();
    let mut entities = HashMap::with_capacity(entity_ids.len());
    for entity_ids in entity_ids.chunks(QUERY_ID_BATCH_SIZE) {
        let mut query = cr::entities::Entity::find()
            .filter(cr::entities::Column::Id.is_in(entity_ids.iter().copied()))
            .filter(cr::entities::Column::Type.eq(0));
        if !include_deleted {
            query = query.filter(cr::entities::Column::DeletedAt.is_null());
        }
        for entity in query.all(source).await? {
            entities.insert(entity.id, entity);
        }
    }
    Ok((associations(files, &file_entities), entities))
}

struct BlobAssociationInfo {
    reference_counts: HashMap<i64, i64>,
    thumbnail_paths: HashMap<i64, String>,
}

async fn load_blob_association_info(
    source: &DatabaseConnection,
    blob_ids: &[i64],
) -> Result<BlobAssociationInfo> {
    if blob_ids.is_empty() {
        return Ok(BlobAssociationInfo {
            reference_counts: HashMap::new(),
            thumbnail_paths: HashMap::new(),
        });
    }
    let relations = cr::file_entities::Entity::find()
        .filter(cr::file_entities::Column::EntityId.is_in(blob_ids.iter().copied()))
        .all(source)
        .await?;
    let primary_files = cr::files::Entity::find()
        .filter(cr::files::Column::PrimaryEntity.is_in(blob_ids.iter().copied()))
        .all(source)
        .await?;
    let file_ids = relations
        .iter()
        .map(|relation| relation.file_id)
        .chain(primary_files.iter().map(|file| file.id))
        .collect::<HashSet<_>>();
    if file_ids.is_empty() {
        return Ok(BlobAssociationInfo {
            reference_counts: HashMap::new(),
            thumbnail_paths: HashMap::new(),
        });
    }
    let all_relations = cr::file_entities::Entity::find()
        .filter(cr::file_entities::Column::FileId.is_in(file_ids.iter().copied()))
        .all(source)
        .await?;
    let thumbnail_ids = all_relations
        .iter()
        .map(|relation| relation.entity_id)
        .collect::<HashSet<_>>();
    let thumbnails = cr::entities::Entity::find()
        .filter(cr::entities::Column::Id.is_in(thumbnail_ids.iter().copied()))
        .filter(cr::entities::Column::Type.eq(1))
        .all(source)
        .await?
        .into_iter()
        .map(|entity| (entity.id, entity.source))
        .collect::<HashMap<_, _>>();
    let relations_by_file =
        all_relations
            .into_iter()
            .fold(HashMap::<i64, Vec<i64>>::new(), |mut values, relation| {
                values
                    .entry(relation.file_id)
                    .or_default()
                    .push(relation.entity_id);
                values
            });
    let blob_id_set = blob_ids.iter().copied().collect::<HashSet<_>>();
    let mut file_blob_pairs = HashSet::new();
    let mut thumbnail_paths = HashMap::new();
    for (blob_id, file_id) in relations
        .into_iter()
        .map(|relation| (relation.entity_id, relation.file_id))
        .chain(
            primary_files
                .into_iter()
                .filter_map(|file| file.primary_entity.map(|entity_id| (entity_id, file.id))),
        )
    {
        if blob_id_set.contains(&blob_id) {
            file_blob_pairs.insert((file_id, blob_id));
        }
        if let Some(path) = relations_by_file
            .get(&file_id)
            .into_iter()
            .flatten()
            .find_map(|entity_id| thumbnails.get(entity_id))
        {
            thumbnail_paths
                .entry(blob_id)
                .or_insert_with(|| path.clone());
        }
    }
    let mut reference_counts = HashMap::new();
    for (_, blob_id) in file_blob_pairs {
        *reference_counts.entry(blob_id).or_insert(0) += 1;
    }
    Ok(BlobAssociationInfo {
        reference_counts,
        thumbnail_paths,
    })
}

fn validate_run_id(run_id: &str) -> Result<()> {
    let run_id = run_id.trim();
    if run_id.is_empty() || run_id.chars().count() > 128 || run_id.chars().any(char::is_control) {
        bail!("--run-id must contain 1-128 non-control characters");
    }
    Ok(())
}

fn hash_fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn source_fingerprint(source_url: &str, source: &SourceData) -> String {
    hash_fingerprint(&format!(
        "{source_url}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        source.users.len(),
        source.groups.len(),
        source.policies.len(),
        source.source_file_records,
        source.source_entities,
        source.source_file_entities,
        source.shares.len(),
        source.metadata.len(),
        source.direct_links.len(),
        source.tasks.len(),
    ))
}

fn plan_fingerprint(options: &MigrationOptions) -> String {
    hash_fingerprint(&format!(
        "{}|{}|{:?}|{}|{}|{}|{}|{}|{}|{}|{}",
        options.local_base_path,
        options
            .local_policy_roots
            .iter()
            .map(|(policy_id, path)| format!("{policy_id}={path}"))
            .collect::<Vec<_>>()
            .join("|"),
        options.storage_mode,
        options
            .target_local_base_path
            .as_deref()
            .unwrap_or_default(),
        options
            .target_local_policy_roots
            .iter()
            .map(|(policy_id, path)| format!("{policy_id}={path}"))
            .collect::<Vec<_>>()
            .join("|"),
        options.verify_local_storage,
        options.include_deleted,
        options.allow_non_empty_target,
        options.skip_unsupported_policies,
        hash_fingerprint(&options.default_password),
        options
            .direct_link_secret
            .as_deref()
            .map(hash_fingerprint)
            .unwrap_or_default(),
    ))
}

fn local_policy_root(options: &MigrationOptions, source_policy_id: i64) -> &str {
    options
        .local_policy_roots
        .get(&source_policy_id)
        .map(String::as_str)
        .unwrap_or(&options.local_base_path)
}

fn target_local_policy_root(options: &MigrationOptions, source_policy_id: i64) -> Result<&str> {
    if options.storage_mode == StorageMode::ReuseSourceStorage {
        return Ok(local_policy_root(options, source_policy_id));
    }
    options
        .target_local_policy_roots
        .get(&source_policy_id)
        .map(String::as_str)
        .or(options.target_local_base_path.as_deref())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "--storage-mode copy-local requires --target-local-base-path or --target-local-policy-root for Cloudreve policy {source_policy_id}"
            )
        })
}

fn local_storage_path(root: &str, storage_path: &str) -> std::path::PathBuf {
    let storage_path = std::path::Path::new(storage_path);
    if storage_path.is_absolute() {
        storage_path.to_path_buf()
    } else {
        std::path::Path::new(root).join(storage_path)
    }
}

fn validate_local_policy_roots(source: &SourceData, options: &MigrationOptions) -> Result<()> {
    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    for source_policy_id in options
        .local_policy_roots
        .keys()
        .chain(options.target_local_policy_roots.keys())
    {
        let Some(policy) = policies.get(source_policy_id) else {
            bail!(
                "local policy root references Cloudreve policy {source_policy_id}, which was not found"
            );
        };
        if policy.r#type != "local" {
            bail!(
                "local policy root references Cloudreve policy {source_policy_id}, which is not a local policy"
            );
        }
    }
    Ok(())
}

fn verify_target_local_storage_roots(
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    for policy in source.policies.iter().filter(|policy| {
        policy.r#type == "local"
            && map_driver_type(&policy.r#type).is_some()
            && !source_settings(&policy.settings)
                .get("encryption")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }) {
        let source_root = local_policy_root(options, policy.id);
        let target_root = target_local_policy_root(options, policy.id)?;
        let target_metadata = std::fs::metadata(target_root).wrap_err_with(|| {
            format!(
                "read target local storage root for Cloudreve policy {}: {target_root}",
                policy.id
            )
        })?;
        if !target_metadata.is_dir() {
            bail!(
                "target local storage root for Cloudreve policy {} is not a directory: {target_root}",
                policy.id
            );
        }
        if same_local_directory(source_root, target_root)? {
            bail!(
                "--storage-mode copy-local source and target roots are the same for Cloudreve policy {}: {source_root}",
                policy.id
            );
        }
    }
    Ok(())
}

fn same_local_directory(left: &str, right: &str) -> Result<bool> {
    let left = std::fs::canonicalize(left)
        .wrap_err_with(|| format!("canonicalize local storage root: {left}"))?;
    let right = std::fs::canonicalize(right)
        .wrap_err_with(|| format!("canonicalize target local storage root: {right}"))?;
    Ok(left == right)
}

#[derive(Debug, Clone)]
struct CopiedLocalObject {
    sha256: String,
    storage_path: String,
}

#[derive(Debug, Default)]
struct CopiedLocalBatch {
    objects: HashMap<i64, CopiedLocalObject>,
    created_paths: Vec<PathBuf>,
}

impl CopiedLocalBatch {
    fn compensate(&self) -> Result<()> {
        for path in self.created_paths.iter().rev() {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).wrap_err_with(|| {
                        format!(
                            "remove copied local object after database rollback: {}",
                            path.display()
                        )
                    });
                }
            }
        }
        Ok(())
    }
}

fn copy_local_blob_batch(
    entities: &[cr::entities::Model],
    source: &SourceData,
    options: &MigrationOptions,
    context: &MigrationContext,
    run_id: &str,
) -> Result<CopiedLocalBatch> {
    if options.storage_mode != StorageMode::CopyLocal {
        return Ok(CopiedLocalBatch::default());
    }

    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    let mut batch = CopiedLocalBatch::default();
    for entity in entities {
        if !context
            .policies
            .contains_key(&entity.storage_policy_entities)
        {
            continue;
        }
        let Some(policy) = policies.get(&entity.storage_policy_entities) else {
            continue;
        };
        if policy.r#type != "local" {
            continue;
        }

        let source_path = local_storage_path(local_policy_root(options, policy.id), &entity.source);
        let target_path = target_local_storage_path(
            target_local_policy_root(options, policy.id)?,
            &entity.source,
            entity.id,
        )?;
        match copy_local_object(&source_path, &target_path, entity.size, run_id, entity.id) {
            Ok((sha256, created)) => {
                if created {
                    batch.created_paths.push(target_path);
                }
                batch.objects.insert(
                    entity.id,
                    CopiedLocalObject {
                        sha256,
                        storage_path: entity.source.clone(),
                    },
                );
            }
            Err(error) => {
                batch.compensate()?;
                return Err(error);
            }
        }
    }
    Ok(batch)
}

fn target_local_storage_path(root: &str, storage_path: &str, entity_id: i64) -> Result<PathBuf> {
    let relative = Path::new(storage_path);
    if relative.is_absolute() {
        bail!(
            "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path is absolute: {storage_path}"
        );
    }
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(component) => normalized.push(component),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                bail!(
                    "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path escapes the configured root: {storage_path}"
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!(
            "--storage-mode copy-local cannot copy Cloudreve entity {entity_id} because its storage path is empty"
        );
    }
    Ok(Path::new(root).join(normalized))
}

fn copy_local_object(
    source_path: &Path,
    target_path: &Path,
    expected_size: i64,
    run_id: &str,
    entity_id: i64,
) -> Result<(String, bool)> {
    const BUFFER_SIZE: usize = 1024 * 1024;

    let expected_size = u64::try_from(expected_size).map_err(|_| {
        color_eyre::eyre::eyre!(
            "Cloudreve local entity {entity_id} has negative size {expected_size}"
        )
    })?;
    let source_metadata = std::fs::metadata(source_path).wrap_err_with(|| {
        format!(
            "read Cloudreve local entity {entity_id} before copy: {}",
            source_path.display()
        )
    })?;
    if !source_metadata.is_file() || source_metadata.len() != expected_size {
        bail!(
            "Cloudreve local entity {entity_id} changed or is not a regular file before copy: {}",
            source_path.display()
        );
    }
    if target_path.exists() {
        let source_hash = sha256_file(source_path)?;
        let target_metadata = std::fs::metadata(target_path).wrap_err_with(|| {
            format!(
                "read existing copied local entity {entity_id}: {}",
                target_path.display()
            )
        })?;
        if target_metadata.is_file()
            && target_metadata.len() == expected_size
            && sha256_file(target_path)? == source_hash
        {
            return Ok((source_hash, false));
        }
        bail!(
            "target local object already exists but differs from Cloudreve entity {entity_id}: {}",
            target_path.display()
        );
    }

    let parent = target_path.parent().ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "target local object for Cloudreve entity {entity_id} has no parent directory: {}",
            target_path.display()
        )
    })?;
    std::fs::create_dir_all(parent).wrap_err_with(|| {
        format!(
            "create destination directory for Cloudreve entity {entity_id}: {}",
            parent.display()
        )
    })?;
    let temporary_path = temporary_copy_path(parent, run_id, entity_id);
    let temporary_size = match std::fs::metadata(&temporary_path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => bail!(
            "copy checkpoint for Cloudreve entity {entity_id} is not a regular file: {}",
            temporary_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("read copy checkpoint: {}", temporary_path.display()));
        }
    };
    if temporary_size > expected_size {
        bail!(
            "copy checkpoint for Cloudreve entity {entity_id} is larger than the source object: {}",
            temporary_path.display()
        );
    }

    let mut source = std::fs::File::open(source_path).wrap_err_with(|| {
        format!(
            "open Cloudreve local entity {entity_id}: {}",
            source_path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut source_buffer = vec![0_u8; BUFFER_SIZE];
    if temporary_size > 0 {
        let mut checkpoint = std::fs::File::open(&temporary_path).wrap_err_with(|| {
            format!(
                "open copy checkpoint for Cloudreve entity {entity_id}: {}",
                temporary_path.display()
            )
        })?;
        let mut checkpoint_buffer = vec![0_u8; BUFFER_SIZE];
        let mut remaining = temporary_size;
        while remaining > 0 {
            let read_len =
                usize::try_from(remaining.min(BUFFER_SIZE as u64)).expect("bounded buffer size");
            source
                .read_exact(&mut source_buffer[..read_len])
                .wrap_err_with(|| format!("read source prefix for Cloudreve entity {entity_id}"))?;
            checkpoint
                .read_exact(&mut checkpoint_buffer[..read_len])
                .wrap_err_with(|| {
                    format!("read copy checkpoint for Cloudreve entity {entity_id}")
                })?;
            if source_buffer[..read_len] != checkpoint_buffer[..read_len] {
                bail!(
                    "copy checkpoint does not match Cloudreve entity {entity_id}; remove only this generated checkpoint and rerun: {}",
                    temporary_path.display()
                );
            }
            hasher.update(&source_buffer[..read_len]);
            remaining -= read_len as u64;
        }
    }

    let mut destination = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temporary_path)
        .wrap_err_with(|| {
            format!(
                "open copy checkpoint for Cloudreve entity {entity_id}: {}",
                temporary_path.display()
            )
        })?;
    let mut copied_size = temporary_size;
    loop {
        let read = source.read(&mut source_buffer).wrap_err_with(|| {
            format!(
                "read Cloudreve local entity {entity_id}: {}",
                source_path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        destination
            .write_all(&source_buffer[..read])
            .wrap_err_with(|| {
                format!(
                    "write copied local entity {entity_id}: {}",
                    temporary_path.display()
                )
            })?;
        hasher.update(&source_buffer[..read]);
        copied_size += read as u64;
    }
    if copied_size != expected_size {
        bail!(
            "Cloudreve local entity {entity_id} changed while copying: expected {expected_size} bytes, copied {copied_size} bytes"
        );
    }
    destination.sync_all().wrap_err_with(|| {
        format!(
            "sync copied local entity {entity_id}: {}",
            temporary_path.display()
        )
    })?;
    std::fs::rename(&temporary_path, target_path).wrap_err_with(|| {
        format!(
            "atomically finalize copied local entity {entity_id}: {} -> {}",
            temporary_path.display(),
            target_path.display()
        )
    })?;
    Ok((format!("{:x}", hasher.finalize()), true))
}

fn temporary_copy_path(parent: &Path, run_id: &str, entity_id: i64) -> PathBuf {
    parent.join(format!(
        ".aster-migration-{}-{entity_id}.part",
        hash_fingerprint(run_id)
    ))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .wrap_err_with(|| format!("open file for SHA-256: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .wrap_err_with(|| format!("read file for SHA-256: {}", path.display()))?;
        if read == 0 {
            return Ok(format!("{:x}", hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

fn verify_local_storage_roots(source: &SourceData, options: &MigrationOptions) -> Result<()> {
    for policy in source.policies.iter().filter(|policy| {
        policy.r#type == "local"
            && map_driver_type(&policy.r#type).is_some()
            && !source_settings(&policy.settings)
                .get("encryption")
                .and_then(Value::as_bool)
                .unwrap_or(false)
    }) {
        let root = local_policy_root(options, policy.id);
        let metadata = std::fs::metadata(root).wrap_err_with(|| {
            format!(
                "read local storage root for Cloudreve policy {}: {root}",
                policy.id
            )
        })?;
        if !metadata.is_dir() {
            bail!(
                "local storage root for Cloudreve policy {} is not a directory: {root}",
                policy.id
            );
        }
    }
    Ok(())
}

async fn verify_all_local_source_objects(
    source_db: &DatabaseConnection,
    source: &SourceData,
    options: &MigrationOptions,
) -> Result<()> {
    const VERIFY_BATCH_SIZE: u64 = 500;

    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    let mut cursor_value = 0;
    loop {
        let mut query = cr::entities::Entity::find()
            .filter(cr::entities::Column::Type.eq(0))
            .filter(cr::entities::Column::Id.gt(cursor_value))
            .order_by_asc(cr::entities::Column::Id)
            .limit(VERIFY_BATCH_SIZE);
        if !source.include_deleted {
            query = query.filter(cr::entities::Column::DeletedAt.is_null());
        }
        let entities = query.all(source_db).await?;
        let Some(last_entity) = entities.last() else {
            return Ok(());
        };
        for entity in &entities {
            let Some(policy) = policies.get(&entity.storage_policy_entities) else {
                continue;
            };
            if policy.r#type == "local"
                && map_driver_type(&policy.r#type).is_some()
                && !source_settings(&policy.settings)
                    .get("encryption")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            {
                verify_local_entity(entity, policy, options)?;
            }
        }
        cursor_value = last_entity.id;
    }
}

fn verify_local_blob_batch(
    entities: &[cr::entities::Model],
    source: &SourceData,
    options: &MigrationOptions,
    context: &MigrationContext,
) -> Result<()> {
    let policies = source
        .policies
        .iter()
        .map(|policy| (policy.id, policy))
        .collect::<HashMap<_, _>>();
    for entity in entities {
        if !context
            .policies
            .contains_key(&entity.storage_policy_entities)
        {
            continue;
        }
        let Some(policy) = policies.get(&entity.storage_policy_entities) else {
            continue;
        };
        if policy.r#type != "local" {
            continue;
        }
        verify_local_entity(entity, policy, options)?;
    }
    Ok(())
}

fn verify_local_entity(
    entity: &cr::entities::Model,
    policy: &cr::storage_policies::Model,
    options: &MigrationOptions,
) -> Result<()> {
    let root = local_policy_root(options, policy.id);
    let path = local_storage_path(root, &entity.source);
    let metadata = std::fs::metadata(&path).wrap_err_with(|| {
        format!(
            "read Cloudreve local entity {} at {}",
            entity.id,
            path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "Cloudreve local entity {} is not a regular file: {}",
            entity.id,
            path.display()
        );
    }
    std::fs::File::open(&path).wrap_err_with(|| {
        format!(
            "open Cloudreve local entity {} at {}",
            entity.id,
            path.display()
        )
    })?;
    let expected_size = u64::try_from(entity.size).map_err(|_| {
        color_eyre::eyre::eyre!(
            "Cloudreve local entity {} has negative size {}",
            entity.id,
            entity.size
        )
    })?;
    if metadata.len() != expected_size {
        bail!(
            "Cloudreve local entity {} size mismatch at {}: database={}, filesystem={}",
            entity.id,
            path.display(),
            expected_size,
            metadata.len()
        );
    }
    Ok(())
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
        (
            "storage_policies",
            ad::storage_policies::Entity::find().count(db).await?,
        ),
        (
            "storage_policy_groups",
            ad::storage_policy_groups::Entity::find().count(db).await?,
        ),
        ("users", ad::users::Entity::find().count(db).await?),
        (
            "user_profiles",
            ad::user_profiles::Entity::find().count(db).await?,
        ),
        ("folders", ad::folders::Entity::find().count(db).await?),
        ("files", ad::files::Entity::find().count(db).await?),
        (
            "file_blobs",
            ad::file_blobs::Entity::find().count(db).await?,
        ),
        (
            "file_versions",
            ad::file_versions::Entity::find().count(db).await?,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct MigrationContext {
    policies: HashMap<i64, i64>,
    policy_groups: HashMap<i64, i64>,
    users: HashMap<i64, i64>,
    usernames: HashMap<i64, String>,
    folders: HashMap<i64, i64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
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
    folders: Vec<cr::files::Model>,
    source_file_records: u64,
    source_files: u64,
    symbolic_files: u64,
    source_entities: u64,
    source_file_entities: u64,
    include_deleted: bool,
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
        let folders = cr::files::Entity::find()
            .filter(cr::files::Column::Type.eq(1))
            .all(db)
            .await?;
        let source_file_records = cr::files::Entity::find().count(db).await?;
        let source_files = cr::files::Entity::find()
            .filter(cr::files::Column::Type.eq(0))
            .count(db)
            .await?;
        let symbolic_files = cr::files::Entity::find()
            .filter(cr::files::Column::Type.eq(0))
            .filter(cr::files::Column::IsSymbolic.eq(true))
            .count(db)
            .await?;
        let entity_query = if include_deleted {
            cr::entities::Entity::find()
        } else {
            cr::entities::Entity::find().filter(cr::entities::Column::DeletedAt.is_null())
        };
        let source_entities = entity_query.count(db).await?;
        let source_file_entities = cr::file_entities::Entity::find().count(db).await?;
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
            folders,
            source_file_records,
            source_files,
            symbolic_files,
            source_entities,
            source_file_entities,
            include_deleted,
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
            source_folders: self.folders.len() as u64,
            source_files: self.source_files,
            source_entities: self.source_entities,
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
        let symbolic = self.symbolic_files;
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

mod checkpoint;
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
            local_policy_roots: std::collections::BTreeMap::new(),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: None,
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
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

    #[tokio::test]
    async fn reuses_and_verifies_local_storage_per_policy_root() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-local-reuse-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-local-reuse-{suffix}.db"));
        let storage_root = std::env::temp_dir().join(format!("cloudreve-local-storage-{suffix}"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let source_policy_id = cr::storage_policies::Entity::find()
            .one(&source)
            .await?
            .expect("seeded storage policy")
            .id;
        source.close().await?;
        std::fs::create_dir_all(storage_root.join("uploads"))?;
        std::fs::write(storage_root.join("uploads/object.bin"), vec![0_u8; 128])?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "unused-local-root".to_string(),
            local_policy_roots: std::collections::BTreeMap::from([(
                source_policy_id,
                storage_root.to_string_lossy().to_string(),
            )]),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: true,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: None,
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        })
        .await?;
        assert!(report.validation.passed);

        let target = Database::connect(&target_url).await?;
        let policy = ad::storage_policies::Entity::find()
            .one(&target)
            .await?
            .expect("migrated storage policy");
        assert_eq!(policy.base_path, storage_root.to_string_lossy());
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_dir_all(storage_root);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_local_storage_size_mismatch() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path =
            std::env::temp_dir().join(format!("cloudreve-local-mismatch-{suffix}.db"));
        let target_path =
            std::env::temp_dir().join(format!("asterdrive-local-mismatch-{suffix}.db"));
        let storage_root =
            std::env::temp_dir().join(format!("cloudreve-local-mismatch-storage-{suffix}"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let source_policy_id = cr::storage_policies::Entity::find()
            .one(&source)
            .await?
            .expect("seeded storage policy")
            .id;
        source.close().await?;
        std::fs::create_dir_all(storage_root.join("uploads"))?;
        std::fs::write(storage_root.join("uploads/object.bin"), vec![0_u8; 127])?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let error = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "unused-local-root".to_string(),
            local_policy_roots: std::collections::BTreeMap::from([(
                source_policy_id,
                storage_root.to_string_lossy().to_string(),
            )]),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: true,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: true,
            run_id: None,
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        })
        .await
        .unwrap_err();
        assert!(format!("{error:?}").contains("size mismatch"));

        let target = Database::connect(&target_url).await?;
        assert_eq!(
            ad::storage_policies::Entity::find().count(&target).await?,
            0
        );
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_dir_all(storage_root);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_unknown_local_policy_root() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-local-policy-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-local-policy-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        source.close().await?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let error = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "unused-local-root".to_string(),
            local_policy_roots: std::collections::BTreeMap::from([(999, "C:/missing".to_string())]),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: true,
            run_id: None,
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("policy 999"));

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    #[tokio::test]
    async fn resumes_from_last_completed_stage() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let run_id = format!("resume-test-{suffix}");
        let source_path = std::env::temp_dir().join(format!("cloudreve-resume-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-resume-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        source.close().await?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target
            .execute_unprepared(
                "CREATE TRIGGER fail_folder_insert BEFORE INSERT ON folders \
                 BEGIN SELECT RAISE(ABORT, 'forced folder stage failure'); END",
            )
            .await?;
        target.close().await?;

        let options = MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "C:/cloudreve".to_string(),
            local_policy_roots: std::collections::BTreeMap::new(),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: Some(run_id.clone()),
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        };

        let error = migrate(options.clone()).await.unwrap_err();
        assert!(error.to_string().contains(&run_id));

        let target = Database::connect(&target_url).await?;
        assert_eq!(
            ad::storage_policies::Entity::find().count(&target).await?,
            1
        );
        assert_eq!(ad::users::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::folders::Entity::find().count(&target).await?, 0);
        let failed_checkpoint = checkpoint::Entity::find_by_id(run_id.clone())
            .one(&target)
            .await?
            .expect("failed migration checkpoint");
        assert_eq!(failed_checkpoint.status, "failed");
        assert_eq!(
            failed_checkpoint.last_completed_stage.as_deref(),
            Some("users")
        );
        target
            .execute_unprepared("DROP TRIGGER fail_folder_insert")
            .await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            resume: true,
            ..options
        })
        .await?;
        assert!(report.resumed);
        assert_eq!(report.run_id.as_deref(), Some(run_id.as_str()));
        assert!(report.validation.passed);
        assert_eq!(report.migrated_users, 1);
        assert_eq!(report.migrated_folders, 1);

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::users::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::folders::Entity::find().count(&target).await?, 1);
        assert_eq!(ad::files::Entity::find().count(&target).await?, 1);
        let completed_checkpoint = checkpoint::Entity::find_by_id(run_id)
            .one(&target)
            .await?
            .expect("completed migration checkpoint");
        assert_eq!(completed_checkpoint.status, "completed");
        assert_eq!(
            completed_checkpoint.last_completed_stage.as_deref(),
            Some("tasks")
        );
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    #[tokio::test]
    async fn resumes_blobs_from_last_committed_batch() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let run_id = format!("blob-resume-test-{suffix}");
        let source_path = std::env::temp_dir().join(format!("cloudreve-blob-resume-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-blob-resume-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let extra_blob_ids = seed_extra_blob_entities(&source, 3).await?;
        source.close().await?;

        let failing_blob_id = extra_blob_ids[1];
        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target
            .execute_unprepared(&format!(
                "CREATE TRIGGER fail_blob_batch BEFORE INSERT ON file_blobs \
                 WHEN NEW.hash = '{}' \
                 BEGIN SELECT RAISE(ABORT, 'forced blob batch failure'); END",
                opaque_blob_key(failing_blob_id)
            ))
            .await?;
        target.close().await?;

        let options = MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "C:/cloudreve".to_string(),
            local_policy_roots: std::collections::BTreeMap::new(),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: Some(run_id.clone()),
            resume: false,
            blob_batch_size: 2,
            file_batch_size: 500,
        };

        let error = migrate(options.clone()).await.unwrap_err();
        assert!(error.to_string().contains("blobs"));

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::file_blobs::Entity::find().count(&target).await?, 2);
        let cursor = checkpoint::load_stage_cursor(&target, &run_id, "blobs")
            .await?
            .expect("committed blob cursor");
        assert_eq!(cursor.cursor_value, extra_blob_ids[0]);
        assert_eq!(cursor.processed_count, 2);
        assert_eq!(
            checkpoint::object_map::Entity::find()
                .filter(checkpoint::object_map::Column::RunId.eq(&run_id))
                .filter(checkpoint::object_map::Column::ObjectType.eq("blob"))
                .count(&target)
                .await?,
            2
        );
        let failed_checkpoint = checkpoint::Entity::find_by_id(run_id.clone())
            .one(&target)
            .await?
            .expect("failed blob migration checkpoint");
        assert_eq!(failed_checkpoint.status, "failed");
        assert_eq!(
            failed_checkpoint.last_completed_stage.as_deref(),
            Some("folders")
        );
        let failed_report: MigrationReport = serde_json::from_value(failed_checkpoint.report_json)?;
        assert_eq!(failed_report.migrated_blobs, 2);
        target
            .execute_unprepared("DROP TRIGGER fail_blob_batch")
            .await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            resume: true,
            ..options
        })
        .await?;
        assert!(report.resumed);
        assert_eq!(report.migrated_blobs, 4);
        assert_eq!(report.mappings.blobs.len(), 4);
        assert!(report.validation.passed);

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::file_blobs::Entity::find().count(&target).await?, 4);
        assert_eq!(
            checkpoint::object_map::Entity::find()
                .filter(checkpoint::object_map::Column::RunId.eq(&run_id))
                .filter(checkpoint::object_map::Column::ObjectType.eq("blob"))
                .count(&target)
                .await?,
            4
        );
        let completed_cursor = checkpoint::load_stage_cursor(&target, &run_id, "blobs")
            .await?
            .expect("completed blob cursor");
        assert_eq!(completed_cursor.cursor_value, extra_blob_ids[2]);
        assert_eq!(completed_cursor.processed_count, 4);
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    #[tokio::test]
    async fn resumes_files_from_last_committed_batch() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let run_id = format!("file-resume-test-{suffix}");
        let source_path = std::env::temp_dir().join(format!("cloudreve-file-resume-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-file-resume-{suffix}.db"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let extra_blob_ids = seed_extra_blob_entities(&source, 3).await?;
        let extra_file_ids = seed_extra_files(&source, &extra_blob_ids).await?;
        source.close().await?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target
            .execute_unprepared(
                "CREATE TRIGGER fail_file_batch BEFORE INSERT ON files \
                 WHEN NEW.name = 'extra-1.txt' \
                 BEGIN SELECT RAISE(ABORT, 'forced file batch failure'); END",
            )
            .await?;
        target.close().await?;

        let options = MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "C:/cloudreve".to_string(),
            local_policy_roots: std::collections::BTreeMap::new(),
            storage_mode: StorageMode::ReuseSourceStorage,
            target_local_base_path: None,
            target_local_policy_roots: std::collections::BTreeMap::new(),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: Some(run_id.clone()),
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 2,
        };

        let error = migrate(options.clone()).await.unwrap_err();
        assert!(error.to_string().contains("files"));

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::files::Entity::find().count(&target).await?, 2);
        assert_eq!(ad::file_versions::Entity::find().count(&target).await?, 1);
        let cursor = checkpoint::load_stage_cursor(&target, &run_id, "files")
            .await?
            .expect("committed file cursor");
        assert_eq!(cursor.cursor_value, extra_file_ids[0]);
        assert_eq!(cursor.processed_count, 2);
        assert_eq!(
            checkpoint::object_map::Entity::find()
                .filter(checkpoint::object_map::Column::RunId.eq(&run_id))
                .filter(checkpoint::object_map::Column::ObjectType.eq("file"))
                .count(&target)
                .await?,
            2
        );
        let failed_checkpoint = checkpoint::Entity::find_by_id(run_id.clone())
            .one(&target)
            .await?
            .expect("failed file migration checkpoint");
        assert_eq!(failed_checkpoint.status, "failed");
        assert_eq!(
            failed_checkpoint.last_completed_stage.as_deref(),
            Some("blobs")
        );
        let failed_report: MigrationReport = serde_json::from_value(failed_checkpoint.report_json)?;
        assert_eq!(failed_report.migrated_files, 2);
        assert_eq!(failed_report.migrated_versions, 1);
        target
            .execute_unprepared("DROP TRIGGER fail_file_batch")
            .await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            resume: true,
            ..options
        })
        .await?;
        assert!(report.resumed);
        assert_eq!(report.migrated_files, 4);
        assert_eq!(report.migrated_versions, 1);
        assert_eq!(report.mappings.files.len(), 4);
        assert!(report.validation.passed);

        let target = Database::connect(&target_url).await?;
        assert_eq!(ad::files::Entity::find().count(&target).await?, 4);
        assert_eq!(ad::file_versions::Entity::find().count(&target).await?, 1);
        assert_eq!(
            checkpoint::object_map::Entity::find()
                .filter(checkpoint::object_map::Column::RunId.eq(&run_id))
                .filter(checkpoint::object_map::Column::ObjectType.eq("file"))
                .count(&target)
                .await?,
            4
        );
        let completed_cursor = checkpoint::load_stage_cursor(&target, &run_id, "files")
            .await?
            .expect("completed file cursor");
        assert_eq!(completed_cursor.cursor_value, extra_file_ids[2]);
        assert_eq!(completed_cursor.processed_count, 4);
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        Ok(())
    }

    #[test]
    fn resumes_local_copy_from_matching_temporary_file() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let root = std::env::temp_dir().join(format!("asterdrive-copy-resume-{suffix}"));
        let source_path = root.join("source.bin");
        let target_path = root.join("target/object.bin");
        let content = b"a local object that resumes from a generated checkpoint";
        std::fs::create_dir_all(&root)?;
        std::fs::write(&source_path, content)?;
        std::fs::create_dir_all(target_path.parent().expect("target parent"))?;
        let temporary_path = temporary_copy_path(
            target_path.parent().expect("target parent"),
            "local-copy-resume",
            42,
        );
        std::fs::write(&temporary_path, &content[..17])?;

        let (sha256, created) = copy_local_object(
            &source_path,
            &target_path,
            content.len() as i64,
            "local-copy-resume",
            42,
        )?;

        assert!(created);
        assert_eq!(sha256, sha256_file(&source_path)?);
        assert_eq!(std::fs::read(&target_path)?, content);
        assert!(!temporary_path.exists());

        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[tokio::test]
    async fn copies_local_objects_to_target_root_and_uses_content_hashes() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-copy-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-copy-{suffix}.db"));
        let source_root = std::env::temp_dir().join(format!("cloudreve-copy-source-{suffix}"));
        let target_root = std::env::temp_dir().join(format!("asterdrive-copy-target-{suffix}"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let source_policy_id = cr::storage_policies::Entity::find()
            .one(&source)
            .await?
            .expect("seeded storage policy")
            .id;
        source.close().await?;
        let content = vec![0x5a_u8; 128];
        std::fs::create_dir_all(source_root.join("uploads"))?;
        std::fs::create_dir_all(&target_root)?;
        std::fs::write(source_root.join("uploads/object.bin"), &content)?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target.close().await?;

        let report = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "unused-source-root".to_string(),
            local_policy_roots: BTreeMap::from([(
                source_policy_id,
                source_root.to_string_lossy().to_string(),
            )]),
            storage_mode: StorageMode::CopyLocal,
            target_local_base_path: None,
            target_local_policy_roots: BTreeMap::from([(
                source_policy_id,
                target_root.to_string_lossy().to_string(),
            )]),
            verify_local_storage: true,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: Some(format!("local-copy-{suffix}")),
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        })
        .await?;
        assert!(report.validation.passed);
        assert_eq!(
            std::fs::read(target_root.join("uploads/object.bin"))?,
            content
        );

        let target = Database::connect(&target_url).await?;
        let policy = ad::storage_policies::Entity::find()
            .one(&target)
            .await?
            .expect("copied local policy");
        assert_eq!(policy.base_path, target_root.to_string_lossy());
        let blob = ad::file_blobs::Entity::find()
            .one(&target)
            .await?
            .expect("copied blob");
        assert_eq!(blob.storage_path, "uploads/object.bin");
        assert_eq!(
            blob.hash,
            sha256_file(&source_root.join("uploads/object.bin"))?
        );
        target.close().await?;

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_dir_all(source_root);
        let _ = std::fs::remove_dir_all(target_root);
        Ok(())
    }

    #[tokio::test]
    async fn compensates_copied_local_objects_when_blob_database_write_fails() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let source_path = std::env::temp_dir().join(format!("cloudreve-copy-fail-{suffix}.db"));
        let target_path = std::env::temp_dir().join(format!("asterdrive-copy-fail-{suffix}.db"));
        let source_root = std::env::temp_dir().join(format!("cloudreve-copy-fail-source-{suffix}"));
        let target_root =
            std::env::temp_dir().join(format!("asterdrive-copy-fail-target-{suffix}"));
        let source_url = sqlite_url(&source_path);
        let target_url = sqlite_url(&target_path);

        let source = Database::connect(&source_url).await?;
        create_source_schema(&source).await?;
        seed_source(&source).await?;
        let source_policy_id = cr::storage_policies::Entity::find()
            .one(&source)
            .await?
            .expect("seeded storage policy")
            .id;
        source.close().await?;
        std::fs::create_dir_all(source_root.join("uploads"))?;
        std::fs::create_dir_all(&target_root)?;
        std::fs::write(source_root.join("uploads/object.bin"), vec![0x4d_u8; 128])?;
        let expected_hash = sha256_file(&source_root.join("uploads/object.bin"))?;

        let target = Database::connect(&target_url).await?;
        create_target_schema(&target).await?;
        target
            .execute_unprepared(&format!(
                "CREATE TRIGGER fail_copied_blob BEFORE INSERT ON file_blobs
                 WHEN NEW.hash = '{expected_hash}'
                 BEGIN SELECT RAISE(ABORT, 'forced copied blob failure'); END"
            ))
            .await?;
        target.close().await?;

        let error = migrate(MigrationOptions {
            source_url: source_url.clone(),
            target_url: target_url.clone(),
            default_password: "temporary-password".to_string(),
            local_base_path: "unused-source-root".to_string(),
            local_policy_roots: BTreeMap::from([(
                source_policy_id,
                source_root.to_string_lossy().to_string(),
            )]),
            storage_mode: StorageMode::CopyLocal,
            target_local_base_path: None,
            target_local_policy_roots: BTreeMap::from([(
                source_policy_id,
                target_root.to_string_lossy().to_string(),
            )]),
            verify_local_storage: false,
            direct_link_secret: Some("test-direct-link-secret".to_string()),
            include_deleted: false,
            allow_non_empty_target: false,
            skip_unsupported_policies: false,
            dry_run: false,
            run_id: Some(format!("local-copy-failure-{suffix}")),
            resume: false,
            blob_batch_size: 500,
            file_batch_size: 500,
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("blobs"));
        assert!(!target_root.join("uploads/object.bin").exists());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_dir_all(source_root);
        let _ = std::fs::remove_dir_all(target_root);
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

    async fn seed_extra_blob_entities(db: &DatabaseConnection, count: usize) -> Result<Vec<i64>> {
        let now = chrono::Utc::now().fixed_offset();
        let policy_id = cr::storage_policies::Entity::find()
            .one(db)
            .await?
            .expect("seeded storage policy")
            .id;
        let user_id = cr::users::Entity::find()
            .one(db)
            .await?
            .expect("seeded user")
            .id;
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let entity = cr::entities::ActiveModel {
                created_at: Set(now),
                updated_at: Set(now),
                deleted_at: Set(None),
                r#type: Set(0),
                source: Set(format!("uploads/extra-{index}.bin")),
                size: Set(256 + index as i64),
                reference_count: Set(1),
                upload_session_id: Set(None),
                recycle_options: Set(None),
                storage_policy_entities: Set(policy_id),
                created_by: Set(Some(user_id)),
                ..Default::default()
            }
            .insert(db)
            .await?;
            ids.push(entity.id);
        }
        Ok(ids)
    }

    async fn seed_extra_files(db: &DatabaseConnection, entity_ids: &[i64]) -> Result<Vec<i64>> {
        let now = chrono::Utc::now().fixed_offset();
        let policy_id = cr::storage_policies::Entity::find()
            .one(db)
            .await?
            .expect("seeded storage policy")
            .id;
        let user_id = cr::users::Entity::find()
            .one(db)
            .await?
            .expect("seeded user")
            .id;
        let folder_id = cr::files::Entity::find()
            .filter(cr::files::Column::Type.eq(1))
            .one(db)
            .await?
            .expect("seeded folder")
            .id;
        let mut ids = Vec::with_capacity(entity_ids.len());
        for (index, entity_id) in entity_ids.iter().copied().enumerate() {
            let file = cr::files::ActiveModel {
                created_at: Set(now),
                updated_at: Set(now),
                r#type: Set(0),
                name: Set(format!("extra-{index}.txt")),
                size: Set(256 + index as i64),
                primary_entity: Set(Some(entity_id)),
                is_symbolic: Set(false),
                props: Set(None),
                file_children: Set(Some(folder_id)),
                storage_policy_files: Set(Some(policy_id)),
                owner_id: Set(user_id),
                ..Default::default()
            }
            .insert(db)
            .await?;
            cr::file_entities::ActiveModel {
                file_id: Set(file.id),
                entity_id: Set(entity_id),
            }
            .insert(db)
            .await?;
            ids.push(file.id);
        }
        if entity_ids.len() >= 2 {
            cr::file_entities::ActiveModel {
                file_id: Set(ids[0]),
                entity_id: Set(entity_ids[1]),
            }
            .insert(db)
            .await?;
        }
        Ok(ids)
    }
}
