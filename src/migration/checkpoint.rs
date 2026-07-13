use color_eyre::eyre::{Result, WrapErr, bail};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Schema, Set, Unchanged};

use super::{MigrationContext, MigrationReport, TargetCounts};

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "aster_external_migration_runs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub source_fingerprint: String,
    pub target_fingerprint: String,
    pub plan_fingerprint: String,
    pub status: String,
    pub last_completed_stage: Option<String>,
    #[sea_orm(column_type = "JsonBinary")]
    pub context_json: Json,
    #[sea_orm(column_type = "JsonBinary")]
    pub report_json: Json,
    #[sea_orm(column_type = "JsonBinary")]
    pub baseline_json: Json,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_error: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}

pub(super) struct LoadedCheckpoint {
    pub status: String,
    pub last_completed_stage: Option<String>,
    pub context: MigrationContext,
    pub report: MigrationReport,
    pub baseline: TargetCounts,
}

pub(super) struct NewCheckpoint<'a> {
    pub run_id: &'a str,
    pub source_fingerprint: &'a str,
    pub target_fingerprint: &'a str,
    pub plan_fingerprint: &'a str,
    pub context: &'a MigrationContext,
    pub report: &'a MigrationReport,
    pub baseline: &'a TargetCounts,
}

pub(super) async fn ensure_table<C: ConnectionTrait>(db: &C) -> Result<()> {
    let schema = Schema::new(db.get_database_backend());
    let mut statement = schema.create_table_from_entity(Entity);
    statement.if_not_exists();
    db.execute(&statement)
        .await
        .wrap_err("create external migration checkpoint table")?;
    Ok(())
}

pub(super) async fn create<C: ConnectionTrait>(
    db: &C,
    checkpoint: NewCheckpoint<'_>,
) -> Result<()> {
    let NewCheckpoint {
        run_id,
        source_fingerprint,
        target_fingerprint,
        plan_fingerprint,
        context,
        report,
        baseline,
    } = checkpoint;
    if Entity::find_by_id(run_id.to_string())
        .one(db)
        .await?
        .is_some()
    {
        bail!("migration run {run_id} already exists; use --resume or choose another --run-id");
    }
    let now = chrono::Utc::now().fixed_offset();
    ActiveModel {
        id: Set(run_id.to_string()),
        source_fingerprint: Set(source_fingerprint.to_string()),
        target_fingerprint: Set(target_fingerprint.to_string()),
        plan_fingerprint: Set(plan_fingerprint.to_string()),
        status: Set("running".to_string()),
        last_completed_stage: Set(None),
        context_json: Set(serde_json::to_value(context).wrap_err("serialize migration context")?),
        report_json: Set(serde_json::to_value(report).wrap_err("serialize migration report")?),
        baseline_json: Set(serde_json::to_value(baseline).wrap_err("serialize target baseline")?),
        last_error: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .wrap_err_with(|| format!("create migration run {run_id}"))?;
    Ok(())
}

pub(super) async fn load<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    source_fingerprint: &str,
    target_fingerprint: &str,
    plan_fingerprint: &str,
) -> Result<LoadedCheckpoint> {
    let model = Entity::find_by_id(run_id.to_string())
        .one(db)
        .await?
        .ok_or_else(|| color_eyre::eyre::eyre!("migration run {run_id} does not exist"))?;
    if model.source_fingerprint != source_fingerprint {
        bail!("migration run {run_id} belongs to a different Cloudreve source");
    }
    if model.target_fingerprint != target_fingerprint {
        bail!("migration run {run_id} belongs to a different AD target");
    }
    if model.plan_fingerprint != plan_fingerprint {
        bail!("migration run {run_id} options differ from the original migration plan");
    }
    Ok(LoadedCheckpoint {
        status: model.status,
        last_completed_stage: model.last_completed_stage,
        context: serde_json::from_value(model.context_json)
            .wrap_err("decode checkpoint migration context")?,
        report: serde_json::from_value(model.report_json)
            .wrap_err("decode checkpoint migration report")?,
        baseline: serde_json::from_value(model.baseline_json)
            .wrap_err("decode checkpoint target baseline")?,
    })
}

pub(super) async fn save_stage<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    stage: &str,
    context: &MigrationContext,
    report: &MigrationReport,
) -> Result<()> {
    ActiveModel {
        id: Unchanged(run_id.to_string()),
        status: Set("running".to_string()),
        last_completed_stage: Set(Some(stage.to_string())),
        context_json: Set(serde_json::to_value(context).wrap_err("serialize migration context")?),
        report_json: Set(serde_json::to_value(report).wrap_err("serialize migration report")?),
        last_error: Set(None),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("save migration run {run_id} stage {stage}"))?;
    Ok(())
}

pub(super) async fn finish<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    status: &str,
    context: &MigrationContext,
    report: &MigrationReport,
) -> Result<()> {
    ActiveModel {
        id: Unchanged(run_id.to_string()),
        status: Set(status.to_string()),
        context_json: Set(serde_json::to_value(context).wrap_err("serialize migration context")?),
        report_json: Set(serde_json::to_value(report).wrap_err("serialize migration report")?),
        last_error: Set(None),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("finish migration run {run_id}"))?;
    Ok(())
}

pub(super) async fn mark_failed<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    error: &str,
) -> Result<()> {
    let error = error.chars().take(2048).collect::<String>();
    ActiveModel {
        id: Unchanged(run_id.to_string()),
        status: Set("failed".to_string()),
        last_error: Set(Some(error)),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("mark migration run {run_id} failed"))?;
    Ok(())
}
