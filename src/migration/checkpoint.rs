use color_eyre::eyre::{Result, WrapErr, bail};
use sea_orm::entity::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Schema,
    Set, Unchanged,
};

use super::{MigrationContext, MigrationReport, TargetCounts};
use aster_drive_migration_core::RunStatus;

pub(super) mod stage_cursor {
    use sea_orm::entity::prelude::*;

    #[sea_orm::model]
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "aster_external_migration_stage_cursors")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub run_id: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub stage: String,
        pub cursor_value: i64,
        pub processed_count: i64,
        pub updated_at: DateTimeWithTimeZone,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub(super) mod object_map {
    use sea_orm::entity::prelude::*;

    #[sea_orm::model]
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "aster_external_migration_object_map")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub run_id: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub object_type: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub source_id: i64,
        pub target_id: i64,
        pub created_at: DateTimeWithTimeZone,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

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

pub(super) async fn list<C: ConnectionTrait>(db: &C) -> Result<Vec<Model>> {
    Entity::find()
        .order_by_desc(Column::UpdatedAt)
        .all(db)
        .await
        .wrap_err("list migration runs")
}

pub(super) async fn load_any<C: ConnectionTrait>(db: &C, run_id: &str) -> Result<Model> {
    Entity::find_by_id(run_id.to_string())
        .one(db)
        .await?
        .ok_or_else(|| color_eyre::eyre::eyre!("migration run {run_id} does not exist"))
}

pub(super) async fn abort<C: ConnectionTrait>(db: &C, run_id: &str) -> Result<()> {
    let model = load_any(db, run_id).await?;
    let status = RunStatus::parse(&model.status)?;
    if !status.can_abort() {
        bail!(
            "migration run {run_id} has status {}; only running, failed or validation_failed runs may be aborted",
            model.status
        );
    }
    ActiveModel {
        id: Unchanged(run_id.to_string()),
        status: Set(RunStatus::Aborted.as_str().to_string()),
        last_error: Set(Some("aborted by operator".to_string())),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("abort migration run {run_id}"))?;
    Ok(())
}

pub(super) async fn delete_completed<C: ConnectionTrait>(db: &C, run_id: &str) -> Result<()> {
    let model = load_any(db, run_id).await?;
    let status = RunStatus::parse(&model.status)?;
    if !status.can_cleanup() {
        bail!(
            "migration run {run_id} has status {}; only completed run metadata may be cleaned up",
            model.status
        );
    }
    stage_cursor::Entity::delete_many()
        .filter(stage_cursor::Column::RunId.eq(run_id))
        .exec(db)
        .await?;
    object_map::Entity::delete_many()
        .filter(object_map::Column::RunId.eq(run_id))
        .exec(db)
        .await?;
    Entity::delete_by_id(run_id.to_string())
        .exec(db)
        .await
        .wrap_err_with(|| format!("delete completed migration run {run_id}"))?;
    Ok(())
}

pub(super) async fn ensure_table<C: ConnectionTrait>(db: &C) -> Result<()> {
    let schema = Schema::new(db.get_database_backend());
    let mut statement = schema.create_table_from_entity(Entity);
    statement.if_not_exists();
    db.execute(&statement)
        .await
        .wrap_err("create external migration checkpoint table")?;
    let mut statement = schema.create_table_from_entity(stage_cursor::Entity);
    statement.if_not_exists();
    db.execute(&statement)
        .await
        .wrap_err("create external migration stage cursor table")?;
    let mut statement = schema.create_table_from_entity(object_map::Entity);
    statement.if_not_exists();
    db.execute(&statement)
        .await
        .wrap_err("create external migration object map table")?;
    Ok(())
}

pub(super) async fn load_stage_cursor<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    stage: &str,
) -> Result<Option<stage_cursor::Model>> {
    Ok(
        stage_cursor::Entity::find_by_id((run_id.to_string(), stage.to_string()))
            .one(db)
            .await?,
    )
}

pub(super) async fn save_stage_cursor<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    stage: &str,
    cursor_value: i64,
    processed_count: i64,
) -> Result<()> {
    use sea_orm::sea_query::OnConflict;

    stage_cursor::Entity::insert(stage_cursor::ActiveModel {
        run_id: Set(run_id.to_string()),
        stage: Set(stage.to_string()),
        cursor_value: Set(cursor_value),
        processed_count: Set(processed_count),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
    })
    .on_conflict(
        OnConflict::columns([stage_cursor::Column::RunId, stage_cursor::Column::Stage])
            .update_columns([
                stage_cursor::Column::CursorValue,
                stage_cursor::Column::ProcessedCount,
                stage_cursor::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(db)
    .await
    .wrap_err_with(|| format!("save migration run {run_id} stage {stage} cursor"))?;
    Ok(())
}

pub(super) async fn save_object_mappings<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    object_type: &str,
    mappings: &[(i64, i64)],
) -> Result<()> {
    if mappings.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now().fixed_offset();
    object_map::Entity::insert_many(mappings.iter().map(|(source_id, target_id)| {
        object_map::ActiveModel {
            run_id: Set(run_id.to_string()),
            object_type: Set(object_type.to_string()),
            source_id: Set(*source_id),
            target_id: Set(*target_id),
            created_at: Set(now),
        }
    }))
    .exec(db)
    .await
    .wrap_err_with(|| format!("save migration run {run_id} {object_type} mappings"))?;
    Ok(())
}

pub(super) async fn load_object_mappings<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    object_type: &str,
) -> Result<std::collections::HashMap<i64, i64>> {
    use sea_orm::{ColumnTrait, QueryFilter};

    Ok(object_map::Entity::find()
        .filter(object_map::Column::RunId.eq(run_id))
        .filter(object_map::Column::ObjectType.eq(object_type))
        .all(db)
        .await?
        .into_iter()
        .map(|mapping| (mapping.source_id, mapping.target_id))
        .collect())
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
        status: Set(RunStatus::Running.as_str().to_string()),
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
        status: Set(RunStatus::Running.as_str().to_string()),
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

pub(super) async fn save_progress<C: ConnectionTrait>(
    db: &C,
    run_id: &str,
    context: &MigrationContext,
    report: &MigrationReport,
) -> Result<()> {
    ActiveModel {
        id: Unchanged(run_id.to_string()),
        status: Set(RunStatus::Running.as_str().to_string()),
        context_json: Set(serde_json::to_value(context).wrap_err("serialize migration context")?),
        report_json: Set(serde_json::to_value(report).wrap_err("serialize migration report")?),
        last_error: Set(None),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("save migration run {run_id} progress"))?;
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
        status: Set(RunStatus::Failed.as_str().to_string()),
        last_error: Set(Some(error)),
        updated_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(db)
    .await
    .wrap_err_with(|| format!("mark migration run {run_id} failed"))?;
    Ok(())
}
