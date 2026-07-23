use std::path::{Path, PathBuf};

use aster_drive_migration::migration::{
    MigrationOptions, MigrationReport, StorageMode, inspect, migrate, write_json_report,
};
use clap::{Parser, Subcommand};
use color_eyre::eyre::{Result, bail};

#[derive(Debug, Parser)]
#[command(name = "aster-drive-migration", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check(ConnectionArgs),
    Migrate(MigrateArgs),
}

#[derive(Debug, clap::Args)]
struct ConnectionArgs {
    #[arg(long, env = "CLOUDREVE_DATABASE_URL")]
    source_url: String,
    #[arg(long, env = "ASTERDRIVE_DATABASE_URL")]
    target_url: String,
    #[arg(long)]
    include_deleted: bool,
    #[arg(long, value_name = "PATH")]
    report_path: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct MigrateArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    #[arg(long, env = "ASTER_MIGRATION_DEFAULT_PASSWORD")]
    default_password: String,
    #[arg(long, default_value = ".")]
    local_base_path: String,
    #[arg(long = "local-policy-root", value_name = "SOURCE_POLICY_ID=PATH")]
    local_policy_roots: Vec<String>,
    #[arg(long, value_enum, default_value_t = StorageMode::ReuseSourceStorage)]
    storage_mode: StorageMode,
    #[arg(long, value_name = "PATH")]
    target_local_base_path: Option<String>,
    #[arg(
        long = "target-local-policy-root",
        value_name = "SOURCE_POLICY_ID=PATH"
    )]
    target_local_policy_roots: Vec<String>,
    #[arg(long)]
    verify_local_storage: bool,
    #[arg(long)]
    verify_remote_storage: bool,
    #[arg(long, env = "ASTER_DIRECT_LINK_SECRET", hide_env_values = true)]
    direct_link_secret: Option<String>,
    #[arg(long)]
    allow_non_empty_target: bool,
    #[arg(long)]
    skip_unsupported_policies: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long, value_name = "ID")]
    run_id: Option<String>,
    #[arg(long, requires = "run_id")]
    resume: bool,
    #[arg(long, default_value_t = 500, value_name = "COUNT")]
    blob_batch_size: usize,
    #[arg(long, default_value_t = 500, value_name = "COUNT")]
    file_batch_size: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    match Cli::parse().command {
        Command::Check(args) => {
            let report = inspect(&args.source_url, &args.target_url, args.include_deleted).await?;
            emit_report(args.report_path.as_deref(), &report)?;
        }
        Command::Migrate(args) => {
            let report_path = args.connection.report_path.clone();
            let report = migrate(MigrationOptions {
                source_url: args.connection.source_url,
                target_url: args.connection.target_url,
                default_password: args.default_password,
                local_base_path: args.local_base_path,
                local_policy_roots: parse_local_policy_roots(args.local_policy_roots)?,
                storage_mode: args.storage_mode,
                target_local_base_path: args.target_local_base_path,
                target_local_policy_roots: parse_local_policy_roots(
                    args.target_local_policy_roots,
                )?,
                verify_local_storage: args.verify_local_storage,
                verify_remote_storage: args.verify_remote_storage,
                direct_link_secret: args.direct_link_secret,
                include_deleted: args.connection.include_deleted,
                allow_non_empty_target: args.allow_non_empty_target,
                skip_unsupported_policies: args.skip_unsupported_policies,
                dry_run: args.dry_run,
                run_id: args.run_id,
                resume: args.resume,
                blob_batch_size: args.blob_batch_size,
                file_batch_size: args.file_batch_size,
            })
            .await?;
            emit_report(report_path.as_deref(), &report)?;
        }
    }
    Ok(())
}

fn parse_local_policy_roots(
    values: Vec<String>,
) -> Result<std::collections::BTreeMap<i64, String>> {
    let mut roots = std::collections::BTreeMap::new();
    for value in values {
        let Some((source_policy_id, path)) = value.split_once('=') else {
            bail!("--local-policy-root must use SOURCE_POLICY_ID=PATH");
        };
        let source_policy_id = source_policy_id.parse::<i64>().map_err(|_| {
            color_eyre::eyre::eyre!("invalid local storage policy ID {source_policy_id}")
        })?;
        if source_policy_id <= 0 || path.trim().is_empty() {
            bail!("--local-policy-root must use a positive policy ID and non-empty path");
        }
        if roots.insert(source_policy_id, path.to_string()).is_some() {
            bail!("local storage policy {source_policy_id} was configured more than once");
        }
    }
    Ok(roots)
}

fn emit_report(report_path: Option<&Path>, report: &MigrationReport) -> Result<()> {
    if let Some(path) = report_path {
        write_json_report(path, report)?;
    }
    println!("{report}");
    if report.validation.performed && !report.validation.passed {
        bail!("migration committed but post-migration validation failed; inspect the JSON report");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_policy_roots() -> Result<()> {
        let roots = parse_local_policy_roots(vec![
            "1=D:/cloudreve-data".to_string(),
            "2=E:/cloudreve-archive".to_string(),
        ])?;
        assert_eq!(roots.get(&1).map(String::as_str), Some("D:/cloudreve-data"));
        assert_eq!(
            roots.get(&2).map(String::as_str),
            Some("E:/cloudreve-archive")
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_local_policy_roots() {
        assert!(parse_local_policy_roots(vec!["missing-separator".to_string()]).is_err());
        assert!(parse_local_policy_roots(vec!["0=C:/data".to_string()]).is_err());
        assert!(
            parse_local_policy_roots(vec!["1=C:/data".to_string(), "1=D:/data".to_string()])
                .is_err()
        );
    }
}
