use std::path::{Path, PathBuf};

use aster_drive_migration::migration::{
    MigrationOptions, MigrationReport, inspect, migrate, write_json_report,
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
    #[arg(long, env = "ASTER_DIRECT_LINK_SECRET", hide_env_values = true)]
    direct_link_secret: Option<String>,
    #[arg(long)]
    allow_non_empty_target: bool,
    #[arg(long)]
    skip_unsupported_policies: bool,
    #[arg(long)]
    dry_run: bool,
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
                direct_link_secret: args.direct_link_secret,
                include_deleted: args.connection.include_deleted,
                allow_non_empty_target: args.allow_non_empty_target,
                skip_unsupported_policies: args.skip_unsupported_policies,
                dry_run: args.dry_run,
            })
            .await?;
            emit_report(report_path.as_deref(), &report)?;
        }
    }
    Ok(())
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
