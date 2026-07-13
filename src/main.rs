use aster_drive_migration::migration::{MigrationOptions, inspect, migrate};
use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

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
            println!("{report}");
        }
        Command::Migrate(args) => {
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
            println!("{report}");
        }
    }
    Ok(())
}
