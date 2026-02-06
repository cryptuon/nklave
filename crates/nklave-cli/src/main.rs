//! Nklave CLI - Command-line interface for Nklave operations
//!
//! Provides operational tooling for managing Nklave instances.

mod commands;

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Nklave CLI - Operational tooling for Nklave signing service
#[derive(Parser)]
#[command(name = "nklave")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Nklave API endpoint URL
    #[arg(short, long, env = "NKLAVE_API_URL", default_value = "http://127.0.0.1:9000")]
    api_url: String,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Check service status
    Status,

    /// Checkpoint management
    #[command(subcommand)]
    Checkpoint(CheckpointCommands),

    /// Validator management
    #[command(subcommand)]
    Validators(ValidatorCommands),

    /// Metrics access
    Metrics,
}

#[derive(Subcommand)]
enum CheckpointCommands {
    /// Create a manual checkpoint
    Create {
        /// Path to save checkpoint (optional, uses configured path if not specified)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Show checkpoint information
    Info {
        /// Path to checkpoint file
        path: String,
    },

    /// List recent checkpoints in a directory
    List {
        /// Directory containing checkpoints
        #[arg(default_value = ".")]
        dir: String,
    },
}

#[derive(Subcommand)]
enum ValidatorCommands {
    /// List all registered validators
    List,

    /// Show validator watermarks and state
    Watermarks {
        /// Validator public key (hex)
        #[arg(short, long)]
        pubkey: Option<String>,
    },

    /// Show signing statistics
    Stats,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Status => commands::status::run(&cli.api_url, cli.format).await,
        Commands::Checkpoint(cmd) => match cmd {
            CheckpointCommands::Create { path } => {
                commands::checkpoint::create(&cli.api_url, path.as_deref(), cli.format).await
            }
            CheckpointCommands::Info { path } => {
                commands::checkpoint::info(&path, cli.format).await
            }
            CheckpointCommands::List { dir } => {
                commands::checkpoint::list(&dir, cli.format).await
            }
        },
        Commands::Validators(cmd) => match cmd {
            ValidatorCommands::List => commands::validators::list(&cli.api_url, cli.format).await,
            ValidatorCommands::Watermarks { pubkey } => {
                commands::validators::watermarks(&cli.api_url, pubkey.as_deref(), cli.format).await
            }
            ValidatorCommands::Stats => commands::validators::stats(&cli.api_url, cli.format).await,
        },
        Commands::Metrics => commands::metrics::run(&cli.api_url, cli.format).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
