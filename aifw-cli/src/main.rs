mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aifw", about = "AiFw — AI-Powered Firewall for FreeBSD", version)]
struct Cli {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db", global = true)]
    db: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize AiFw configuration and database
    Init {
        /// Path to create the database
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Manage firewall rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Show firewall status
    Status,
    /// Reload rules from database and apply to pf
    Reload,
}

#[derive(Subcommand)]
enum RulesAction {
    /// Add a new rule
    Add {
        /// Action: pass, block, block-drop, block-return
        #[arg(long)]
        action: String,

        /// Direction: in, out, any
        #[arg(long, default_value = "any")]
        direction: String,

        /// Protocol: tcp, udp, icmp, icmp6, any
        #[arg(long, default_value = "any")]
        proto: String,

        /// Source address (IP, CIDR, "any", or <table>)
        #[arg(long, default_value = "any")]
        src: String,

        /// Source port or port range (e.g., 80, 8000:9000)
        #[arg(long)]
        src_port: Option<String>,

        /// Destination address
        #[arg(long, default_value = "any")]
        dst: String,

        /// Destination port or port range
        #[arg(long)]
        dst_port: Option<String>,

        /// Network interface
        #[arg(long)]
        interface: Option<String>,

        /// Rule priority (0-10000, lower = first)
        #[arg(long, default_value = "100")]
        priority: i32,

        /// Enable logging
        #[arg(long)]
        log: bool,

        /// Rule label
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a rule by ID
    Remove {
        /// Rule UUID
        id: String,
    },
    /// List all rules
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            commands::init(path.as_deref().unwrap_or(&cli.db)).await?;
        }
        Commands::Rules { action } => match action {
            RulesAction::Add {
                action,
                direction,
                proto,
                src,
                src_port,
                dst,
                dst_port,
                interface,
                priority,
                log,
                label,
            } => {
                commands::rules_add(
                    &cli.db, &action, &direction, &proto, &src, src_port.as_deref(),
                    &dst, dst_port.as_deref(), interface.as_deref(), priority, log,
                    label.as_deref(),
                )
                .await?;
            }
            RulesAction::Remove { id } => {
                commands::rules_remove(&cli.db, &id).await?;
            }
            RulesAction::List { json } => {
                commands::rules_list(&cli.db, json).await?;
            }
        },
        Commands::Status => {
            commands::status(&cli.db).await?;
        }
        Commands::Reload => {
            commands::reload(&cli.db).await?;
        }
    }

    Ok(())
}
