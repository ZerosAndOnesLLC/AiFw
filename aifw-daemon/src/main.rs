use aifw_core::{Database, RuleEngine};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "aifw-daemon", about = "AiFw firewall daemon")]
struct Args {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    /// pf anchor name
    #[arg(long, default_value = "aifw")]
    anchor: String,

    /// Network interface to attach to
    #[arg(long)]
    interface: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    info!("AiFw daemon starting");

    // Ensure the database directory exists
    if let Some(parent) = args.db.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let db = Database::new(&args.db).await?;
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::from(aifw_pf::create_backend());
    let engine = RuleEngine::new(db, pf.clone()).with_anchor(args.anchor.clone());

    // Check pf status
    match pf.is_running().await {
        Ok(true) => info!("pf is running"),
        Ok(false) => error!("pf is not running — rules will not take effect"),
        Err(e) => error!("failed to check pf status: {e}"),
    }

    // Load and apply rules
    match engine.apply_rules().await {
        Ok(()) => {
            let rules = engine.list_rules().await?;
            info!(count = rules.len(), anchor = %args.anchor, "rules loaded and applied");
        }
        Err(e) => error!("failed to apply rules: {e}"),
    }

    if let Some(ref iface) = args.interface {
        info!(interface = %iface, "attached to interface");
    }

    info!("daemon ready, waiting for signals");

    // Wait for shutdown signal
    shutdown_signal().await;

    info!("shutting down");

    // Flush rules on shutdown
    if let Err(e) = engine.flush_rules().await {
        error!("failed to flush rules on shutdown: {e}");
    }

    info!("AiFw daemon stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to listen for ctrl+c");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM")
            .recv()
            .await;
    };

    #[cfg(unix)]
    let reload = async {
        signal::unix::signal(signal::unix::SignalKind::hangup())
            .expect("failed to listen for SIGHUP")
            .recv()
            .await;
    };

    #[cfg(unix)]
    tokio::select! {
        _ = ctrl_c => info!("received SIGINT"),
        _ = terminate => info!("received SIGTERM"),
        _ = reload => info!("received SIGHUP (reload)"),
    }

    #[cfg(not(unix))]
    ctrl_c.await;
}
