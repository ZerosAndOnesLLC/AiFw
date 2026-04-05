use aifw_core::{AliasEngine, Database, NatEngine, RuleEngine};
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
    let pool = db.pool().clone();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::from(aifw_pf::create_backend());
    let engine = RuleEngine::new(db, pf.clone()).with_anchor(args.anchor.clone());
    let nat_engine = NatEngine::new(pool.clone(), pf.clone());
    let alias_engine = AliasEngine::new(pool.clone(), pf.clone());

    // Check pf status
    match pf.is_running().await {
        Ok(true) => info!("pf is running"),
        Ok(false) => error!("pf is not running — rules will not take effect"),
        Err(e) => error!("failed to check pf status: {e}"),
    }

    // Sync aliases to pf tables (must happen before rules that reference them)
    match alias_engine.sync_all().await {
        Ok(()) => info!("aliases synced to pf tables"),
        Err(e) => error!("failed to sync aliases: {e}"),
    }

    // Load and apply filter rules
    match engine.apply_rules().await {
        Ok(()) => {
            let rules = engine.list_rules().await?;
            info!(count = rules.len(), anchor = %args.anchor, "filter rules applied");
        }
        Err(e) => error!("failed to apply filter rules: {e}"),
    }

    // Load and apply NAT rules
    match nat_engine.apply_rules().await {
        Ok(()) => info!("NAT rules applied"),
        Err(e) => error!("failed to apply NAT rules: {e}"),
    }

    if let Some(ref iface) = args.interface {
        info!(interface = %iface, "attached to interface");
    }

    // Initialize IDS engine (only allocate resources if enabled)
    aifw_ids::IdsEngine::migrate(&pool).await.unwrap_or_else(|e| error!("IDS migration failed: {e}"));
    let ids_engine = match aifw_ids::config::RuntimeConfig::load(&pool).await {
        Ok(cfg) if cfg.config().mode != aifw_common::ids::IdsMode::Disabled => {
            match aifw_ids::IdsEngine::new(pool.clone(), pf.clone()).await {
                Ok(engine) => {
                    let mgr = aifw_ids::rules::manager::RulesetManager::new(pool.clone());
                    match mgr.compile_rules(engine.rule_db()).await {
                        Ok(count) => info!(count, "IDS rules compiled"),
                        Err(e) => error!("failed to compile IDS rules: {e}"),
                    }
                    if let Err(e) = engine.start().await {
                        error!("failed to start IDS engine: {e}");
                    }
                    Some(engine)
                }
                Err(e) => {
                    error!("failed to initialize IDS engine: {e}");
                    None
                }
            }
        }
        _ => {
            info!("IDS engine disabled, skipping initialization");
            None
        }
    };

    // Drop privileges to 'aifw' user if running as root
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if unsafe { libc::getuid() } == 0 {
            let user = CString::new("aifw").unwrap();
            let pw = unsafe { libc::getpwnam(user.as_ptr()) };
            if !pw.is_null() {
                let uid = unsafe { (*pw).pw_uid };
                let gid = unsafe { (*pw).pw_gid };
                unsafe {
                    libc::setgid(gid);
                    libc::setuid(uid);
                }
                info!(uid, gid, "dropped privileges to aifw user");
            } else {
                tracing::warn!("aifw user not found — continuing as root");
            }
        }
    }

    info!("daemon ready, waiting for signals");

    // Wait for shutdown signal
    shutdown_signal().await;

    info!("shutting down");

    // Stop IDS engine gracefully (flush alerts)
    if let Some(ref engine) = ids_engine {
        engine.stop().await;
    }

    // Note: we do NOT flush rules on shutdown — pf rules persist in the kernel
    // and should remain active while the daemon restarts or the API takes over.
    // Rules are only flushed when explicitly requested via the API.

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
