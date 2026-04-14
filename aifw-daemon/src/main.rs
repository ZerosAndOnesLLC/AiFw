use aifw_core::{
    AliasEngine, Database, GatewayEngine, GroupEngine, InstanceEngine, LeakEngine, NatEngine,
    PolicyEngine, RuleEngine, SlaEngine,
};
use chrono::Timelike;
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

    // ========================================================
    // Multi-WAN bootstrap (issue #132)
    // ========================================================
    let multiwan_engine = Arc::new(InstanceEngine::new(pool.clone(), pf.clone()));
    let gateway_engine = Arc::new(GatewayEngine::new(pool.clone()));
    let group_engine = Arc::new(GroupEngine::new(pool.clone()));
    let policy_engine = Arc::new(PolicyEngine::new(pool.clone(), pf.clone()));
    let leak_engine = Arc::new(LeakEngine::new(pool.clone(), pf.clone()));
    let sla_engine = Arc::new(SlaEngine::new(pool.clone()));

    if let Err(e) = multiwan_engine.migrate().await { error!("multiwan migrate: {e}"); }
    if let Err(e) = gateway_engine.migrate().await { error!("gateway migrate: {e}"); }
    if let Err(e) = group_engine.migrate().await { error!("group migrate: {e}"); }
    if let Err(e) = policy_engine.migrate().await { error!("policy migrate: {e}"); }
    if let Err(e) = leak_engine.migrate().await { error!("leak migrate: {e}"); }
    if let Err(e) = sla_engine.migrate().await { error!("sla migrate: {e}"); }

    // Re-apply policies/leaks from DB state at boot
    let instances = multiwan_engine.list().await.unwrap_or_default();
    let gateways = gateway_engine.list().await.unwrap_or_default();
    let groups = group_engine.list().await.unwrap_or_default();
    let mut members = std::collections::HashMap::new();
    for g in &groups {
        if let Ok(list) = group_engine.list_members(g.id).await {
            members.insert(g.id, list);
        }
    }
    if let Err(e) = policy_engine.apply(&instances, &gateways, &groups, &members).await {
        error!("policy apply at boot: {e}");
    }
    if let Err(e) = leak_engine.apply(&instances).await {
        error!("leak apply at boot: {e}");
    }

    // Spawn probe monitors for all enabled gateways
    if let Err(e) = gateway_engine.start_all().await {
        error!("gateway monitors failed to start: {e}");
    } else {
        info!(count = gateways.len(), "gateway monitors started");
    }

    // SLA aggregation loop — 1-minute buckets, retention pruned daily
    {
        let sla = sla_engine.clone();
        let gw = gateway_engine.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut prune_counter: u32 = 0;
            loop {
                ticker.tick().await;
                let Ok(list) = gw.list().await else { continue };
                let now = chrono::Utc::now();
                let bucket = now
                    .with_second(0)
                    .and_then(|t| t.with_nanosecond(0))
                    .unwrap_or(now);
                for g in list {
                    let sample = aifw_core::multiwan::SlaSample {
                        gateway_id: g.id,
                        bucket_ts: bucket,
                        samples: 60 / (g.interval_ms.max(1) as u64 / 1000).max(1),
                        rtt_avg: g.last_rtt_ms,
                        rtt_p95: g.last_rtt_ms,
                        rtt_p99: g.last_rtt_ms,
                        jitter_avg: g.last_jitter_ms,
                        loss_pct: g.last_loss_pct,
                        mos_avg: g.last_mos,
                        up_seconds: if g.state == aifw_common::GatewayState::Up { 60 } else { 0 },
                    };
                    let _ = sla.record(&sample).await;
                }
                prune_counter += 1;
                if prune_counter >= 60 * 24 {
                    prune_counter = 0;
                    let _ = sla.prune(30).await;
                }
            }
        });
        info!("SLA aggregation loop started");
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
        use nix::unistd::{Uid, User};
        if Uid::effective().is_root() {
            match User::from_name("aifw") {
                Ok(Some(pw)) => {
                    let uid = pw.uid;
                    let gid = pw.gid;
                    if let Err(e) = nix::unistd::setgid(gid) {
                        tracing::warn!(error = %e, "failed to setgid");
                    }
                    if let Err(e) = nix::unistd::setuid(uid) {
                        tracing::warn!(error = %e, "failed to setuid");
                    } else {
                        info!(uid = uid.as_raw(), gid = gid.as_raw(), "dropped privileges to aifw user");
                    }
                }
                Ok(None) => {
                    tracing::warn!("aifw user not found — continuing as root");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to look up aifw user — continuing as root");
                }
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
