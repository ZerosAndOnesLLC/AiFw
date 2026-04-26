//! aifw-ids — owns the IDS engine, BPF capture, FlowTable, and the IPC
//! server that aifw-api queries.

mod handler;

use aifw_common::single_instance::acquire;
use aifw_ids::IdsEngine;
use aifw_ids_ipc::server::serve;
use anyhow::Context;
use clap::Parser;
use handler::EngineHandler;
use sqlx::sqlite::SqlitePoolOptions;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "aifw-ids", about = "AiFw IDS daemon")]
struct Args {
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    #[arg(long, default_value = "/var/run/aifw/ids.sock")]
    socket: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    #[cfg(unix)]
    let _instance_lock = match acquire("aifw-ids") {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("aifw-ids: {e}");
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&format!("sqlite://{}", args.db.display()))
        .await
        .context("connect sqlite")?;

    IdsEngine::migrate(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("migrate: {e}"))?;

    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::from(aifw_pf::create_backend());

    // Always attach an in-memory alert buffer so the IPC `tail_alerts`
    // request has somewhere to read from. Limits mirror the defaults used
    // by aifw-api today (PR 5 will move config knobs out of aifw-api).
    let alert_buffer = Arc::new(aifw_ids::output::memory::AlertBuffer::new(64, 86400));
    let engine = Arc::new(
        IdsEngine::with_alert_buffer(pool, pf, Some(alert_buffer))
            .await
            .map_err(|e| anyhow::anyhow!("init engine: {e}"))?,
    );

    // Compile and start if mode != Disabled.
    if let Ok(cfg) = engine.load_config().await
        && cfg.mode != aifw_common::ids::IdsMode::Disabled
    {
        let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
        if let Err(e) = mgr.compile_rules(engine.rule_db()).await {
            tracing::warn!(error = %e, "rule compile failed");
        }
        if let Err(e) = engine.start().await {
            tracing::warn!(error = %e, "engine start failed");
        }
    }

    // Periodic time-based flow expiry — even idle flows eventually fall off
    // so memory plateaus on quiet links. Per-packet expiry runs in the
    // capture worker; this is the safety net for low-traffic paths.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            const FLOW_IDLE_TIMEOUT_US: i64 = 300_000_000; // 5 min
            loop {
                interval.tick().await;
                if let Some(table) = engine.flow_table() {
                    let now_us = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as i64;
                    let expired = table.expire(now_us, FLOW_IDLE_TIMEOUT_US);
                    if expired > 0 {
                        tracing::debug!(expired, active = table.len(), "flow table time-expiry");
                    }
                }
            }
        });
    }

    // Bind the IPC socket. Remove stale socket file if present.
    let _ = std::fs::remove_file(&args.socket);
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent).context("create socket dir")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind unix socket")?;

    // Permissions: root:aifw 0660. The rc.d script chowns the parent dir;
    // we just chmod the socket inode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        let _ = std::fs::set_permissions(&args.socket, perms);
    }

    tracing::info!(socket = %args.socket.display(), "aifw-ids serving");

    let handler = Arc::new(EngineHandler::new(engine.clone()));
    let server_task = tokio::spawn(serve(listener, handler));

    // Wait for SIGTERM/SIGINT for clean shutdown.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM"),
        _ = sigint.recv() => tracing::info!("SIGINT"),
    }

    server_task.abort();
    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}
