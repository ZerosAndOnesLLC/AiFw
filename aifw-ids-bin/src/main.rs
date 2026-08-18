//! aifw-ids — owns the IDS engine, BPF capture, FlowTable, and the IPC
//! server that aifw-api queries.

mod handler;

use aifw_common::single_instance::acquire;
use aifw_ids::IdsEngine;
use aifw_ids_ipc::server::serve;
use anyhow::Context;
use clap::Parser;
use handler::EngineHandler;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

/// mimalloc as the process allocator (#412): the API/daemon/IDS workloads
/// are dominated by many small short-lived allocations (JSON frames, pf
/// state snapshots, alert records) where the default libc malloc on the
/// appliance is measurably slower. `--no-default-features` builds without it.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "aifw-ids", about = "AiFw IDS daemon")]
struct Args {
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    #[arg(long, default_value = "/var/run/aifw/ids.sock")]
    socket: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,

    /// Serve tokio-console task diagnostics on 127.0.0.1:6669 (#413). Only
    /// available in a build made with
    /// `RUSTFLAGS="--cfg tokio_unstable" cargo build --features tokio-console`;
    /// otherwise the flag is accepted and warns.
    #[arg(long)]
    tokio_console: bool,
}

fn main() -> anyhow::Result<()> {
    // Explicit runtime (#409): worker floor of 4 so a 2-vCPU appliance's
    // periodic tasks don't fully subscribe the scheduler; override with
    // AIFW_WORKER_THREADS.
    let rt = aifw_common::runtime::build("aifw-ids")?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Fail closed when another instance actually holds the lock; fail open
    // when the lockfile path isn't writable (older appliances whose rc.d
    // didn't pre-create the lockfile). rc.d retains its own singleton
    // enforcement via the daemon-pair pidfiles.
    #[cfg(unix)]
    let _instance_lock = match acquire("aifw-ids") {
        Ok(lock) => Some(lock),
        Err(aifw_common::single_instance::InstanceLockError::AlreadyRunning(pid)) => {
            // stderr, not tracing: the subscriber isn't initialized until below,
            // so this pre-init startup diagnostic would otherwise be dropped.
            eprintln!("aifw-ids: another instance is already running (pid {pid})");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("aifw-ids: warning: singleton lock unavailable: {e} (continuing)");
            None
        }
    };

    // Remote syslog manager exists before the subscriber so the forwarding
    // layer can attach; DB config is applied below once the pool is up.
    let syslog_mgr = aifw_common::syslog::SyslogManager::start();
    {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
        // tokio-console layer (#413): only compiled in with the feature;
        // otherwise `--tokio-console` is a no-op with a warning below.
        #[cfg(feature = "tokio-console")]
        let console_layer = args.tokio_console.then(console_subscriber::spawn);
        #[cfg(not(feature = "tokio-console"))]
        let console_layer: Option<tracing_subscriber::layer::Identity> = None;
        tracing_subscriber::registry()
            .with(console_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_filter(env_filter)
                    .with_filter(aifw_common::syslog::LocalStorageGate::new(
                        syslog_mgr.handle(),
                    )),
            )
            .with(aifw_common::syslog::SyslogLayer::new(
                syslog_mgr.handle(),
                "aifw-ids",
            ))
            .init();
    }
    #[cfg(not(feature = "tokio-console"))]
    if args.tokio_console {
        tracing::warn!(
            "--tokio-console ignored: this build lacks the tokio-console feature \
             (build with RUSTFLAGS=\"--cfg tokio_unstable\" --features tokio-console)"
        );
    }
    {
        let rt = aifw_common::runtime::snapshot();
        tracing::info!(
            worker_threads = rt.worker_threads,
            "aifw-ids: tokio runtime ready"
        );
    }

    // aifw-api and aifw-ids share aifw.db. Without WAL + busy_timeout we
    // see SQLITE_BUSY drops on concurrent INSERT (alert ingestion racing
    // with API config writes), and silent alert loss. WAL + 5s busy_timeout
    // matches the settings aifw-api uses.
    let connect_url = format!("sqlite://{}", args.db.display());
    let opts = SqliteConnectOptions::from_str(&connect_url)
        .context("parse sqlite url")?
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        // PERF-H1: match aifw-core's pool tuning. ids_alerts grows into the
        // millions; without a bigger cache + mmap every aggregate scan hits
        // disk. Applied per-connection on connect.
        .pragma("cache_size", "-65536") // ~64 MB page cache (negative = KiB)
        .pragma("mmap_size", "268435456") // 256 MiB memory-mapped reads
        .pragma("temp_store", "MEMORY") // sorts/temp b-trees stay in RAM
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .context("connect sqlite")?;

    IdsEngine::migrate(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("migrate: {e}"))?;

    // Remote syslog: apply persisted config and refresh via the shared
    // 60s poller (picks up API/CLI edits).
    aifw_common::syslog::migrate(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("syslog migrate: {e}"))?;
    syslog_mgr.apply(aifw_common::syslog::load(&pool).await);
    aifw_common::syslog::spawn_config_poller(pool.clone(), syslog_mgr.clone(), "aifw-ids");

    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::from(aifw_pf::create_backend());

    // Always attach an in-memory alert buffer so the IPC `tail_alerts`
    // request has somewhere to read from. Limits mirror the defaults used
    // by aifw-api today (PR 5 will move config knobs out of aifw-api).
    let alert_buffer = Arc::new(aifw_ids::output::memory::AlertBuffer::new(64, 86400));
    let engine = Arc::new(
        IdsEngine::with_alert_buffer(pool, pf, Some(alert_buffer), Some(syslog_mgr.handle()))
            .await
            .map_err(|e| anyhow::anyhow!("init engine: {e}"))?,
    );

    // Alert retention runs regardless of engine mode (#601): pruning and
    // the clock-skew scrub are hygiene for rows already in the DB, and
    // gating them behind the mode check left disabled-IDS appliances with
    // multi-million-row ids_alerts tables that never shrink.
    engine.spawn_retention_worker();

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
