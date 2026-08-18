mod cluster_replicator;
mod health_prober;
mod role_watcher;

use aifw_core::{
    AliasEngine, ClusterEngine, Database, GatewayEngine, GroupEngine, InstanceEngine, LeakEngine,
    NatEngine, PolicyEngine, RuleEngine, SlaEngine,
};
use chrono::Timelike;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

/// mimalloc as the process allocator (#412): the API/daemon/IDS workloads
/// are dominated by many small short-lived allocations (JSON frames, pf
/// state snapshots, alert records) where the default libc malloc on the
/// appliance is measurably slower. `--no-default-features` builds without it.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    let rt = aifw_common::runtime::build("aifw-daemon")?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Fail closed when another instance actually holds the lock; fail open
    // when the lockfile path isn't writable (e.g. an appliance whose rc.d
    // never got upgraded to pre-create the lockfile). The latter case lets
    // the binary still come up so the in-product updater can ship the rc.d
    // fix that solves it. rc.d retains its own singleton enforcement via
    // the daemon-pair pidfiles.
    #[cfg(unix)]
    let _instance_lock = match aifw_common::single_instance::acquire("aifw-daemon") {
        Ok(lock) => Some(lock),
        Err(aifw_common::single_instance::InstanceLockError::AlreadyRunning(pid)) => {
            // stderr, not tracing: the subscriber isn't initialized until below,
            // so this pre-init startup diagnostic would otherwise be dropped.
            eprintln!("aifw-daemon: another instance is already running (pid {pid})");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("aifw-daemon: warning: singleton lock unavailable: {e} (continuing)");
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
            .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default());
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
                "aifw-daemon",
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
            "aifw-daemon: tokio runtime ready"
        );
    }

    info!("AiFw daemon starting");

    // Ensure the database directory exists
    if let Some(parent) = args.db.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // #298: secrets master key beside the database (shared with aifw-api).
    aifw_core::secrets::configure_from_db_path(&args.db);
    let db = Database::new(&args.db).await?;
    let pool = db.pool().clone();

    // Remote syslog: table may not exist yet if aifw-api never ran; the
    // migrate is idempotent. Config refreshes via the shared 60s poller.
    aifw_common::syslog::migrate(&pool).await?;
    syslog_mgr.apply(aifw_common::syslog::load(&pool).await);
    aifw_common::syslog::spawn_config_poller(pool.clone(), syslog_mgr.clone(), "aifw-daemon");

    // Reconcile the pf local-log policy (pflogd on/off for disable_local):
    // once at boot, on every polled policy change, again after a failed
    // attempt (sudo errors don't mark the state applied), and — while the
    // policy is "stopped" — re-enforced every tick so an externally
    // restarted pflogd is corrected within a minute. Covers CLI DB edits
    // and crash recovery; the API also applies immediately on settings PUT.
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut last_ok: Option<bool> = None;
            loop {
                // A transient DB read error must not read as "policy off" —
                // that would start pflogd and flap the toggle (see the
                // matching guard in the shared config poller).
                match aifw_common::syslog::try_load(&pool).await {
                    Ok(cfg) => {
                        let want = aifw_core::local_log::local_pf_log_disabled(&cfg);
                        if want || last_ok != Some(want) {
                            let ok = aifw_core::local_log::apply_local_log_policy(&cfg).await;
                            last_ok = if ok { Some(want) } else { None };
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "pf local-log policy poll failed; keeping current state");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::from(aifw_pf::create_backend());
    let engine =
        Arc::new(RuleEngine::new(pool.clone(), pf.clone()).with_anchor(args.anchor.clone()));
    // NAT engine defaults to aifw_common::anchors::NAT ("aifw-nat"):
    // NAT loads replace every rule class in their anchor since #531, so a
    // boot-time apply into "aifw" would wipe the filter rules loaded above.
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
            let rules = engine.list().await?;
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

    // Schedule boundary watcher (#537) — apply_rules only compiles rules
    // inside their schedule window, so something must reload the anchor when
    // a window opens or closes. Re-evaluate every minute (same cadence
    // pfSense/OPNsense use for schedule ticks; granularity is HH:MM) and
    // reapply only when a scheduled rule's active/inactive state actually
    // flips. Schedule CRUD is also picked up within one tick.
    {
        let engine = engine.clone();
        let vpn_engine = aifw_core::VpnEngine::new(pool.clone(), pf.clone());
        let baseline = schedule_fingerprint(&engine).await;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last = baseline;
            loop {
                ticker.tick().await;
                let fp = schedule_fingerprint(&engine).await;
                if fp == last {
                    continue;
                }
                info!("schedule boundary crossed; reloading firewall rules");
                // Keep VPN pass rules in the anchor across the reload, same
                // as the API's reload path.
                match vpn_engine.collect_vpn_rules().await {
                    Ok(extras) => engine.set_extra_rules(extras).await,
                    Err(e) => {
                        tracing::warn!(error = %e, "schedule reload: collecting vpn rules failed")
                    }
                }
                match engine.apply_rules().await {
                    // Only advance the fingerprint on success so a failed
                    // reload is retried on the next tick instead of leaving
                    // the stale ruleset loaded silently.
                    Ok(()) => last = fp,
                    Err(e) => error!("schedule reload: apply_rules failed: {e}"),
                }
            }
        });
        info!("schedule watcher started");
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

    if let Err(e) = multiwan_engine.migrate().await {
        error!("multiwan migrate: {e}");
    }
    if let Err(e) = gateway_engine.migrate().await {
        error!("gateway migrate: {e}");
    }
    if let Err(e) = group_engine.migrate().await {
        error!("group migrate: {e}");
    }
    if let Err(e) = policy_engine.migrate().await {
        error!("policy migrate: {e}");
    }
    if let Err(e) = leak_engine.migrate().await {
        error!("leak migrate: {e}");
    }
    if let Err(e) = sla_engine.migrate().await {
        error!("sla migrate: {e}");
    }

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
    if let Err(e) = policy_engine
        .apply(&instances, &gateways, &groups, &members)
        .await
    {
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

    // Reload firewall rules when a gateway changes state (#540): rules with
    // a policy-routing gateway compile to `route-to` while it's healthy and
    // fall back to default routing while it's down, so state transitions
    // must recompile the anchor. Skipped when no rule references a gateway.
    {
        let engine = engine.clone();
        let vpn_engine = aifw_core::VpnEngine::new(pool.clone(), pf.clone());
        let mut rx = gateway_engine.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        match engine.db().has_gateway_rules().await {
                            Ok(false) => continue,
                            Ok(true) => {}
                            Err(e) => {
                                tracing::warn!(error = %e, "gateway route watcher: db check failed");
                                continue;
                            }
                        }
                        info!(gateway = %ev.gateway_id, to = ?ev.to_state,
                            "gateway transition; reloading policy-routed rules");
                        match vpn_engine.collect_vpn_rules().await {
                            Ok(extras) => engine.set_extra_rules(extras).await,
                            Err(e) => tracing::warn!(error = %e,
                                "gateway route reload: collecting vpn rules failed"),
                        }
                        if let Err(e) = engine.apply_rules().await {
                            error!("gateway route reload: apply_rules failed: {e}");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        info!("gateway route watcher started");
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
                        samples: 60 / (g.interval_ms.max(1) / 1000).max(1),
                        rtt_avg: g.last_rtt_ms,
                        rtt_p95: g.last_rtt_ms,
                        rtt_p99: g.last_rtt_ms,
                        jitter_avg: g.last_jitter_ms,
                        loss_pct: g.last_loss_pct,
                        mos_avg: g.last_mos,
                        up_seconds: if g.state == aifw_common::GatewayState::Up {
                            60
                        } else {
                            0
                        },
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

    // HA kernel-state recovery — idempotent; re-runs ifconfig commands for
    // pfsync and CARP VIPs if they are absent after a reboot. Logs a warning
    // and continues on failure so a misconfigured HA setup never prevents the
    // daemon from coming up.
    //
    // cluster_engine is kept alive past this block so the ACME scheduler can
    // use it for master-only renewal and cert-push to peers (Commit 9 #222).
    let cluster_engine = Arc::new(ClusterEngine::new(pool.clone(), pf.clone()));
    {
        if let Err(e) = cluster_engine.migrate().await {
            tracing::warn!(error = %e, "ha: cluster migrate failed; continuing");
        }
        if let Err(e) = cluster_engine.recover_kernel_state().await {
            tracing::warn!(error = %e, "ha: kernel-state recovery failed; continuing");
        }

        // Cluster background tasks — active only when AIFW_LOOPBACK_API_KEY is set.
        // RoleWatcher: 1s CARP role polling → /cluster/internal/role-changed
        // HealthProber: per-check interval probes → CARP demotion on failure
        // ClusterReplicator: 10s snapshot push to peer on master
        let self_api_key = std::env::var("AIFW_LOOPBACK_API_KEY").unwrap_or_default();
        if !self_api_key.is_empty() {
            let api_base = aifw_common::DEFAULT_LOOPBACK_API_BASE.to_string();

            let watcher = role_watcher::RoleWatcher::new(api_base.clone(), self_api_key.clone());
            tokio::spawn(watcher.run());
            info!("ha: role watcher started");

            let prober = health_prober::HealthProber::new(
                cluster_engine.clone(),
                api_base.clone(),
                self_api_key.clone(),
            );
            tokio::spawn(prober.run());
            info!("ha: health prober started");

            let replicator = cluster_replicator::ClusterReplicator::new(
                cluster_engine.clone(),
                api_base,
                self_api_key,
            );
            tokio::spawn(replicator.run());
            info!("ha: cluster replicator started");
        } else {
            info!("ha: AIFW_LOOPBACK_API_KEY not set; cluster background tasks disabled");
        }
    }

    // IDS engine moved to aifw-ids binary (see PR 5 / spec
    // 2026-04-26-process-hardening-and-ids-extraction-design.md). aifw-daemon
    // no longer holds an in-process IdsEngine. Configuration changes flow
    // through the IPC layer at /var/run/aifw/ids.sock, which aifw-api owns.

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
                        info!(
                            uid = uid.as_raw(),
                            gid = gid.as_raw(),
                            "dropped privileges to aifw user"
                        );
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

    // DNS blocklist scheduler — owned by the daemon, never the API process.
    aifw_core::dns_blocklists::migrate(&pool)
        .await
        .unwrap_or_else(|e| error!("dns_blocklists migration failed: {e}"));
    aifw_core::dns_blocklists::spawn_scheduler(pool.clone());
    info!("DNS blocklist scheduler started");

    // ACME cert renewal scheduler — also daemon-owned. Sweeps certs flagged
    // for auto-renewal whose expiry is within the renew window, plus fires
    // expiring-soon notifications for certs nearing expiry.
    // cluster_engine is passed so the scheduler skips renewal when BACKUP and
    // pushes renewed certs to secondary peers after each master issuance (#222).
    aifw_core::acme::migrate(&pool)
        .await
        .unwrap_or_else(|e| error!("acme migration failed: {e}"));
    aifw_core::acme_engine::spawn_scheduler(pool.clone(), Some(cluster_engine.clone()));
    info!("ACME renewal scheduler started");

    // Dynamic DNS scheduler — also daemon-owned. Sweeps every
    // ddns_config.poll_interval_secs and updates A/AAAA records via the
    // same provider credentials used for ACME DNS-01.
    aifw_core::ddns::migrate(&pool)
        .await
        .unwrap_or_else(|e| error!("ddns migration failed: {e}"));
    aifw_core::ddns::spawn_scheduler(pool.clone());
    info!("DDNS scheduler started");

    // Re-apply pf state-table limit so an operator-set value survives
    // reboot. Logs warn (not fatal) — pf may be in a transient state.
    aifw_core::pf_tuning::apply_on_boot(&pool).await;

    // Drift detect + auto-heal — runs AFTER all rule engines have populated
    // their anchors from the DB. Root cause of the historical "main ruleset
    // empty at boot" outages this was built for: pf_tuning used to load an
    // options-only file with `pfctl -m -f`, which merges options but
    // REPLACES the ruleset with the file's zero rules — wiping main on
    // every boot right before this heal reloaded it (found by the #533
    // functional harness; fixed in pf_tuning by patching pf.conf.aifw and
    // reloading the full file). The auto-heal stays as belt-and-braces for
    // any other path that leaves main without our hooks.
    //
    // Safe since v5.57.3: pf.conf.aifw no longer contains
    // `load anchor "aifw" from <file>`, so `pfctl -f` won't wipe the
    // anchor contents we just populated. The v5.55.1 regression that made
    // this detect-only no longer applies.
    //
    // Opt-out: set env var AIFW_NO_PF_AUTO_HEAL=1 to revert to detect-only.
    reconcile_pf_main().await;
    reconcile_dns_backend_detect(&pool).await;

    info!("daemon ready, waiting for signals");

    // Wait for shutdown signal
    shutdown_signal().await;

    info!("shutting down");

    // Note: we do NOT flush rules on shutdown — pf rules persist in the kernel
    // and should remain active while the daemon restarts or the API takes over.
    // Rules are only flushed when explicitly requested via the API.

    info!("AiFw daemon stopped");
    Ok(())
}

/// Current schedule gating state: (rule id, inside-window) for every active
/// rule that references a schedule, sorted for stable comparison (#537).
/// Returns an empty list on DB errors (logged) — comparison against the
/// previous tick then goes through apply_rules, whose own error handling
/// retries on the next tick.
async fn schedule_fingerprint(engine: &RuleEngine) -> Vec<(String, bool)> {
    let db = engine.db();
    let (rules, schedules) =
        match tokio::try_join!(db.list_active_rules(), db.list_schedule_specs()) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "schedule watcher: db read failed");
                return Vec::new();
            }
        };
    let now = chrono::Local::now().naive_local();
    let mut fp: Vec<(String, bool)> = rules
        .iter()
        .filter(|r| r.schedule_id.is_some())
        .map(|r| {
            (
                r.id.to_string(),
                aifw_common::schedule::rule_schedule_active(
                    r.schedule_id.as_deref(),
                    &schedules,
                    now,
                ),
            )
        })
        .collect();
    fp.sort_unstable();
    fp
}

/// Boot-time drift detection + auto-heal.
///
/// If the kernel pf main ruleset has lost (or never received) its aifw
/// anchor hooks, reload pf.conf.aifw ourselves so the anchors the rule
/// engines just populated are actually reachable. Without this,
/// pf_start failures at boot leave main empty, NAT + filter anchors
/// have rules nobody evaluates, and LAN outbound silently breaks.
///
/// Safe as of v5.57.3: pf.conf.aifw no longer contains
/// `load anchor "aifw" from <file>`, so `pfctl -f` loads/replaces main
/// without wiping anchor contents that apply_rules just wrote from the DB.
///
/// This replaces the v5.55.2 detect-only behavior. That detect-only
/// guard existed because v5.55.1 auto-reload had the twin bugs of
/// (a) probing pf as the aifw user without sudo (got "Operation not
/// permitted", treated as empty stdout, treated as drift), and
/// (b) pf.conf.aifw's `load anchor` line wiping anchors the daemon
/// had just populated. We fixed (a) by using sudo below, (b) by
/// removing the load-anchor line from the generated pf.conf.aifw in
/// aifw-setup. Both guardrails in place → auto-heal is the right
/// default again.
///
/// Opt-out: set env var `AIFW_NO_PF_AUTO_HEAL=1` for detect-only.
async fn reconcile_pf_main() {
    const PF_CONF: &str = "/usr/local/etc/aifw/pf.conf.aifw";

    if !std::path::Path::new(PF_CONF).exists() {
        info!("{PF_CONF} not present; skipping pf drift check");
        return;
    }

    // MUST use sudo — aifw user can't probe pf state directly.
    let out = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/sbin/pfctl", "-sn"])
        .output()
        .await;

    let (output_ok, stdout) = match out {
        Ok(o) if o.status.success() => (true, String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => {
            info!(
                "pf drift check: pfctl -sn failed (status {}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            (false, String::new())
        }
        Err(e) => {
            info!("pf drift check: could not spawn pfctl: {e}");
            (false, String::new())
        }
    };

    if !output_ok {
        // Can't tell — don't false-positive into "drift detected."
        return;
    }

    let has_hooks = stdout.contains("aifw-nat") || stdout.contains("anchor \"aifw\"");
    let auto_heal_disabled =
        pf_auto_heal_disabled(std::env::var("AIFW_NO_PF_AUTO_HEAL").ok().as_deref());

    if !has_hooks && auto_heal_disabled {
        error!(
            "pf drift check: main ruleset is MISSING aifw anchor hooks — \
             auto-heal disabled via AIFW_NO_PF_AUTO_HEAL; run `aifw reconcile` to reload from {PF_CONF}"
        );
        return;
    }

    if has_hooks {
        info!("pf drift check: main ruleset has aifw anchor hooks");
    } else {
        error!(
            "pf drift check: main ruleset is MISSING aifw anchor hooks — auto-healing by reloading {PF_CONF}"
        );
        let reload = tokio::process::Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-f", PF_CONF])
            .output()
            .await;
        match reload {
            Ok(o) if o.status.success() => {
                info!("pf drift check: auto-heal succeeded — {PF_CONF} loaded into main ruleset");
            }
            Ok(o) => {
                error!(
                    "pf drift check: auto-heal FAILED (status {}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return;
            }
            Err(e) => {
                error!("pf drift check: auto-heal could not spawn pfctl: {e}");
                return;
            }
        }
    }

    // A valid ruleset can still be present while packet filtering itself is
    // disabled. In that state `pfctl -sn` succeeds and the anchor check above
    // looks healthy, but traffic bypasses every rule. Only enable pf after the
    // ruleset is known to be valid, and preserve the detect-only opt-out.
    let status = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/sbin/pfctl", "-si"])
        .output()
        .await;
    match status {
        Ok(o) if o.status.success() && pf_status_is_disabled(&o.stdout) => {
            if auto_heal_disabled {
                error!(
                    "pf drift check: packet filter is DISABLED — auto-heal disabled via \
                     AIFW_NO_PF_AUTO_HEAL; run `pfctl -e` to enable it"
                );
                return;
            }

            let enable = tokio::process::Command::new("/usr/local/bin/sudo")
                .args(["/sbin/pfctl", "-e"])
                .output()
                .await;
            match enable {
                Ok(o) if o.status.success() => {
                    info!("pf drift check: packet filter was disabled; enabled it")
                }
                Ok(o) => error!(
                    "pf drift check: pfctl -e FAILED (status {}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => error!("pf drift check: could not spawn pfctl -e: {e}"),
            }
        }
        Ok(o) => {
            if !o.status.success() {
                info!(
                    "pf drift check: pfctl -si failed (status {}): {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
            }
        }
        Err(e) => info!("pf drift check: could not inspect pf status: {e}"),
    }
}

fn pf_auto_heal_disabled(value: Option<&str>) -> bool {
    value
        .map(|v| {
            !v.is_empty()
                && v != "0"
                && !v.eq_ignore_ascii_case("no")
                && !v.eq_ignore_ascii_case("false")
        })
        .unwrap_or(false)
}

fn pf_status_is_disabled(stdout: &[u8]) -> bool {
    String::from_utf8_lossy(stdout)
        .lines()
        .any(|line| line.trim_start().starts_with("Status: Disabled"))
}

/// Boot-time drift detection for rc.conf vs DB DNS backend.
/// Logs an error on mismatch. Does NOT auto-write rc.conf — too risky to
/// force-flip enable flags on boot without operator oversight.
async fn reconcile_dns_backend_detect(pool: &sqlx::SqlitePool) {
    let backend = sqlx::query_scalar::<_, String>(
        "SELECT value FROM dns_resolver_config WHERE key = 'backend'",
    )
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .unwrap_or_default();

    let (want_key, other_key) = match backend.as_str() {
        "rdns" => ("rdns_enable", "local_unbound_enable"),
        "unbound" => ("local_unbound_enable", "rdns_enable"),
        _ => return,
    };

    let want_val = sysrc_read(want_key).await;
    let other_val = sysrc_read(other_key).await;

    if want_val.as_deref() != Some("YES") {
        error!(
            "dns backend drift: db=`{backend}` but rc.conf {want_key} is `{}` — run `aifw reconcile` to fix",
            want_val.as_deref().unwrap_or("unset")
        );
    } else if other_val.as_deref() == Some("YES") {
        error!(
            "dns backend drift: db=`{backend}` but rc.conf also has {other_key}=YES — run `aifw reconcile` to fix"
        );
    } else {
        info!(%backend, "dns backend check: rc.conf matches db");
    }
}

async fn sysrc_read(key: &str) -> Option<String> {
    let out = tokio::process::Command::new("/usr/sbin/sysrc")
        .args(["-n", key])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
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

#[cfg(test)]
mod pf_reconcile_tests {
    use super::{pf_auto_heal_disabled, pf_status_is_disabled};

    #[test]
    fn auto_heal_opt_out_parses_false_values() {
        for value in [None, Some(""), Some("0"), Some("no"), Some("FALSE")] {
            assert!(
                !pf_auto_heal_disabled(value),
                "unexpected opt-out: {value:?}"
            );
        }
        assert!(pf_auto_heal_disabled(Some("1")));
        assert!(pf_auto_heal_disabled(Some("yes")));
    }

    #[test]
    fn disabled_status_is_detected_without_matching_enabled_status() {
        assert!(pf_status_is_disabled(
            b"Status: Disabled for 0 days 00:01:00\nDebug: Urgent\n"
        ));
        assert!(pf_status_is_disabled(b"  Status: Disabled\n"));
        assert!(!pf_status_is_disabled(
            b"Status: Enabled for 0 days 00:01:00\n"
        ));
    }
}
