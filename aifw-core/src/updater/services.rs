//! Service restart / reboot orchestration and embedded-script upkeep.

use tokio::process::Command;
use tracing::{debug, info, warn};

use super::*;

/// Services that may have had their rc.d script replaced by an update and
/// therefore need a restart for the new script to take effect. Order
/// matters for aifw_api (last) so HTTP stays up as long as possible.
/// Used by the synchronous CLI path; the API path delegates to
/// /usr/local/libexec/aifw-restart.sh which keeps its own ordering in
/// sync with this list.
pub(super) const RESTARTABLE_SERVICES: &[&str] = &[
    "rdns",
    "rdhcpd",
    "rtime",
    "trafficcop",
    "aifw_daemon",
    // aifw_ids must be restarted before aifw_api — aifw_api REQUIREs aifw_ids,
    // and the API connects to the IDS IPC socket on startup.
    "aifw_ids",
    "aifw_api",
    // Watchdog last so it doesn't observe transient down-states during
    // the bounce window and redundantly try to start things.
    "aifw_watchdog",
];

pub(super) const RESTART_SCRIPT: &str = "/usr/local/libexec/aifw-restart.sh";

/// Services we own. `aifw_firstboot` is excluded — it's a one-shot that
/// disables itself after the first run and must not be re-enabled here.
pub(super) const OWNED_RCVARS: &[&str] = &[
    "aifw_daemon_enable",
    "aifw_ids_enable",
    "aifw_api_enable",
    "aifw_watchdog_enable",
];

/// Write the embedded libexec scripts to /usr/local/libexec/ if missing or
/// stale. Idempotent. Called from aifw-api startup so the appliance
/// self-bootstraps the bouncer + watchdog scripts even when the install
/// was driven by an old updater that didn't iterate `libexec/`.
///
/// Compares content first to avoid touching the file on every startup
/// (mtime churn matters for log-watching tools). Uses sudo because
/// /usr/local/libexec is root-owned and aifw-api runs as the aifw user.
pub async fn ensure_libexec_scripts() {
    write_embedded_script("aifw-restart.sh", EMBEDDED_RESTART_SH).await;
    write_embedded_script("aifw-watchdog.sh", EMBEDDED_WATCHDOG_SH).await;
    // Bootstrap the narrow-grant sudo helpers (#204 / SEC-C2). These ship
    // in the tarball overlay AND are embedded here so an in-place upgrade
    // from a pre-#204 box — which has no `aifw-sudo-*` on disk and no
    // narrow grants in sudoers — still ends up with the helpers in place.
    // write_embedded_script falls back to direct `sudo /usr/bin/install`
    // when the narrow `aifw-sudo-install` helper isn't on disk yet.
    for (name, content) in EMBEDDED_SUDO_HELPERS {
        write_embedded_script(name, content).await;
    }
}

pub(super) async fn write_embedded_script(name: &str, content: &str) {
    let path = format!("/usr/local/libexec/{}", name);
    if let Ok(existing) = tokio::fs::read_to_string(&path).await
        && existing == content
        && is_executable(&path).await
    {
        // Matching content alone isn't enough to skip: ISO installs before
        // v5.97.6 laid these down mode 644 (#469), and sudo reports a
        // non-executable helper as "command not found". Reinstalling with
        // -m 755 below is the only self-heal path such a box has.
        return;
    }
    // Stage in /tmp first, then install -m 755 so the write is atomic
    // and gets correct ownership/perms regardless of who runs us.
    let tmp = format!("/tmp/.{}.aifw-bootstrap", name);
    if tokio::fs::write(&tmp, content).await.is_err() {
        warn!(name, "failed to stage embedded script");
        return;
    }
    if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", "/usr/local/libexec"]).await) {
        warn!(name, error = %err, "bootstrap: mkdir /usr/local/libexec failed");
    }
    // Prefer the narrow `aifw-sudo-install` helper when it's already on
    // disk. Otherwise fall back to direct `sudo /usr/bin/install`, which
    // the broad pre-#204 sudoers grant permits. This is the bootstrap path
    // used on first upgrade from an old box; once the helpers exist on
    // disk, every subsequent boot takes the narrow path.
    let aifw_sudo_install_exists =
        std::path::Path::new("/usr/local/libexec/aifw-sudo-install").exists();
    let result = if aifw_sudo_install_exists {
        crate::sudo::install(Some("755"), None, None, &tmp, &path).await
    } else {
        Command::new("/usr/local/bin/sudo")
            .args(["/usr/bin/install", "-m", "755", &tmp, &path])
            .output()
            .await
    };
    if let Err(e) = tokio::fs::remove_file(&tmp).await {
        debug!(name, path = %tmp, error = %e, "failed to remove staged bootstrap script");
    }
    match result {
        Ok(o) if o.status.success() => info!(name, "libexec script bootstrapped"),
        Ok(o) => warn!(name, stderr = %String::from_utf8_lossy(&o.stderr), "install failed"),
        Err(e) => warn!(name, error = %e, "install errored"),
    }
}

/// True when any execute bit is set. The helpers are root-owned and run
/// via sudo, so a single x bit anywhere is what sudo's path resolution
/// requires; a 644 file fails with "command not found".
pub(super) async fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::metadata(path)
        .await
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// SEC-C1: ensure_sudoers_* functions removed.
//
// The previous design migrated the runtime sudoers.d/aifw file from this
// process via the aifw-sudo-install helper. That made the helper able to
// install arbitrary content into the sudoers file (PE primitive). The
// helper allowlist no longer accepts /usr/local/etc/sudoers.d/aifw; the
// sudoers file is now written by a root-running installer step
// (deploy.sh / aifw-setup) and is immutable at aifw-uid runtime.

/// Ensure each AiFw service has its rcvar set to YES in /etc/rc.conf.
///
/// Appliances upgraded from versions predating a service (notably aifw_ids
/// added in v5.76.0) only got the binary + rc.d script installed by the
/// updater — the rcvar stayed unset, so `service aifw_ids restart` was a
/// silent no-op and the IPC socket never came up. Idempotent: `sysrc`
/// rewrites the line whether or not it exists.
pub async fn ensure_rcvars() {
    for var in OWNED_RCVARS {
        let arg = format!("{}=YES", var);
        if let Some(err) = step_failure(&crate::sudo::sysrc(&[&arg]).await) {
            warn!(rcvar = var, error = %err, "failed to set rcvar — service restart may be a silent no-op");
        }
    }
}

/// Restart AiFw services after an install or rollback. Spawns the
/// /usr/local/libexec/aifw-restart.sh driver detached via daemon(8) and
/// returns immediately so the HTTP response can leave the box.
///
/// The previous implementation ran the bounce loop inside aifw-api
/// itself via tokio::spawn. When the loop reached `service aifw_api
/// restart`, the rc.d stop killed aifw-api and took the loop with it —
/// any failure during the start half had no driver left to retry, and
/// the appliance would sit with the API down until an operator noticed.
/// Detaching via daemon(8) reparents the script to init, so aifw-api
/// dying mid-iteration cannot kill the bounce.
///
/// Falls back to the in-process loop on appliances that don't yet have
/// the libexec script (mid-upgrade from a pre-detached version). The
/// fragility we're fixing beats no restart at all.
pub async fn restart_services() {
    if std::path::Path::new(RESTART_SCRIPT).exists() && spawn_detached_restart().await.is_ok() {
        return;
    }
    // Either the libexec script isn't present (mid-transitional upgrade)
    // or sudo refused (older sudoers without /usr/sbin/daemon). Fall
    // back to the in-process loop. It has the bounce-self-last bug, but
    // that's strictly better than silently doing nothing — which is
    // what the previous code did when sudo refused.
    warn!("falling back to in-process restart loop");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        ensure_rcvars().await;
        for svc in RESTARTABLE_SERVICES {
            restart_one(svc).await;
        }
    });
}

/// Try to spawn /usr/local/libexec/aifw-restart.sh detached via daemon(8).
/// Returns Err when sudo refuses or the spawn itself fails so the
/// caller can fall back to the in-process loop instead of silently
/// pretending the bounce happened.
pub(super) async fn spawn_detached_restart() -> Result<(), String> {
    // .output() (not .spawn() + .wait()) so we observe sudo's exit
    // status. sudo returns non-zero when NOPASSWD doesn't cover the
    // command — the tell-tale signature of an older sudoers file
    // without /usr/sbin/daemon. Without checking, we'd log "restart
    // driver detached" while nothing happened.
    let result = Command::new("/usr/local/bin/sudo")
        .args([
            "-n", // never prompt; fail fast if NOPASSWD doesn't apply
            "/usr/sbin/daemon",
            "-f",
            "-o",
            "/var/log/aifw/restart.log",
            RESTART_SCRIPT,
        ])
        .output()
        .await
        .map_err(|e| format!("spawn: {}", e))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        warn!(
            stderr = %stderr,
            "sudo refused detached restart spawn"
        );
        return Err(format!("sudo exit={:?}", result.status.code()));
    }
    info!("restart driver detached");
    Ok(())
}

/// Restart AiFw services synchronously (blocks until restart completes, use from CLI).
pub async fn restart_services_sync() {
    ensure_rcvars().await;
    for svc in RESTARTABLE_SERVICES {
        restart_one(svc).await;
    }
}

/// Schedule a system reboot via FreeBSD's `shutdown(8)`. The +1 syntax
/// gives the HTTP response a full minute to flush and gives the operator
/// a window to cancel via console (`shutdown -c`). `shutdown` returns
/// immediately after registering with init; we await the sudo wrapper
/// just to reap it.
///
/// sudoers (set in deploy.sh + aifw-setup) allows `/sbin/shutdown` for
/// the aifw user without a password. We deliberately don't go through
/// `daemon(8)` here — that would need a separate sudoers entry, and
/// shutdown is already detached from our process tree by init.
/// shutdown(8) invocation for an operator-requested reboot. `+10s` is
/// load-bearing (#627): the sudoers grant is `/sbin/shutdown -r +10s *`
/// exactly — any other grace period is refused by sudo. Keep in sync with
/// the grant in aifw-setup's sudoers content.
pub const SHUTDOWN_REBOOT_ARGS: [&str; 4] = [
    "/sbin/shutdown",
    "-r",
    "+10s",
    "AiFw: operator-requested reboot",
];

/// Schedule a full system reboot via shutdown(8) (10-second grace).
pub async fn schedule_reboot() -> Result<(), UpdaterError> {
    // #627: a refused shutdown must be an error, not a warning — the UI
    // shows a "system is going down" overlay on success, and a silent
    // failure strands the operator on it forever (live appliance, during
    // the first guided OS upgrade).
    let output = Command::new("/usr/local/bin/sudo")
        .args(SHUTDOWN_REBOOT_ARGS)
        .output()
        .await
        .map_err(|e| UpdaterError::Install(format!("schedule reboot: {}", e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(UpdaterError::Install(format!(
            "shutdown was refused ({}): {}",
            output.status,
            stderr.trim()
        )));
    }
    info!("reboot scheduled (+10s)");
    Ok(())
}

/// Restart a single service with a hard 60-second timeout. If the underlying
/// `service X restart` hangs (e.g. graceful-drain stuck, daemon(8) supervisor
/// waiting on a child whose tokio runtime won't exit), we move on rather than
/// wedge the entire upgrade. The next restart cycle's `start_precmd` pkill
/// will reap any orphans we leave behind.
pub(super) async fn restart_one(svc: &str) {
    let cmd = crate::sudo::service(svc, "restart");
    match tokio::time::timeout(std::time::Duration::from_secs(60), cmd).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => warn!(service = svc, error = %e, "service restart errored"),
        Err(_) => warn!(
            service = svc,
            "service restart timed out after 60s — moving on"
        ),
    }
}
