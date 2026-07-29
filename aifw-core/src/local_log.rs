//! Local log storage policy for the remote-syslog `disable_local` toggle.
//!
//! When "stop storing logs locally" is active alongside remote forwarding,
//! the pf packet-log file writer (`pflogd`) is stopped while the `pflog0`
//! interface is kept up, so live capture (Blocked page) and remote
//! forwarding keep working. Re-enabling local storage restarts `pflogd`.
//!
//! App-log files are handled separately: the tracing stdout layer is gated
//! by `aifw_common::syslog::LocalStorageGate`, since `/var/log/aifw/*.log`
//! are just `daemon(8)` stdout redirects.
//!
//! Callers: aifw-api applies on every settings PUT / config restore for
//! immediate effect; aifw-daemon reconciles at boot, on 60s config-poll
//! changes, after failed attempts, and enforces the stopped state each tick
//! (covers CLI edits, crash recovery, and external pflogd restarts).

use aifw_common::syslog::SyslogConfig;

use crate::sudo;

/// True when the config asks for local pf log storage to be off. Requires
/// pf forwarding to be enabled too — the same "logs must go somewhere"
/// guard the app-log gate has: stopping the pf log file while pf logs are
/// not forwarded would leave packet history nowhere but the small in-memory
/// buffer.
pub fn local_pf_log_disabled(cfg: &SyslogConfig) -> bool {
    cfg.enabled && cfg.disable_local && cfg.pf_enabled
}

/// Reconcile pflogd with the config. Best-effort: failures are logged, not
/// fatal — the DB config stays authoritative and the daemon retries.
/// Returns `true` when every required command succeeded (callers use this
/// to decide whether to retry on the next tick). No-op `true` on
/// non-FreeBSD dev hosts.
pub async fn apply_local_log_policy(cfg: &SyslogConfig) -> bool {
    if !cfg!(target_os = "freebsd") {
        return true;
    }
    let mut ok = true;
    if local_pf_log_disabled(cfg) {
        // Stop the file writer. "not running" is a normal outcome for an
        // idempotent reconcile, so only log other failures.
        match sudo::service("pflogd", "onestop").await {
            Ok(out) if !out.status.success() => {
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.contains("not running") {
                    tracing::warn!(error = %err.trim(), "failed to stop pflogd for disable_local");
                    ok = false;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to run service pflogd onestop");
                ok = false;
            }
            _ => tracing::info!("pflogd stopped (local pf log storage disabled)"),
        }
        // Keep pflog0 alive for tcpdump live capture + forwarding. Create
        // fails harmlessly when the interface already exists.
        match sudo::ifconfig("pflog0", "create", &[]).await {
            Ok(out) if !out.status.success() => {
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.contains("exists") {
                    tracing::warn!(error = %err.trim(), "failed to create pflog0");
                    ok = false;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to run ifconfig pflog0 create");
                ok = false;
            }
            _ => {}
        }
        match sudo::ifconfig("pflog0", "up", &[]).await {
            Ok(out) if !out.status.success() => {
                tracing::warn!(
                    error = %String::from_utf8_lossy(&out.stderr).trim(),
                    "failed to bring pflog0 up — pf log capture/forwarding may stop"
                );
                ok = false;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to run ifconfig pflog0 up");
                ok = false;
            }
            _ => {}
        }
    } else {
        // Restore the normal file writer. "already running" is the normal
        // idempotent outcome.
        match sudo::service("pflogd", "onestart").await {
            Ok(out) if !out.status.success() => {
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.contains("already running") {
                    tracing::warn!(error = %err.trim(), "failed to start pflogd");
                    ok = false;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to run service pflogd onestart");
                ok = false;
            }
            _ => {}
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_forwarding_and_toggle_and_pf_category() {
        let mut cfg = SyslogConfig::default();
        assert!(!local_pf_log_disabled(&cfg));
        cfg.disable_local = true;
        assert!(!local_pf_log_disabled(&cfg), "disabled master switch wins");
        cfg.enabled = true;
        assert!(
            !local_pf_log_disabled(&cfg),
            "pf logs not forwarded — the file must keep being written"
        );
        cfg.pf_enabled = true;
        assert!(local_pf_log_disabled(&cfg));
    }
}
