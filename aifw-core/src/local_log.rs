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
//! immediate effect; aifw-daemon reconciles at boot and on 60s config-poll
//! changes (covers CLI edits and crash recovery).

use aifw_common::syslog::SyslogConfig;

use crate::sudo;

/// True when the config asks for local pf log storage to be off.
pub fn local_pf_log_disabled(cfg: &SyslogConfig) -> bool {
    cfg.enabled && cfg.disable_local
}

/// Reconcile pflogd with the config. Best-effort: failures are logged, not
/// fatal — the DB config stays authoritative and the daemon re-reconciles.
/// No-op on non-FreeBSD dev hosts.
pub async fn apply_local_log_policy(cfg: &SyslogConfig) {
    if !cfg!(target_os = "freebsd") {
        return;
    }
    if local_pf_log_disabled(cfg) {
        // Stop the file writer. "not running" is a normal outcome for an
        // idempotent reconcile, so only log other failures.
        match sudo::service("pflogd", "onestop").await {
            Ok(out) if !out.status.success() => {
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.contains("not running") {
                    tracing::warn!(error = %err.trim(), "failed to stop pflogd for disable_local");
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to run service pflogd onestop"),
            _ => tracing::info!("pflogd stopped (local pf log storage disabled)"),
        }
        // Keep pflog0 alive for tcpdump live capture + forwarding. Create
        // fails harmlessly when the interface already exists.
        if let Ok(out) = sudo::ifconfig("pflog0", "create", &[]).await
            && !out.status.success()
        {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("exists") {
                tracing::warn!(error = %err.trim(), "failed to create pflog0");
            }
        }
        match sudo::ifconfig("pflog0", "up", &[]).await {
            Ok(out) if !out.status.success() => {
                tracing::warn!(
                    error = %String::from_utf8_lossy(&out.stderr).trim(),
                    "failed to bring pflog0 up — pf log capture/forwarding may stop"
                );
            }
            Err(e) => tracing::warn!(error = %e, "failed to run ifconfig pflog0 up"),
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
                }
            }
            Err(e) => tracing::warn!(error = %e, "failed to run service pflogd onestart"),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_both_flags() {
        let mut cfg = SyslogConfig::default();
        assert!(!local_pf_log_disabled(&cfg));
        cfg.disable_local = true;
        assert!(!local_pf_log_disabled(&cfg), "disabled master switch wins");
        cfg.enabled = true;
        assert!(local_pf_log_disabled(&cfg));
    }
}
