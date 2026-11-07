//! HA start-up sequencing (#712).
//!
//! At boot `rc.d/aifw_carp_demote` (via `aifw-sudo-carp boot`) puts a
//! `boot` demotion hold on the node before any interface is configured. The
//! daemon then loads the `aifw-ha` anchor, configures pfsync and the CARP
//! vhids, and only releases the hold once pfsync's bulk update has finished
//! (or a timeout passes). Until then the peer keeps the VIPs, so a rebooted
//! primary can't preempt with an empty state table.

use aifw_core::ClusterEngine;
use aifw_core::carp::DemoteReason;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Minimum time the boot hold is kept, so links, ARP and the peer's view
/// of us settle before we compete for MASTER.
const MIN_HOLD: Duration = Duration::from_secs(10);
/// Release regardless after this long — a peer that never answers the bulk
/// request must not keep this node demoted forever.
const MAX_HOLD: Duration = Duration::from_secs(120);
/// When the kernel doesn't report `syncok`, wait this long instead.
const NO_SYNCOK_HOLD: Duration = Duration::from_secs(30);

/// Load the HA anchor and bring the kernel in line with the DB, then
/// release the boot hold in the background once state sync is ready.
pub async fn start(engine: Arc<ClusterEngine>) {
    if let Err(e) = engine.apply_ha_rules().await {
        tracing::error!(error = %e, "ha: loading the aifw-ha anchor failed");
    }
    match engine.reconcile_kernel_state().await {
        Ok(r) if !r.errors.is_empty() => tracing::warn!(
            failed = r.errors.len(),
            "ha: kernel reconcile finished with errors"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "ha: kernel reconcile failed"),
    }
    scrub_legacy_vip_aliases(&engine).await;
    tokio::spawn(release_boot_hold(engine));
}

async fn release_boot_hold(engine: Arc<ClusterEngine>) {
    if !aifw_core::carp::held_reasons()
        .await
        .contains(&DemoteReason::Boot)
    {
        return;
    }
    let pfsync_configured = matches!(engine.get_pfsync().await, Ok(Some(p)) if p.enabled);
    let started = Instant::now();
    tracing::info!(
        pfsync_configured,
        "ha: holding boot demotion until state sync is ready"
    );
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let elapsed = started.elapsed();
        let syncok = aifw_core::carp::kernel_view()
            .await
            .pfsync
            .and_then(|p| p.syncok);
        if boot_hold_ready(pfsync_configured, syncok, elapsed) {
            match aifw_core::carp::undemote(DemoteReason::Boot).await {
                Ok(()) => tracing::info!(
                    waited_secs = elapsed.as_secs(),
                    ?syncok,
                    "ha: boot demotion released"
                ),
                Err(e) => tracing::error!(error = %e, "ha: releasing boot demotion failed"),
            }
            return;
        }
    }
}

/// Pure release decision for the boot hold.
fn boot_hold_ready(pfsync_configured: bool, syncok: Option<bool>, elapsed: Duration) -> bool {
    if elapsed >= MAX_HOLD {
        return true;
    }
    if elapsed < MIN_HOLD {
        return false;
    }
    if !pfsync_configured {
        return true;
    }
    match syncok {
        Some(true) => true,
        Some(false) => false,
        None => elapsed >= NO_SYNCOK_HOLD,
    }
}

/// Older setups wrote the CARP VIPs (password included) into
/// `ifconfig_<if>_aliases` in the world-readable rc.conf. That brings the
/// VIPs up in `netif`, before pf and pfsync, and leaks the password. The
/// daemon now owns VIP creation, so drop alias lines that only carry CARP
/// VIPs. Mixed lines (operator aliases too) are left alone with a warning.
async fn scrub_legacy_vip_aliases(engine: &ClusterEngine) {
    let Ok(vips) = engine.list_carp_vips().await else {
        return;
    };
    let mut ifaces: Vec<&str> = vips.iter().map(|v| v.interface.0.as_str()).collect();
    ifaces.sort_unstable();
    ifaces.dedup();
    for iface in ifaces {
        let key = format!("ifconfig_{iface}_aliases");
        let Ok(out) = tokio::process::Command::new("sysrc")
            .args(["-n", &key])
            .output()
            .await
        else {
            continue;
        };
        if !out.status.success() {
            continue; // not set
        }
        let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
        match classify_aliases(&value) {
            AliasLine::OnlyCarp => {
                let res = aifw_core::sudo::sysrc(&["-x", &key]).await;
                if aifw_core::sudo::warn_on_fail(&format!("ha: removing legacy {key}"), &res) {
                    tracing::info!(key, "ha: removed legacy CARP aliases from rc.conf");
                }
            }
            AliasLine::Mixed => tracing::warn!(
                key,
                "ha: rc.conf aliases mix CARP VIPs with other addresses; \
                 remove the `vhid` entries by hand (they contain the CARP password)"
            ),
            AliasLine::NoCarp => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AliasLine {
    OnlyCarp,
    Mixed,
    NoCarp,
}

/// Split an `ifconfig_<if>_aliases` value into its `inet`/`inet6` entries
/// and classify them by whether they carry a `vhid`.
fn classify_aliases(value: &str) -> AliasLine {
    let mut entries: Vec<Vec<&str>> = Vec::new();
    for w in value.split_whitespace() {
        if w == "inet" || w == "inet6" || entries.is_empty() {
            entries.push(vec![w]);
        } else if let Some(last) = entries.last_mut() {
            last.push(w);
        }
    }
    let carp = entries.iter().filter(|e| e.contains(&"vhid")).count();
    match (carp, entries.len()) {
        (0, _) => AliasLine::NoCarp,
        (c, n) if c == n => AliasLine::OnlyCarp,
        _ => AliasLine::Mixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_hold_waits_for_syncok() {
        let s = Duration::from_secs;
        assert!(!boot_hold_ready(true, Some(true), s(2)), "min hold");
        assert!(boot_hold_ready(true, Some(true), s(11)));
        assert!(!boot_hold_ready(true, Some(false), s(60)));
        assert!(boot_hold_ready(true, Some(false), s(121)), "max hold");
        assert!(!boot_hold_ready(true, None, s(20)));
        assert!(boot_hold_ready(true, None, s(31)));
        assert!(boot_hold_ready(false, None, s(11)));
    }

    #[test]
    fn classifies_alias_lines() {
        assert_eq!(
            classify_aliases(
                "inet vhid 1 advskew 0 advbase 1 pass x 10.0.0.1/24 inet vhid 2 advskew 0 advbase 1 pass x 10.0.1.1/24"
            ),
            AliasLine::OnlyCarp
        );
        assert_eq!(
            classify_aliases("inet vhid 1 pass x 10.0.0.1/24 inet 10.0.0.50/32"),
            AliasLine::Mixed
        );
        assert_eq!(classify_aliases("inet 10.0.0.50/32"), AliasLine::NoCarp);
        assert_eq!(classify_aliases(""), AliasLine::NoCarp);
    }
}
