//! Role-dependent services follow the live CARP role (#712 review H1/H2).
//!
//! In a cluster only the MASTER should:
//! - initiate IPsec (the BACKUP renders tunnels `start_action = none`), and
//! - run WireGuard (both nodes hold the same private key; a standby with a
//!   configured endpoint would pull the remote peer away from the master).
//!
//! This loop re-reads the kernel every [`INTERVAL`] and converges both,
//! instead of trusting a one-shot startup check plus role-change events:
//! an event lost while the API was still starting used to leave a MASTER
//! with IPsec passive and WireGuard down until the next failover. The
//! daemon's role-change POST just wakes the loop early via [`nudge`].

use crate::AppState;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Notify;

const INTERVAL: Duration = Duration::from_secs(2);

fn wake() -> &'static Notify {
    static WAKE: OnceLock<Notify> = OnceLock::new();
    WAKE.get_or_init(Notify::new)
}

/// Re-evaluate now (called on a role-change event).
pub(crate) fn nudge() {
    wake().notify_one();
}

/// What the role-dependent services should be doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Not clustered, or CARP MASTER on every vhid: run everything.
    Active,
    /// CARP BACKUP: IPsec passive, WireGuard down.
    Standby,
}

/// Pure decision: the mode for the kernel's aggregate CARP state, or `None`
/// to keep the current one (INIT / split / not yet configured mid-change).
/// On the very first evaluation an undecided state counts as standby — the
/// safe side; the loop flips to active as soon as the node is MASTER.
pub(crate) fn decide(clustered: bool, aggregate: &str, current: Option<Mode>) -> Option<Mode> {
    if !clustered {
        return Some(Mode::Active);
    }
    match aggregate {
        "master" => Some(Mode::Active),
        "backup" => Some(Mode::Standby),
        _ if current.is_none() => Some(Mode::Standby),
        _ => None,
    }
}

/// Spawn the convergence loop.
pub(crate) fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut current: Option<Mode> = None;
        loop {
            current = tick(&state, current).await;
            tokio::select! {
                _ = tokio::time::sleep(INTERVAL) => {}
                _ = wake().notified() => {}
            }
        }
    });
}

async fn tick(state: &AppState, current: Option<Mode>) -> Option<Mode> {
    let clustered = match state.cluster_engine.list_carp_vips().await {
        Ok(v) => !v.is_empty(),
        Err(e) => {
            tracing::warn!(error = %e, "ha: role sync could not read CARP VIPs");
            return current;
        }
    };
    let aggregate = aifw_core::carp::kernel_view().await.aggregate_state();
    let Some(want) = decide(clustered, aggregate, current) else {
        return current;
    };
    if Some(want) == current {
        return current;
    }
    tracing::info!(
        ?want,
        aggregate,
        clustered,
        "ha: applying role to IPsec / WireGuard"
    );

    if state.ipsec_engine.set_standby(want == Mode::Standby)
        && let Err(e) = state.ipsec_engine.apply_all().await
    {
        tracing::warn!(error = %e, "ha: IPsec re-render for role change failed");
    }

    // Non-clustered nodes start their tunnels at API startup; only a
    // cluster role change moves WireGuard.
    if clustered {
        let res = match want {
            Mode::Active => state.vpn_engine.reconfigure_for_master().await,
            Mode::Standby => state.vpn_engine.deconfigure_for_backup().await,
        };
        match res {
            Ok(n) => tracing::info!(?want, tunnels = n, "ha: WireGuard follows the CARP role"),
            Err(e) => tracing::warn!(?want, error = %e, "ha: WireGuard role change failed"),
        }
    }
    Some(want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_follows_aggregate_and_holds_on_uncertain_states() {
        assert_eq!(decide(false, "none", None), Some(Mode::Active));
        assert_eq!(
            decide(false, "backup", Some(Mode::Standby)),
            Some(Mode::Active)
        );
        assert_eq!(decide(true, "master", None), Some(Mode::Active));
        assert_eq!(
            decide(true, "backup", Some(Mode::Active)),
            Some(Mode::Standby)
        );
        // first evaluation while CARP is still settling: safe side
        assert_eq!(decide(true, "init", None), Some(Mode::Standby));
        assert_eq!(decide(true, "none", None), Some(Mode::Standby));
        // later: hold whatever is current
        assert_eq!(decide(true, "init", Some(Mode::Active)), None);
        assert_eq!(decide(true, "split", Some(Mode::Active)), None);
    }
}
