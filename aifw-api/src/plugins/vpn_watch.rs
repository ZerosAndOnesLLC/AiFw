//! `VpnEvent` bridge: polls WireGuard peers and IPsec tunnels and
//! dispatches up/down transitions. There is no event stream for either —
//! `wg show` and `swanctl --list-sas` are snapshots — so state is diffed
//! between polls.

use std::collections::HashMap;
use std::time::Duration;

use aifw_common::VpnStatus;
use aifw_plugins::{HookEvent, HookEventData, HookPoint};

use crate::AppState;

const POLL_EVERY: Duration = Duration::from_secs(30);
/// A WireGuard session is valid for 180 s after its last handshake
/// (REJECT_AFTER_TIME); a peer with no handshake inside that window has no
/// usable session.
const WG_SESSION_SECS: i64 = 180;

/// One VPN endpoint's observed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VpnObs {
    /// Stable identity across polls
    pub key: String,
    pub kind: &'static str,
    pub tunnel: String,
    pub peer: Option<String>,
    pub up: bool,
    pub detail: Option<String>,
}

/// Observations whose up/down state changed since `prev`. Endpoints seen
/// for the first time are baseline, not events.
pub(crate) fn diff_vpn<'a>(prev: &HashMap<String, bool>, cur: &'a [VpnObs]) -> Vec<&'a VpnObs> {
    cur.iter()
        .filter(|o| prev.get(&o.key).is_some_and(|was| *was != o.up))
        .collect()
}

async fn observe(state: &AppState) -> Vec<VpnObs> {
    let mut out = Vec::new();

    match state.vpn_engine.list_wg_tunnels().await {
        Ok(tunnels) => {
            for t in tunnels.iter().filter(|t| t.status == VpnStatus::Up) {
                let status = match state.vpn_engine.tunnel_status(t.id).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(tunnel = %t.name, error = %e, "plugins: wg status failed");
                        continue;
                    }
                };
                let iface = &t.interface.0;
                let running = status["running"].as_bool().unwrap_or(false);
                out.push(VpnObs {
                    key: format!("wg:{}", t.id),
                    kind: "wireguard",
                    tunnel: t.name.clone(),
                    peer: None,
                    up: running,
                    detail: Some(format!("interface {iface}")),
                });
                if !running {
                    continue;
                }
                let names: HashMap<String, String> =
                    match state.vpn_engine.list_wg_peers(t.id).await {
                        Ok(peers) => peers.into_iter().map(|p| (p.public_key, p.name)).collect(),
                        Err(_) => HashMap::new(),
                    };
                for p in status["peers"].as_array().into_iter().flatten() {
                    let Some(pk) = p["public_key"].as_str() else {
                        continue;
                    };
                    let ago = p["latest_handshake_secs_ago"].as_i64().unwrap_or(-1);
                    let up = (0..=WG_SESSION_SECS).contains(&ago);
                    let endpoint = p["endpoint"].as_str().unwrap_or("unknown endpoint");
                    out.push(VpnObs {
                        key: format!("wg:{}:{pk}", t.id),
                        kind: "wireguard",
                        tunnel: t.name.clone(),
                        peer: Some(names.get(pk).cloned().unwrap_or_else(|| pk.to_string())),
                        up,
                        detail: Some(if ago < 0 {
                            format!("{endpoint}, no handshake yet")
                        } else {
                            format!("{endpoint}, last handshake {ago}s ago")
                        }),
                    });
                }
            }
        }
        Err(e) => tracing::debug!(error = %e, "plugins: listing WireGuard tunnels failed"),
    }

    let names: HashMap<uuid::Uuid, (String, bool)> = match state.ipsec_engine.list_tunnels().await {
        Ok(t) => t.into_iter().map(|t| (t.id, (t.name, t.enabled))).collect(),
        Err(e) => {
            tracing::debug!(error = %e, "plugins: listing IPsec tunnels failed");
            return out;
        }
    };
    if names.values().any(|(_, enabled)| *enabled) {
        match state.ipsec_engine.live_status().await {
            Ok(live) => {
                for s in live {
                    let Some((name, true)) = names.get(&s.tunnel_id) else {
                        continue;
                    };
                    out.push(VpnObs {
                        key: format!("ipsec:{}", s.tunnel_id),
                        kind: "ipsec",
                        tunnel: name.clone(),
                        peer: None,
                        up: s.ike_state == "ESTABLISHED",
                        detail: Some(match &s.remote_host {
                            Some(h) => format!("IKE {} with {h}", s.ike_state),
                            None => format!("IKE {}", s.ike_state),
                        }),
                    });
                }
            }
            Err(e) => tracing::debug!(error = %e, "plugins: IPsec status failed"),
        }
    }
    out
}

fn event(o: &VpnObs) -> HookEvent {
    HookEvent {
        hook: HookPoint::VpnEvent,
        data: HookEventData::Vpn {
            kind: o.kind.to_string(),
            tunnel_name: o.tunnel.clone(),
            peer: o.peer.clone(),
            action: if o.up { "up" } else { "down" }.to_string(),
            detail: o.detail.clone(),
        },
    }
}

/// Poll VPN state while a running plugin subscribes to `VpnEvent`.
pub(crate) fn spawn(state: AppState) {
    tokio::spawn(async move {
        let mut prev: Option<HashMap<String, bool>> = None;
        let mut tick = tokio::time::interval(POLL_EVERY);
        loop {
            tick.tick().await;
            if !state.plugin_manager.wants(HookPoint::VpnEvent) {
                prev = None;
                continue;
            }
            let cur = observe(&state).await;
            if let Some(p) = &prev {
                for o in diff_vpn(p, &cur) {
                    state.plugin_manager.dispatch(event(o)).await;
                }
            }
            prev = Some(cur.into_iter().map(|o| (o.key, o.up)).collect());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(key: &str, up: bool) -> VpnObs {
        VpnObs {
            key: key.into(),
            kind: "wireguard",
            tunnel: "t".into(),
            peer: None,
            up,
            detail: None,
        }
    }

    #[test]
    fn only_state_changes_are_events() {
        let prev: HashMap<String, bool> = [("a".to_string(), true), ("b".to_string(), false)]
            .into_iter()
            .collect();
        let cur = vec![obs("a", false), obs("b", false), obs("c", true)];
        let changed = diff_vpn(&prev, &cur);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].key, "a");
        assert!(!changed[0].up);
    }

    #[test]
    fn first_poll_is_baseline() {
        let cur = vec![obs("a", true)];
        assert!(diff_vpn(&HashMap::new(), &cur).is_empty());
    }
}
