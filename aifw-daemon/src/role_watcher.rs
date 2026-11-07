//! Polls the kernel CARP state every 1s and notifies the API of role
//! transitions, per VHID and for the node as a whole (#712).
//!
//! Each VHID that changes state is reported with its own `vhid`. The node's
//! aggregate role — `primary` only when every VHID is MASTER, `secondary`
//! when every VHID is BACKUP, `split` when they disagree — is reported with
//! `vhid = 0`; that is the event the API acts on (WireGuard, IPsec standby,
//! failover history).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct RoleWatcher {
    api_base: String,
    api_key: String,
    auth_warned: AtomicBool,
}

/// One observation of the kernel: aggregate role + per-VHID state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub aggregate: String,
    pub vhids: BTreeMap<u8, String>,
}

impl Snapshot {
    pub(crate) fn from_view(view: &aifw_core::carp::KernelCarpView) -> Self {
        Self {
            aggregate: canonical_role(view.aggregate_state()),
            vhids: view
                .vhids
                .iter()
                .map(|v| (v.vhid, canonical_role(&v.state)))
                .collect(),
        }
    }
}

/// Transitions between two observations, as `(vhid, from, to)`; the
/// aggregate is `vhid = 0` and comes last.
pub(crate) fn transitions(prev: &Snapshot, next: &Snapshot) -> Vec<(u8, String, String)> {
    let mut out = Vec::new();
    let vhids: std::collections::BTreeSet<u8> = prev
        .vhids
        .keys()
        .chain(next.vhids.keys())
        .copied()
        .collect();
    for vhid in vhids {
        let from = prev
            .vhids
            .get(&vhid)
            .cloned()
            .unwrap_or_else(|| "none".into());
        let to = next
            .vhids
            .get(&vhid)
            .cloned()
            .unwrap_or_else(|| "none".into());
        if from != to {
            out.push((vhid, from, to));
        }
    }
    if prev.aggregate != next.aggregate {
        out.push((0, prev.aggregate.clone(), next.aggregate.clone()));
    }
    out
}

impl RoleWatcher {
    pub fn new(api_base: String, api_key: String) -> Self {
        Self {
            api_base,
            api_key,
            auth_warned: AtomicBool::new(false),
        }
    }

    pub async fn run(self) {
        let mut last: Option<Snapshot> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // #317: loopback calls are pinned to the local API certificate.
        let loopback = aifw_core::peer_tls::LocalApiClient::new(Duration::from_secs(5));

        loop {
            tick.tick().await;
            let now = Snapshot::from_view(&aifw_core::carp::kernel_view().await);
            if let Some(prev) = &last {
                for (vhid, from, to) in transitions(prev, &now) {
                    if vhid == 0 {
                        tracing::info!(%from, %to, "ha: node CARP role changed");
                    } else {
                        tracing::info!(vhid, %from, %to, "ha: CARP vhid changed state");
                    }
                    self.post(&loopback, vhid, &from, &to).await;
                }
            }
            last = Some(now);
        }
    }

    async fn post(
        &self,
        loopback: &aifw_core::peer_tls::LocalApiClient,
        vhid: u8,
        from: &str,
        to: &str,
    ) {
        let body = serde_json::json!({"from": from, "to": to, "vhid": vhid});
        let url = format!("{}/api/v1/cluster/internal/role-changed", self.api_base);
        let client = match loopback.get() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "ha: role_watcher http client");
                return;
            }
        };
        match client
            .post(&url)
            .header("Authorization", format!("ApiKey {}", self.api_key))
            .json(&body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {}
            Ok(r) if r.status().as_u16() == 401 => {
                if !self.auth_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "ha: role_watcher loopback auth failed \
                         (AIFW_LOOPBACK_API_KEY set but not registered)"
                    );
                }
            }
            Ok(r) => tracing::warn!(status = ?r.status(), "ha: role_watcher post rejected"),
            Err(e) => tracing::warn!(error = %e, "ha: role_watcher post failed"),
        }
    }
}

/// Canonical (`primary`/`secondary`) form of a CARP state, passing anything
/// else (`init`, `split`, `none`) through — one vocabulary for history and
/// WS consumers.
pub(crate) fn canonical_role(raw: &str) -> String {
    match raw {
        "master" => "primary".into(),
        "backup" => "secondary".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(view: &str) -> Snapshot {
        Snapshot::from_view(&aifw_core::carp::parse_ifconfig(view))
    }

    #[test]
    fn per_vhid_and_aggregate_transitions() {
        let a = snap(
            "em0: flags=8843<UP>\n\tcarp: BACKUP vhid 1 advbase 1 advskew 0\nem1: flags=8843<UP>\n\tcarp: BACKUP vhid 2 advbase 1 advskew 0\n",
        );
        let b = snap(
            "em0: flags=8843<UP>\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\nem1: flags=8843<UP>\n\tcarp: BACKUP vhid 2 advbase 1 advskew 0\n",
        );
        let c = snap(
            "em0: flags=8843<UP>\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\nem1: flags=8843<UP>\n\tcarp: MASTER vhid 2 advbase 1 advskew 0\n",
        );
        assert_eq!(a.aggregate, "secondary");
        assert_eq!(
            transitions(&a, &b),
            vec![
                (1, "secondary".into(), "primary".into()),
                (0, "secondary".into(), "split".into())
            ]
        );
        assert_eq!(
            transitions(&b, &c),
            vec![
                (2, "secondary".into(), "primary".into()),
                (0, "split".into(), "primary".into())
            ]
        );
        assert!(transitions(&c, &c).is_empty());
    }

    #[test]
    fn vhid_appearing_is_a_transition_from_none() {
        let empty = snap("lo0: flags=8049<UP,LOOPBACK>\n");
        let one = snap("em0: flags=8843<UP>\n\tcarp: INIT vhid 4 advbase 1 advskew 0\n");
        assert_eq!(empty.aggregate, "none");
        assert_eq!(
            transitions(&empty, &one),
            vec![
                (4, "none".into(), "init".into()),
                (0, "none".into(), "init".into())
            ]
        );
    }
}
