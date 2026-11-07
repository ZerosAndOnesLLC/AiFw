//! Peer monitor (#712): every few seconds, call each peer's
//! `/cluster/peer-state` with the peer key and record what came back —
//! node health, `last_seen`, the peer's live CARP role and its version — so
//! the dashboard shows reality instead of a one-shot ICMP ping. Also the
//! split-brain detector: this node and the peer both reporting MASTER.

use aifw_common::{ClusterNode, NodeHealth};
use aifw_core::ClusterEngine;
use std::sync::Arc;
use std::time::Duration;

const INTERVAL: Duration = Duration::from_secs(5);

#[derive(serde::Deserialize)]
struct PeerState {
    state: String,
    software_version: String,
}

pub struct PeerMonitor {
    engine: Arc<ClusterEngine>,
}

impl PeerMonitor {
    pub fn new(engine: Arc<ClusterEngine>) -> Self {
        Self { engine }
    }

    pub async fn run(self) {
        let mut tick = tokio::time::interval(INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut split_brain = false;
        loop {
            tick.tick().await;
            let Ok(nodes) = self.engine.list_nodes().await else {
                continue;
            };
            if nodes.len() < 2 {
                continue;
            }
            let me = self.engine.self_node().await.ok().flatten();
            let local = aifw_core::carp::kernel_view().await;
            let local_master = local.aggregate_state() == "master";
            let mut peer_master = false;

            for peer in nodes
                .iter()
                .filter(|n| Some(n.id) != me.as_ref().map(|m| m.id))
            {
                let (health, state, version) = self.probe(peer).await;
                peer_master |= state.as_deref() == Some("primary");
                if let Err(e) = self
                    .engine
                    .record_peer_probe(peer.id, health, state.as_deref(), version.as_deref())
                    .await
                {
                    tracing::warn!(peer = %peer.name, error = %e, "ha: could not record peer probe");
                }
            }
            if let Some(me) = &me
                && let Err(e) = self
                    .engine
                    .record_peer_probe(
                        me.id,
                        NodeHealth::Healthy,
                        Some(&canonical(local.aggregate_state())),
                        Some(env!("CARGO_PKG_VERSION")),
                    )
                    .await
            {
                tracing::warn!(error = %e, "ha: could not record own node state");
            }

            let now_split = local_master && peer_master;
            if now_split != split_brain {
                split_brain = now_split;
                let cause = if now_split {
                    tracing::error!(
                        "ha: SPLIT BRAIN — this node and its peer both report CARP MASTER; \
                         check the links between them (CARP advertisements are not getting through)"
                    );
                    "split_brain_detected"
                } else {
                    tracing::warn!("ha: split brain resolved — one MASTER again");
                    "split_brain_resolved"
                };
                if let Err(e) = self
                    .engine
                    .record_failover_event("primary", "primary", cause, None)
                    .await
                {
                    tracing::warn!(error = %e, "ha: could not record split-brain event");
                }
            }
        }
    }

    /// Probe one peer: (health, live role, version).
    async fn probe(&self, peer: &ClusterNode) -> (NodeHealth, Option<String>, Option<String>) {
        let key = match self.engine.peer_api_key(peer.id).await {
            Ok(Some(k)) => k,
            _ => {
                // No key for this peer: TCP reachability is all we can say.
                let addr = std::net::SocketAddr::new(peer.address, peer.api_port);
                let up = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                .is_ok_and(|r| r.is_ok());
                let health = if up {
                    NodeHealth::Degraded
                } else {
                    NodeHealth::Unreachable
                };
                return (health, None, None);
            }
        };
        let client = match self.engine.peer_client(peer, Duration::from_secs(4)) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(peer = %peer.name, error = %e, "ha: peer client");
                return (NodeHealth::Unreachable, None, None);
            }
        };
        let url = format!("{}/api/v1/cluster/peer-state", peer.api_base());
        match client
            .get(&url)
            .header("Authorization", format!("ApiKey {key}"))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                self.engine.learn_peer_cert(peer, &r).await;
                match r.json::<PeerState>().await {
                    Ok(p) => (NodeHealth::Healthy, Some(p.state), Some(p.software_version)),
                    Err(_) => (NodeHealth::Degraded, None, None),
                }
            }
            Ok(r) => {
                tracing::debug!(peer = %peer.name, status = %r.status(), "ha: peer refused probe");
                (NodeHealth::Degraded, None, None)
            }
            Err(e) => {
                tracing::debug!(peer = %peer.name, error = %e, "ha: peer probe failed");
                (NodeHealth::Unreachable, None, None)
            }
        }
    }
}

fn canonical(aggregate: &str) -> String {
    match aggregate {
        "master" => "primary".into(),
        "backup" => "secondary".into(),
        other => other.into(),
    }
}
