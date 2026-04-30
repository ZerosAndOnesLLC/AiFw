//! Periodically replicates config snapshots to peer nodes when this node is master.
//!
//! Runs every 10 seconds. If the local CARP role is Primary, computes our
//! snapshot hash via the loopback API, then for each registered non-primary peer
//! node it:
//!   1. Fetches the peer's current hash.
//!   2. If hashes differ, pushes our snapshot data via PUT.
//!   3. Logs 409 conflicts (split-brain: peer also thinks it's master).

use aifw_common::ClusterRole;
use aifw_core::ClusterEngine;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;

pub struct ClusterReplicator {
    engine: Arc<ClusterEngine>,
    api_base: String,
    self_api_key: String,
}

impl ClusterReplicator {
    pub fn new(engine: Arc<ClusterEngine>, api_base: String, self_api_key: String) -> Self {
        Self {
            engine,
            api_base,
            self_api_key,
        }
    }

    pub async fn run(self) {
        let mut tick = interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            if let Err(e) = self.tick_once().await {
                tracing::debug!(error = %e, "ha: replicator tick failed (continuing)");
            }
        }
    }

    async fn tick_once(&self) -> anyhow::Result<()> {
        let role = read_local_role().await;
        if !matches!(role, ClusterRole::Primary) {
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(15))
            .build()?;

        // Fetch our snapshot hash from the loopback API
        let local_hash = client
            .get(format!(
                "{}/api/v1/cluster/snapshot/hash",
                self.api_base
            ))
            .header(
                "Authorization",
                format!("ApiKey {}", self.self_api_key),
            )
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let local_hash = local_hash.trim().to_string();

        let nodes = self.engine.list_nodes().await?;
        for peer in nodes.iter().filter(|n| {
            !matches!(
                n.role,
                ClusterRole::Primary | ClusterRole::Standalone
            )
        }) {
            let key = match self.engine.peer_api_key(peer.id).await? {
                Some(k) => k,
                None => continue,
            };

            let peer_hash_url = format!(
                "https://{}:8080/api/v1/cluster/snapshot/hash",
                peer.address
            );
            let peer_hash = match client
                .get(&peer_hash_url)
                .header("Authorization", format!("ApiKey {key}"))
                .send()
                .await
            {
                Ok(r) => r.text().await.unwrap_or_default().trim().to_string(),
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        peer = %peer.address,
                        "ha: peer hash fetch failed"
                    );
                    continue;
                }
            };

            if peer_hash == local_hash {
                continue;
            }

            // Hashes differ — pull our full snapshot data and push to peer
            let data = client
                .get(format!("{}/api/v1/cluster/snapshot", self.api_base))
                .header(
                    "Authorization",
                    format!("ApiKey {}", self.self_api_key),
                )
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            let peer_put_url = format!(
                "https://{}:8080/api/v1/cluster/snapshot",
                peer.address
            );
            let resp = client
                .put(&peer_put_url)
                .header("Authorization", format!("ApiKey {key}"))
                .header("Content-Type", "application/json")
                .body(data)
                .send()
                .await?;

            if resp.status().as_u16() == 409 {
                tracing::warn!(
                    peer = %peer.address,
                    "ha: peer rejected snapshot (conflict — peer also reports MASTER)"
                );
                let _ = self
                    .engine
                    .record_failover_event(
                        "primary",
                        "primary",
                        "split_brain_detected",
                        Some(&format!(
                            "peer {} also reports MASTER",
                            peer.address
                        )),
                    )
                    .await;
            } else {
                resp.error_for_status()?;
                tracing::debug!(
                    peer = %peer.address,
                    "ha: snapshot pushed to peer"
                );
            }
        }
        Ok(())
    }
}

async fn read_local_role() -> ClusterRole {
    tokio::process::Command::new("sysrc")
        .arg("-n")
        .arg("aifw_cluster_role")
        .output()
        .await
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .and_then(|s| ClusterRole::parse(&s).ok())
        .unwrap_or(ClusterRole::Standalone)
}
