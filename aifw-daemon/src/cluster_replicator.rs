//! Periodically replicates config snapshots to peer nodes when this node is master.
//!
//! Runs every 10 seconds. If the local CARP role is Primary, fetches our snapshot
//! ONCE from the loopback API and computes its SHA-256 hash locally so that both
//! values are derived from the same read. For each registered non-primary peer it:
//!   1. Fetches the peer's current hash cheaply via GET /snapshot/hash.
//!   2. If hashes differ, pushes the snapshot body we already have (no second fetch).
//!   3. Logs 409 conflicts (split-brain: peer also thinks it's master).

use aifw_common::ClusterRole;
use aifw_core::ClusterEngine;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::interval;

pub struct ClusterReplicator {
    engine: Arc<ClusterEngine>,
    api_base: String,
    self_api_key: String,
    /// Tracks whether we have already emitted the one-shot auth warning so we
    /// don't spam the log on every 10-second tick.
    auth_warned: AtomicBool,
}

impl ClusterReplicator {
    pub fn new(engine: Arc<ClusterEngine>, api_base: String, self_api_key: String) -> Self {
        Self {
            engine,
            api_base,
            self_api_key,
            auth_warned: AtomicBool::new(false),
        }
    }

    pub async fn run(self) {
        let mut tick = interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            if let Err(e) = self.tick_once().await {
                // Warn ONCE on the first 401 so a missing/unregistered
                // AIFW_LOOPBACK_API_KEY is visible without flooding logs.
                let status = e
                    .downcast_ref::<reqwest::Error>()
                    .and_then(|re| re.status());
                if status == Some(reqwest::StatusCode::UNAUTHORIZED)
                    && !self.auth_warned.swap(true, Ordering::Relaxed)
                {
                    tracing::warn!(
                        error = %e,
                        "ha: cluster replicator failed to authenticate to loopback API. \
                         AIFW_LOOPBACK_API_KEY is set but not registered. \
                         Replication will not work until provisioned."
                    );
                } else {
                    tracing::debug!(error = %e, "ha: replicator tick failed (continuing)");
                }
            }
        }
    }

    async fn tick_once(&self) -> anyhow::Result<()> {
        let role = aifw_core::current_local_role().await;
        if !matches!(role, ClusterRole::Primary) {
            return Ok(());
        }

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(15))
            .build()?;

        // Pull our snapshot ONCE — body and hash are both derived from this
        // single read, so they are always consistent with each other.
        let local_data = client
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
        let local_hash = aifw_core::sha256_hex(&local_data);

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

            // Cheap hash probe — we don't need the full snapshot from the peer,
            // only whether it matches what we already have.
            let peer_hash_url = format!(
                "https://{}:{}/api/v1/cluster/snapshot/hash",
                peer.address,
                aifw_common::DEFAULT_LOOPBACK_API_PORT
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

            // Hashes differ — push the snapshot body we already fetched above.
            // No second loopback call, so the pushed body and local_hash are
            // guaranteed to match.
            let peer_put_url = format!(
                "https://{}:{}/api/v1/cluster/snapshot",
                peer.address,
                aifw_common::DEFAULT_LOOPBACK_API_PORT
            );
            let resp = client
                .put(&peer_put_url)
                .header("Authorization", format!("ApiKey {key}"))
                .header("Content-Type", "application/json")
                .body(local_data.clone())
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

