use aifw_pf::{PfBackend, PfState};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{debug, warn};

use crate::query::{ConnectionFilter, ConnectionQuery};
use crate::stats::ConntrackStats;

/// In-process cache of the pf state table.
///
/// `start_polling` should be spawned once at boot to refresh the snapshot on a
/// fixed cadence. Hot readers call `get_connections()` to obtain an
/// `Arc<Vec<PfState>>` snapshot — atomic load, no lock, no clone. Each WS tick
/// and `/api/v1/connections` request used to shell out to `pfctl -ss -vv` AND
/// clone the full Vec; now both just bump an Arc refcount.
pub struct ConnectionTracker {
    pf: Arc<dyn PfBackend>,
    states: Arc<ArcSwap<Vec<PfState>>>,
    poll_interval: Duration,
    expiry_threshold_secs: u64,
}

impl ConnectionTracker {
    pub fn new(pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pf,
            states: Arc::new(ArcSwap::from_pointee(Vec::new())),
            poll_interval: Duration::from_secs(5),
            expiry_threshold_secs: 3600,
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    pub fn with_expiry_threshold(mut self, secs: u64) -> Self {
        self.expiry_threshold_secs = secs;
        self
    }

    /// Refresh the state table from pf once. Useful for tests and one-shot
    /// callers; production code should rely on `start_polling`.
    pub async fn refresh(&self) -> aifw_common::Result<()> {
        let new_states = self
            .pf
            .get_states()
            .await
            .map_err(|e| aifw_common::AifwError::Pf(e.to_string()))?;
        debug!(count = new_states.len(), "refreshed connection states");
        self.states.store(Arc::new(new_states));
        Ok(())
    }

    /// Start background polling of the pf state table.
    /// Returns a handle that can be used to stop the polling.
    pub fn start_polling(&self) -> tokio::task::JoinHandle<()> {
        let pf = self.pf.clone();
        let states = self.states.clone();
        let poll_interval = self.poll_interval;
        let expiry_threshold = self.expiry_threshold_secs;

        tokio::spawn(async move {
            let mut tick = interval(poll_interval);
            loop {
                tick.tick().await;
                match pf.get_states().await {
                    Ok(new_states) => {
                        let expired = new_states
                            .iter()
                            .filter(|s| s.age_secs > expiry_threshold)
                            .count();
                        if expired > 0 {
                            debug!(
                                count = expired,
                                threshold_secs = expiry_threshold,
                                "connections older than expiry threshold"
                            );
                        }
                        debug!(count = new_states.len(), "polled connection states");
                        states.store(Arc::new(new_states));
                    }
                    Err(e) => {
                        warn!("failed to poll pf states: {e}");
                    }
                }
            }
        })
    }

    /// Cheap snapshot of the current state table. Atomic load — no syscalls,
    /// no clone, just an Arc refcount bump.
    pub fn snapshot(&self) -> Arc<Vec<PfState>> {
        self.states.load_full()
    }

    /// Backward-compatible shim for callers that took a Vec directly. Prefer
    /// `snapshot()` in new code to avoid the clone.
    pub async fn get_connections(&self) -> Arc<Vec<PfState>> {
        self.snapshot()
    }

    /// Search connections with a filter
    pub async fn search(&self, filter: &ConnectionFilter) -> Vec<PfState> {
        let states = self.snapshot();
        ConnectionQuery::filter(&states, filter)
    }

    /// Count connections matching a filter
    pub async fn count(&self, filter: &ConnectionFilter) -> usize {
        let states = self.snapshot();
        ConnectionQuery::count(&states, filter)
    }

    /// Get total connection count
    pub async fn total_count(&self) -> usize {
        self.snapshot().len()
    }

    /// Get connection tracking statistics
    pub async fn stats(&self) -> ConntrackStats {
        let states = self.snapshot();
        ConntrackStats::from_states(&states)
    }

    /// Get top talkers by bytes transferred
    pub async fn top_talkers(&self, limit: usize) -> Vec<(std::net::IpAddr, u64)> {
        let states = self.snapshot();
        ConnectionQuery::top_talkers(&states, limit)
    }

    /// Get connections grouped by protocol
    pub async fn by_protocol(&self) -> Vec<(String, usize)> {
        let states = self.snapshot();
        ConnectionQuery::connections_by_protocol(&states)
    }

    /// Find expired connections (age exceeds threshold)
    pub async fn expired_connections(&self) -> Vec<PfState> {
        let threshold = self.expiry_threshold_secs;
        let states = self.snapshot();
        states
            .iter()
            .filter(|s| s.age_secs > threshold)
            .cloned()
            .collect()
    }
}
