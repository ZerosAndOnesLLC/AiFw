use aifw_pf::{PfBackend, PfState};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};
use tracing::{debug, warn};

use crate::query::{ConnectionFilter, ConnectionQuery};
use crate::stats::ConntrackStats;

pub struct ConnectionTracker {
    pf: Arc<dyn PfBackend>,
    states: Arc<RwLock<Vec<PfState>>>,
    poll_interval: Duration,
    expiry_threshold_secs: u64,
}

impl ConnectionTracker {
    pub fn new(pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pf,
            states: Arc::new(RwLock::new(Vec::new())),
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

    /// Refresh the state table from pf once
    pub async fn refresh(&self) -> aifw_common::Result<()> {
        let new_states = self
            .pf
            .get_states()
            .await
            .map_err(|e| aifw_common::AifwError::Pf(e.to_string()))?;
        debug!(count = new_states.len(), "refreshed connection states");
        *self.states.write().await = new_states;
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
                        let expired: Vec<_> = new_states
                            .iter()
                            .filter(|s| s.age_secs > expiry_threshold)
                            .collect();

                        if !expired.is_empty() {
                            warn!(
                                count = expired.len(),
                                threshold = expiry_threshold,
                                "detected expired connections exceeding threshold"
                            );
                        }

                        debug!(count = new_states.len(), "polled connection states");
                        *states.write().await = new_states;
                    }
                    Err(e) => {
                        warn!("failed to poll pf states: {e}");
                    }
                }
            }
        })
    }

    /// Get current snapshot of all tracked connections
    pub async fn get_connections(&self) -> Vec<PfState> {
        self.states.read().await.clone()
    }

    /// Search connections with a filter
    pub async fn search(&self, filter: &ConnectionFilter) -> Vec<PfState> {
        let states = self.states.read().await;
        ConnectionQuery::filter(&states, filter)
    }

    /// Count connections matching a filter
    pub async fn count(&self, filter: &ConnectionFilter) -> usize {
        let states = self.states.read().await;
        ConnectionQuery::count(&states, filter)
    }

    /// Get total connection count
    pub async fn total_count(&self) -> usize {
        self.states.read().await.len()
    }

    /// Get connection tracking statistics
    pub async fn stats(&self) -> ConntrackStats {
        let states = self.states.read().await;
        ConntrackStats::from_states(&states)
    }

    /// Get top talkers by bytes transferred
    pub async fn top_talkers(&self, limit: usize) -> Vec<(std::net::IpAddr, u64)> {
        let states = self.states.read().await;
        ConnectionQuery::top_talkers(&states, limit)
    }

    /// Get connections grouped by protocol
    pub async fn by_protocol(&self) -> Vec<(String, usize)> {
        let states = self.states.read().await;
        ConnectionQuery::connections_by_protocol(&states)
    }

    /// Find expired connections (age exceeds threshold)
    pub async fn expired_connections(&self) -> Vec<PfState> {
        let threshold = self.expiry_threshold_secs;
        let states = self.states.read().await;
        states
            .iter()
            .filter(|s| s.age_secs > threshold)
            .cloned()
            .collect()
    }
}
