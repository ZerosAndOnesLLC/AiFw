//! Broadcast channel for cluster events. Subscribers (WS frames, role-change
//! reactors) receive each event; lagging subscribers drop frames rather than
//! back-pressure producers.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Capacity of the broadcast channel — slow subscribers will see RecvError::Lagged
/// and drop frames; do NOT raise this without a corresponding cap on per-subscriber
/// memory.
pub const CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClusterEvent {
    /// Local CARP role transitioned. Emitted by aifw-daemon's RoleWatcher (Commit 7).
    RoleChanged { from: String, to: String, vhid: u8 },
    /// A health check flipped state. Emitted by HealthProber (Commit 7).
    HealthChanged {
        check: String,
        healthy: bool,
        detail: Option<String>,
    },
    /// Periodic pfsync metrics for the dashboard. Emitted ~every 2s (Commit 10).
    Metrics {
        pfsync_in: u64,
        pfsync_out: u64,
        state_count: u64,
        ts_ms: u64,
    },
}

#[derive(Clone)]
pub struct ClusterEventBus {
    tx: broadcast::Sender<ClusterEvent>,
}

impl ClusterEventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ClusterEvent> {
        self.tx.subscribe()
    }

    pub fn emit(&self, ev: ClusterEvent) {
        let _ = self.tx.send(ev); // ignore send failure when no subscribers
    }

    pub fn sender(&self) -> broadcast::Sender<ClusterEvent> {
        self.tx.clone()
    }
}

impl Default for ClusterEventBus {
    fn default() -> Self {
        Self::new()
    }
}
