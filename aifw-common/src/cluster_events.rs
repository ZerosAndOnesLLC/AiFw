//! Broadcast channel for cluster events. Subscribers (WS frames, role-change
//! reactors) receive each event; lagging subscribers drop frames rather than
//! back-pressure producers.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Capacity of the broadcast channel — slow subscribers will see RecvError::Lagged
/// and drop frames; do NOT raise this without a corresponding cap on per-subscriber
/// memory.
pub const CAPACITY: usize = 256;

/// An HA cluster event broadcast on the [`ClusterEventBus`]. Serialized with
/// a `"type"` tag (snake_case) for WebSocket frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClusterEvent {
    /// Local CARP role transitioned. Emitted by aifw-daemon's RoleWatcher (Commit 7).
    RoleChanged {
        /// Previous CARP role (e.g. "backup")
        from: String,
        /// New CARP role (e.g. "master")
        to: String,
        /// CARP virtual host ID the transition applies to
        vhid: u8,
    },
    /// A health check flipped state. Emitted by HealthProber (Commit 7).
    HealthChanged {
        /// Name of the health check that changed
        check: String,
        /// New state: true = healthy, false = failing
        healthy: bool,
        /// Optional detail on why the check flipped (error text)
        detail: Option<String>,
    },
    /// Periodic pfsync metrics for the dashboard. Emitted ~every 2s (Commit 10).
    Metrics {
        /// pfsync packets received (cumulative counter)
        pfsync_in: u64,
        /// pfsync packets sent (cumulative counter)
        pfsync_out: u64,
        /// Current pf state table entry count
        state_count: u64,
        /// Sample timestamp in milliseconds since the Unix epoch
        ts_ms: u64,
    },
}

/// Cheaply cloneable handle to the cluster event broadcast channel.
/// All clones share the same underlying channel.
#[derive(Clone)]
pub struct ClusterEventBus {
    tx: broadcast::Sender<ClusterEvent>,
}

impl ClusterEventBus {
    /// Create a new bus with a fresh broadcast channel of [`CAPACITY`] slots
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx }
    }

    /// Register a new subscriber; it only sees events emitted after this call
    pub fn subscribe(&self) -> broadcast::Receiver<ClusterEvent> {
        self.tx.subscribe()
    }

    /// Broadcast an event to all current subscribers. A send with no
    /// subscribers is silently dropped (not an error).
    pub fn emit(&self, ev: ClusterEvent) {
        let _ = self.tx.send(ev); // ignore send failure when no subscribers
    }

    /// Clone the raw broadcast sender, for producers that need to send
    /// without holding the whole bus
    pub fn sender(&self) -> broadcast::Sender<ClusterEvent> {
        self.tx.clone()
    }
}

impl Default for ClusterEventBus {
    fn default() -> Self {
        Self::new()
    }
}
