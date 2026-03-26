use aifw_pf::PfBackend;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{debug, warn};

use crate::backend::MetricsBackend;
use crate::series::Aggregation;
use crate::store::MetricsStore;

/// Well-known metric names
pub mod names {
    // pf stats
    pub const PF_STATES: &str = "pf.states";
    pub const PF_PACKETS_IN: &str = "pf.packets_in";
    pub const PF_PACKETS_OUT: &str = "pf.packets_out";
    pub const PF_BYTES_IN: &str = "pf.bytes_in";
    pub const PF_BYTES_OUT: &str = "pf.bytes_out";
    pub const PF_RULES_COUNT: &str = "pf.rules_count";
    pub const PF_RUNNING: &str = "pf.running";

    // Connection stats
    pub const CONN_TOTAL: &str = "conn.total";
    pub const CONN_TCP: &str = "conn.tcp";
    pub const CONN_UDP: &str = "conn.udp";
    pub const CONN_ICMP: &str = "conn.icmp";
    pub const CONN_NEW_RATE: &str = "conn.new_rate";

    // Traffic rates (computed as delta / interval)
    pub const TRAFFIC_BPS_IN: &str = "traffic.bps_in";
    pub const TRAFFIC_BPS_OUT: &str = "traffic.bps_out";
    pub const TRAFFIC_PPS_IN: &str = "traffic.pps_in";
    pub const TRAFFIC_PPS_OUT: &str = "traffic.pps_out";

    // Threat stats
    pub const THREATS_TOTAL: &str = "threats.total";
    pub const THREATS_BLOCKED: &str = "threats.blocked";
    pub const THREATS_PORT_SCAN: &str = "threats.port_scan";
    pub const THREATS_DDOS: &str = "threats.ddos";
    pub const THREATS_BRUTE_FORCE: &str = "threats.brute_force";

    // System
    pub const RULES_ACTIVE: &str = "system.rules_active";
    pub const NAT_RULES: &str = "system.nat_rules";
    pub const QUEUE_COUNT: &str = "system.queues";
    pub const RATELIMIT_COUNT: &str = "system.rate_limits";

    // API
    pub const API_REQUESTS: &str = "api.requests";
    pub const API_ERRORS: &str = "api.errors";
}

/// Collects metrics from the pf backend and records them into the store.
pub struct MetricsCollector {
    pf: Arc<dyn PfBackend>,
    store: Arc<MetricsStore>,
    interval: Duration,
    prev_packets_in: u64,
    prev_packets_out: u64,
    prev_bytes_in: u64,
    prev_bytes_out: u64,
}

impl MetricsCollector {
    pub fn new(pf: Arc<dyn PfBackend>, store: Arc<MetricsStore>) -> Self {
        Self {
            pf,
            store,
            interval: Duration::from_secs(1),
            prev_packets_in: 0,
            prev_packets_out: 0,
            prev_bytes_in: 0,
            prev_bytes_out: 0,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Register all well-known metrics with appropriate aggregation
    pub async fn register_metrics(&self) {
        use names::*;

        // Gauges (use Last)
        for name in [PF_STATES, PF_RULES_COUNT, PF_RUNNING, CONN_TOTAL, CONN_TCP,
                      CONN_UDP, CONN_ICMP, RULES_ACTIVE, NAT_RULES, QUEUE_COUNT,
                      RATELIMIT_COUNT, THREATS_TOTAL, THREATS_BLOCKED] {
            self.store.register(name, Aggregation::Last).await;
        }

        // Counters / rates (use Sum for rollups)
        for name in [PF_PACKETS_IN, PF_PACKETS_OUT, PF_BYTES_IN, PF_BYTES_OUT,
                      TRAFFIC_BPS_IN, TRAFFIC_BPS_OUT, TRAFFIC_PPS_IN, TRAFFIC_PPS_OUT,
                      CONN_NEW_RATE, THREATS_PORT_SCAN, THREATS_DDOS, THREATS_BRUTE_FORCE,
                      API_REQUESTS, API_ERRORS] {
            self.store.register(name, Aggregation::Average).await;
        }
    }

    /// Collect one round of metrics from pf
    pub async fn collect_once(&mut self) {
        match self.pf.get_stats().await {
            Ok(stats) => {
                let _ = self.store.record(names::PF_STATES, stats.states_count as f64).await;
                let _ = self.store.record(names::PF_PACKETS_IN, stats.packets_in as f64).await;
                let _ = self.store.record(names::PF_PACKETS_OUT, stats.packets_out as f64).await;
                let _ = self.store.record(names::PF_BYTES_IN, stats.bytes_in as f64).await;
                let _ = self.store.record(names::PF_BYTES_OUT, stats.bytes_out as f64).await;
                let _ = self.store.record(names::PF_RULES_COUNT, stats.rules_count as f64).await;
                let _ = self.store.record(names::PF_RUNNING, if stats.running { 1.0 } else { 0.0 }).await;

                // Compute rates (delta / interval)
                let interval_secs = self.interval.as_secs_f64().max(1.0);
                let pps_in = (stats.packets_in.saturating_sub(self.prev_packets_in)) as f64 / interval_secs;
                let pps_out = (stats.packets_out.saturating_sub(self.prev_packets_out)) as f64 / interval_secs;
                let bps_in = (stats.bytes_in.saturating_sub(self.prev_bytes_in)) as f64 * 8.0 / interval_secs;
                let bps_out = (stats.bytes_out.saturating_sub(self.prev_bytes_out)) as f64 * 8.0 / interval_secs;

                let _ = self.store.record(names::TRAFFIC_PPS_IN, pps_in).await;
                let _ = self.store.record(names::TRAFFIC_PPS_OUT, pps_out).await;
                let _ = self.store.record(names::TRAFFIC_BPS_IN, bps_in).await;
                let _ = self.store.record(names::TRAFFIC_BPS_OUT, bps_out).await;

                self.prev_packets_in = stats.packets_in;
                self.prev_packets_out = stats.packets_out;
                self.prev_bytes_in = stats.bytes_in;
                self.prev_bytes_out = stats.bytes_out;

                debug!("collected pf metrics");
            }
            Err(e) => {
                warn!("failed to collect pf metrics: {e}");
            }
        }

        // Connection breakdown
        match self.pf.get_states().await {
            Ok(states) => {
                let total = states.len();
                let tcp = states.iter().filter(|s| s.protocol == "tcp").count();
                let udp = states.iter().filter(|s| s.protocol == "udp").count();
                let icmp = states.iter().filter(|s| s.protocol.starts_with("icmp")).count();

                let _ = self.store.record(names::CONN_TOTAL, total as f64).await;
                let _ = self.store.record(names::CONN_TCP, tcp as f64).await;
                let _ = self.store.record(names::CONN_UDP, udp as f64).await;
                let _ = self.store.record(names::CONN_ICMP, icmp as f64).await;
            }
            Err(e) => {
                warn!("failed to collect connection metrics: {e}");
            }
        }
    }

    /// Start the collection loop in the background
    pub fn start(mut self) -> tokio::task::JoinHandle<()> {
        let poll_interval = self.interval;
        tokio::spawn(async move {
            self.register_metrics().await;
            let mut tick = interval(poll_interval);
            loop {
                tick.tick().await;
                self.collect_once().await;
            }
        })
    }
}
