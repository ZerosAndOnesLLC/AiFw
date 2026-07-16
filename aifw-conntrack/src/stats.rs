use aifw_pf::PfState;
use serde::{Deserialize, Serialize};

/// Aggregate statistics rolled up from a snapshot of the pf state table
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConntrackStats {
    /// Total number of tracked connections
    pub total_connections: u64,
    /// Connections using TCP
    pub tcp_connections: u64,
    /// Connections using UDP
    pub udp_connections: u64,
    /// Connections using ICMP or ICMPv6
    pub icmp_connections: u64,
    /// Connections using any other protocol
    pub other_connections: u64,
    /// Sum of inbound bytes across all connections
    pub total_bytes_in: u64,
    /// Sum of outbound bytes across all connections
    pub total_bytes_out: u64,
    /// Sum of inbound packets across all connections
    pub total_packets_in: u64,
    /// Sum of outbound packets across all connections
    pub total_packets_out: u64,
    /// Mean connection age in seconds (integer division)
    pub avg_age_secs: u64,
    /// Age of the oldest connection in seconds
    pub max_age_secs: u64,
}

impl ConntrackStats {
    /// Compute stats from a pf state snapshot. Returns all-zero defaults for
    /// an empty slice.
    pub fn from_states(states: &[PfState]) -> Self {
        if states.is_empty() {
            return Self::default();
        }

        let mut stats = Self {
            total_connections: states.len() as u64,
            ..Default::default()
        };

        let mut total_age: u64 = 0;

        for s in states {
            match s.protocol.to_lowercase().as_str() {
                "tcp" => stats.tcp_connections += 1,
                "udp" => stats.udp_connections += 1,
                "icmp" | "icmp6" => stats.icmp_connections += 1,
                _ => stats.other_connections += 1,
            }
            stats.total_bytes_in += s.bytes_in;
            stats.total_bytes_out += s.bytes_out;
            stats.total_packets_in += s.packets_in;
            stats.total_packets_out += s.packets_out;
            total_age += s.age_secs;
            if s.age_secs > stats.max_age_secs {
                stats.max_age_secs = s.age_secs;
            }
        }

        stats.avg_age_secs = total_age / stats.total_connections;
        stats
    }
}
