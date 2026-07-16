use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// One entry in the pf state table — a tracked connection with its
/// endpoints, protocol state, and traffic counters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfState {
    /// pf's unique state ID
    pub id: u64,
    /// Protocol name (e.g. "tcp", "udp", "icmp")
    pub protocol: String,
    /// Source address
    pub src_addr: IpAddr,
    /// Source port (0 for portless protocols)
    pub src_port: u16,
    /// Destination address
    pub dst_addr: IpAddr,
    /// Destination port (0 for portless protocols)
    pub dst_port: u16,
    /// Protocol state as reported by pf (e.g. "ESTABLISHED:ESTABLISHED")
    pub state: String,
    /// Packets received on this state
    pub packets_in: u64,
    /// Packets sent on this state
    pub packets_out: u64,
    /// Bytes received on this state
    pub bytes_in: u64,
    /// Bytes sent on this state
    pub bytes_out: u64,
    /// Age of the state in seconds
    pub age_secs: u64,
    /// Interface the state is bound to, when known (omitted from JSON if absent)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// Routing table (FIB) number for the state, when known — used by multi-WAN
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtable: Option<u32>,
}

/// Global pf counters as reported by `pfctl -si` (or synthesized by the mock)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PfStats {
    /// Current number of entries in the state table
    pub states_count: u64,
    /// Cumulative state-table searches
    pub states_searches: u64,
    /// Cumulative state-table insertions
    pub states_inserts: u64,
    /// Cumulative state-table removals
    pub states_removals: u64,
    /// Total packets received
    pub packets_in: u64,
    /// Total packets sent
    pub packets_out: u64,
    /// Total bytes received
    pub bytes_in: u64,
    /// Total bytes sent
    pub bytes_out: u64,
    /// Number of loaded rules
    pub rules_count: u64,
    /// Whether pf is currently enabled
    pub running: bool,
}

/// One address entry in a pf table, with per-entry traffic counters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfTableEntry {
    /// The address (network base for CIDR entries)
    pub addr: IpAddr,
    /// CIDR prefix length (32 or 128 for a single host)
    pub prefix: u8,
    /// Packets matched against this entry
    pub packets: u64,
    /// Bytes matched against this entry
    pub bytes: u64,
}
