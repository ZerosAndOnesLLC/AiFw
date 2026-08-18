use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::types::Interface;

// ============================================================
// CARP — Common Address Redundancy Protocol
// ============================================================

/// Latency profile controlling CARP advertisement timers.
///
/// Maps to (advbase, primary_advskew, secondary_advskew):
/// - Conservative: ~3 s detection, very stable
/// - Tight: ~1.5 s detection, requires reliable network
/// - Aggressive: ~1 s detection, requires future heartbeat daemon
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CarpLatencyProfile {
    /// ~3 s failover detection, very stable (default)
    #[default]
    Conservative,
    /// ~1.5 s failover detection, requires a reliable network
    Tight,
    /// ~1 s failover detection, requires the future heartbeat daemon
    Aggressive,
}

impl CarpLatencyProfile {
    /// Returns (advbase, primary_advskew, secondary_advskew) for this profile.
    pub fn skews(self) -> (u8, u8, u8) {
        match self {
            Self::Conservative => (1, 0, 100),
            Self::Tight => (1, 0, 20),
            Self::Aggressive => (1, 0, 10),
        }
    }

    /// Parse a profile from its lowercase wire/CLI name
    /// ("conservative", "tight", "aggressive"), case-insensitively.
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "conservative" => Ok(Self::Conservative),
            "tight" => Ok(Self::Tight),
            "aggressive" => Ok(Self::Aggressive),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown latency profile: {s}"
            ))),
        }
    }

    /// Returns the CARP timing for this profile in the given role.
    /// Primary always uses advskew=0; secondary uses the profile's secondary_skew.
    /// Standalone falls back to secondary_skew (conservative "this node will lose elections" default).
    pub fn timing_for(self, role: ClusterRole) -> CarpTiming {
        let (advbase, primary_skew, secondary_skew) = self.skews();
        let advskew = match role {
            ClusterRole::Primary => primary_skew,
            ClusterRole::Secondary | ClusterRole::Standalone => secondary_skew,
        };
        CarpTiming { advbase, advskew }
    }
}

/// Effective CARP advertisement timing derived from a profile + role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CarpTiming {
    /// CARP advertisement interval base in seconds (ifconfig `advbase`)
    pub advbase: u8,
    /// CARP advertisement skew (ifconfig `advskew`, in 1/256 s increments);
    /// higher values lose master elections
    pub advskew: u8,
}

impl std::fmt::Display for CarpLatencyProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Conservative => "conservative",
            Self::Tight => "tight",
            Self::Aggressive => "aggressive",
        })
    }
}

/// A CARP virtual IP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarpVip {
    /// Unique identifier
    pub id: Uuid,
    /// CARP virtual host ID (1-255); must match on all cluster members sharing this VIP
    pub vhid: u8,
    /// The shared virtual IP address that fails over between nodes
    pub virtual_ip: IpAddr,
    /// Network prefix length for the virtual IP
    pub prefix: u8,
    /// Physical interface the VIP is configured on
    pub interface: Interface,
    /// CARP authentication password (ifconfig `pass`)
    pub password: String,
    /// Last observed CARP state for this VIP
    pub status: CarpStatus,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

/// CARP state of a virtual IP as reported by the kernel (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CarpStatus {
    /// This node currently owns the VIP and answers traffic
    Master,
    /// This node is standing by, ready to take over the VIP
    Backup,
    /// CARP is initializing; no role established yet
    Init,
    /// The VIP is administratively disabled
    Disabled,
}

impl std::fmt::Display for CarpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CarpStatus::Master => write!(f, "master"),
            CarpStatus::Backup => write!(f, "backup"),
            CarpStatus::Init => write!(f, "init"),
            CarpStatus::Disabled => write!(f, "disabled"),
        }
    }
}

impl CarpVip {
    /// Create a new VIP with a fresh UUID, status `Init`, and both timestamps set to now
    pub fn new(
        vhid: u8,
        virtual_ip: IpAddr,
        prefix: u8,
        interface: Interface,
        password: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            vhid,
            virtual_ip,
            prefix,
            interface,
            password,
            status: CarpStatus::Init,
            created_at: now,
            updated_at: now,
        }
    }

    /// Render ifconfig argv for the given CARP timing (derived from profile + role).
    ///
    /// Returns a list of argument vectors — each inner `Vec<String>` is one
    /// command where `[0]` is the executable and the rest are its arguments.
    /// Pass them directly to `tokio::process::Command::new(&argv[0]).args(&argv[1..])`.
    pub fn to_ifconfig_argv(&self, timing: CarpTiming) -> Vec<Vec<String>> {
        let af = if self.virtual_ip.is_ipv4() {
            "inet"
        } else {
            "inet6"
        };
        vec![vec![
            "ifconfig".to_string(),
            self.interface.to_string(),
            "vhid".to_string(),
            self.vhid.to_string(),
            "advskew".to_string(),
            timing.advskew.to_string(),
            "advbase".to_string(),
            timing.advbase.to_string(),
            "pass".to_string(),
            self.password.clone(),
            af.to_string(),
            format!("{}/{}", self.virtual_ip, self.prefix),
            "alias".to_string(),
        ]]
    }

    /// Generate pf rules to allow CARP protocol traffic
    pub fn to_pf_rules(&self) -> Vec<String> {
        vec![format!(
            "pass quick proto carp keep state label \"carp-vhid-{}\"",
            self.vhid
        )]
    }
}

// ============================================================
// pfsync — State Table Synchronization
// ============================================================

/// pfsync configuration for state table synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfsyncConfig {
    /// Unique identifier
    pub id: Uuid,
    /// Interface used for pfsync traffic
    pub sync_interface: Interface,
    /// Peer IP for pfsync (unicast) or None for multicast
    pub sync_peer: Option<IpAddr>,
    /// Defer mode — defer initial state sync to avoid failover flap
    pub defer: bool,
    /// Whether pfsync is active; when false no ifconfig commands or pf rules are generated
    pub enabled: bool,
    /// CARP advertisement timer profile
    pub latency_profile: CarpLatencyProfile,
    /// Dedicated heartbeat interface (schema-only; consumed by future heartbeat daemon)
    pub heartbeat_iface: Option<Interface>,
    /// Heartbeat interval in milliseconds (schema-only; consumed by future heartbeat daemon)
    pub heartbeat_interval_ms: Option<u32>,
    /// Link rDHCP HA state to this pfsync session (consumed in Commit 8 / #221)
    pub dhcp_link: bool,
    /// Tear down WireGuard interfaces while this node is CARP BACKUP and
    /// bring them back on MASTER (#486). Off by default: with the tunnels
    /// bound to floating VIPs, wireguard-go on 0.0.0.0 already stops seeing
    /// traffic on BACKUP; turn this on when a peer would otherwise keep a
    /// handshake alive with the standby.
    #[serde(default)]
    pub wg_deconfigure_on_backup: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl PfsyncConfig {
    /// Create an enabled multicast config with defer on, the conservative
    /// latency profile, and no heartbeat/DHCP linkage
    pub fn new(sync_interface: Interface) -> Self {
        Self {
            id: Uuid::new_v4(),
            sync_interface,
            sync_peer: None,
            defer: true,
            enabled: true,
            latency_profile: CarpLatencyProfile::Conservative,
            heartbeat_iface: None,
            heartbeat_interval_ms: None,
            dhcp_link: false,
            wg_deconfigure_on_backup: false,
            created_at: Utc::now(),
        }
    }

    /// Generate ifconfig argv vectors to configure pfsync.
    ///
    /// Returns a list of argument vectors — each inner `Vec<String>` is one
    /// command where `[0]` is the executable and the rest are its arguments.
    /// Pass them directly to `tokio::process::Command::new(&argv[0]).args(&argv[1..])`.
    pub fn to_ifconfig_cmds(&self) -> Vec<Vec<String>> {
        if !self.enabled {
            return Vec::new();
        }

        let create_argv = vec![
            "ifconfig".to_string(),
            "pfsync0".to_string(),
            "create".to_string(),
        ];

        let mut config_argv = vec![
            "ifconfig".to_string(),
            "pfsync0".to_string(),
            "syncdev".to_string(),
            self.sync_interface.to_string(),
        ];
        if let Some(ref peer) = self.sync_peer {
            config_argv.push("syncpeer".to_string());
            config_argv.push(peer.to_string());
        }
        if self.defer {
            config_argv.push("defer".to_string());
        }
        config_argv.push("up".to_string());

        vec![create_argv, config_argv]
    }

    /// Generate pf rules to allow pfsync traffic
    pub fn to_pf_rules(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut rules = vec![format!(
            "pass on {} proto pfsync keep state label \"pfsync\"",
            self.sync_interface
        )];
        if let Some(ref peer) = self.sync_peer {
            rules.push(format!(
                "pass quick proto pfsync from {} keep state label \"pfsync-peer\"",
                peer
            ));
        }
        rules
    }
}

// ============================================================
// Cluster Node Management
// ============================================================

/// Role of a node in the HA cluster (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClusterRole {
    /// Preferred master; uses the profile's primary advskew (0) to win CARP elections
    Primary,
    /// Standby node; uses the profile's secondary advskew so it defers to the primary
    Secondary,
    /// Not part of a cluster; treated like a secondary for CARP timing
    Standalone,
}

impl std::fmt::Display for ClusterRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClusterRole::Primary => write!(f, "primary"),
            ClusterRole::Secondary => write!(f, "secondary"),
            ClusterRole::Standalone => write!(f, "standalone"),
        }
    }
}

impl ClusterRole {
    /// Parse a role from a string, case-insensitively. Accepts aliases
    /// ("master" for primary; "backup"/"slave" for secondary).
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "primary" | "master" => Ok(ClusterRole::Primary),
            "secondary" | "backup" | "slave" => Ok(ClusterRole::Secondary),
            "standalone" => Ok(ClusterRole::Standalone),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown cluster role: {s}"
            ))),
        }
    }
}

/// A node in the HA cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Unique identifier
    pub id: Uuid,
    /// Human-readable node name
    pub name: String,
    /// Management IP used to reach the node for sync and health checks
    pub address: IpAddr,
    /// This node's role in the cluster
    pub role: ClusterRole,
    /// Last known health status
    pub health: NodeHealth,
    /// When the node was last heard from
    pub last_seen: DateTime<Utc>,
    /// Monotonic version of the config snapshot this node has applied
    pub config_version: u64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Software version string (e.g. "5.88.1") written by the node at boot.
    /// Used by the dashboard to detect version drift during rolling upgrades.
    pub software_version: Option<String>,
    /// When this node last successfully pushed a TLS cert to its peer.
    pub last_pushed_cert_at: Option<DateTime<Utc>>,
    /// SHA-256 fingerprint (lowercase hex) of the API certificate this peer
    /// presents; every HTTPS call to the peer is pinned to it (#317). `None`
    /// until first contact learns it (or after an operator re-pin).
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// TCP port the peer's API listens on (#487). Defaults to
    /// [`crate::DEFAULT_LOOPBACK_API_PORT`]; set it when a peer runs its
    /// API on a non-default port.
    #[serde(default = "default_api_port")]
    pub api_port: u16,
}

fn default_api_port() -> u16 {
    crate::DEFAULT_LOOPBACK_API_PORT
}

/// Health status of a cluster node (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NodeHealth {
    /// Node is reachable and all health checks pass
    Healthy,
    /// Node is reachable but some health checks are failing
    Degraded,
    /// Node cannot be contacted
    Unreachable,
    /// Health has not been determined yet (initial state)
    Unknown,
}

impl std::fmt::Display for NodeHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeHealth::Healthy => write!(f, "healthy"),
            NodeHealth::Degraded => write!(f, "degraded"),
            NodeHealth::Unreachable => write!(f, "unreachable"),
            NodeHealth::Unknown => write!(f, "unknown"),
        }
    }
}

impl ClusterNode {
    /// Create a new node with a fresh UUID, health `Unknown`, config_version 0,
    /// and `last_seen` set to now
    pub fn new(name: String, address: IpAddr, role: ClusterRole) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            address,
            role,
            health: NodeHealth::Unknown,
            last_seen: now,
            config_version: 0,
            created_at: now,
            software_version: None,
            last_pushed_cert_at: None,
            cert_fingerprint: None,
            api_port: crate::DEFAULT_LOOPBACK_API_PORT,
        }
    }

    /// Base URL for calling this peer's API (`https://<address>:<port>`).
    /// IPv6 addresses are bracketed.
    pub fn api_base(&self) -> String {
        match self.address {
            std::net::IpAddr::V6(v6) => format!("https://[{v6}]:{}", self.api_port),
            v4 => format!("https://{v4}:{}", self.api_port),
        }
    }

    /// True when the node is contactable (Healthy or Degraded);
    /// false for Unreachable or Unknown
    pub fn is_reachable(&self) -> bool {
        matches!(self.health, NodeHealth::Healthy | NodeHealth::Degraded)
    }
}

// ============================================================
// Health Checks
// ============================================================

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Unique identifier
    pub id: Uuid,
    /// Human-readable check name
    pub name: String,
    /// What kind of probe this check performs
    pub check_type: HealthCheckType,
    /// How often the check runs, in seconds
    pub interval_secs: u32,
    /// Per-attempt timeout in seconds before the check counts as failed
    pub timeout_secs: u32,
    /// Consecutive failures required before the target is declared down
    pub failures_before_down: u32,
    /// Probe target; meaning depends on `check_type` (IP/host for ping,
    /// host:port for tcp_port, URL for http_get, process name for process_running)
    pub target: String,
    /// Whether the check is active
    pub enabled: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Kind of probe a health check performs (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    /// ICMP ping
    Ping,
    /// TCP port open check
    TcpPort,
    /// HTTP GET returning 2xx
    HttpGet,
    /// pf is running
    PfStatus,
    /// Process is running — `target` is the exact process name passed to `pgrep -x`
    ProcessRunning,
}

impl std::fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthCheckType::Ping => write!(f, "ping"),
            HealthCheckType::TcpPort => write!(f, "tcp_port"),
            HealthCheckType::HttpGet => write!(f, "http_get"),
            HealthCheckType::PfStatus => write!(f, "pf_status"),
            HealthCheckType::ProcessRunning => write!(f, "process_running"),
        }
    }
}

impl HealthCheckType {
    /// Parse a check type from a string, case-insensitively. Accepts aliases
    /// ("icmp", "tcp", "http", "pf", "process", "pgrep").
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "ping" | "icmp" => Ok(HealthCheckType::Ping),
            "tcp" | "tcp_port" => Ok(HealthCheckType::TcpPort),
            "http" | "http_get" => Ok(HealthCheckType::HttpGet),
            "pf" | "pf_status" => Ok(HealthCheckType::PfStatus),
            "process_running" | "process" | "pgrep" => Ok(HealthCheckType::ProcessRunning),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown health check type: {s}"
            ))),
        }
    }
}

impl HealthCheck {
    /// Create an enabled check with defaults: 10 s interval, 5 s timeout,
    /// 3 failures before down
    pub fn new(name: String, check_type: HealthCheckType, target: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            check_type,
            interval_secs: 10,
            timeout_secs: 5,
            failures_before_down: 3,
            target,
            enabled: true,
            created_at: Utc::now(),
        }
    }
}

// ============================================================
// Config Sync
// ============================================================

/// A versioned configuration snapshot for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// Monotonically increasing config version number
    pub version: u64,
    /// Node that produced this snapshot
    pub node_id: Uuid,
    /// When the snapshot was taken
    pub timestamp: DateTime<Utc>,
    /// Hash of the firewall rule set, used to detect drift between nodes
    pub rules_hash: String,
    /// Hash of the NAT rule set, used to detect drift between nodes
    pub nat_hash: String,
    /// Serialized configuration payload to replicate
    pub data: String,
}

impl ConfigSnapshot {
    /// Create a snapshot with the timestamp set to now
    pub fn new(
        version: u64,
        node_id: Uuid,
        rules_hash: String,
        nat_hash: String,
        data: String,
    ) -> Self {
        Self {
            version,
            node_id,
            timestamp: Utc::now(),
            rules_hash,
            nat_hash,
            data,
        }
    }

    /// Check if this snapshot differs from another
    pub fn differs_from(&self, other: &ConfigSnapshot) -> bool {
        self.rules_hash != other.rules_hash || self.nat_hash != other.nat_hash
    }
}
