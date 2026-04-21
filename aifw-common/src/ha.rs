use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

use crate::types::Interface;

// ============================================================
// CARP — Common Address Redundancy Protocol
// ============================================================

/// A CARP virtual IP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarpVip {
    pub id: Uuid,
    pub vhid: u8,
    pub virtual_ip: IpAddr,
    pub prefix: u8,
    pub interface: Interface,
    pub advskew: u8,
    pub advbase: u8,
    pub password: String,
    pub status: CarpStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CarpStatus {
    Master,
    Backup,
    Init,
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
            advskew: 0,
            advbase: 1,
            password,
            status: CarpStatus::Init,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate ifconfig commands to create the CARP VIP
    pub fn to_ifconfig_cmds(&self) -> Vec<String> {
        let af = if self.virtual_ip.is_ipv4() {
            "inet"
        } else {
            "inet6"
        };
        vec![format!(
            "ifconfig {} vhid {} advskew {} advbase {} pass {} {af} {}/{} alias",
            self.interface,
            self.vhid,
            self.advskew,
            self.advbase,
            self.password,
            self.virtual_ip,
            self.prefix,
        )]
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
    pub id: Uuid,
    /// Interface used for pfsync traffic
    pub sync_interface: Interface,
    /// Peer IP for pfsync (unicast) or None for multicast
    pub sync_peer: Option<IpAddr>,
    /// Defer mode — defer initial state sync to avoid failover flap
    pub defer: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl PfsyncConfig {
    pub fn new(sync_interface: Interface) -> Self {
        Self {
            id: Uuid::new_v4(),
            sync_interface,
            sync_peer: None,
            defer: true,
            enabled: true,
            created_at: Utc::now(),
        }
    }

    /// Generate ifconfig commands to configure pfsync
    pub fn to_ifconfig_cmds(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let mut cmds = vec![format!("ifconfig pfsync0 create")];

        let mut pfsync_cmd = format!("ifconfig pfsync0 syncdev {}", self.sync_interface);
        if let Some(ref peer) = self.sync_peer {
            pfsync_cmd.push_str(&format!(" syncpeer {peer}"));
        }
        if self.defer {
            pfsync_cmd.push_str(" defer");
        }
        pfsync_cmd.push_str(" up");
        cmds.push(pfsync_cmd);

        cmds
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClusterRole {
    Primary,
    Secondary,
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
    pub id: Uuid,
    pub name: String,
    pub address: IpAddr,
    pub role: ClusterRole,
    pub health: NodeHealth,
    pub last_seen: DateTime<Utc>,
    pub config_version: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NodeHealth {
    Healthy,
    Degraded,
    Unreachable,
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
        }
    }

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
    pub id: Uuid,
    pub name: String,
    pub check_type: HealthCheckType,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub failures_before_down: u32,
    pub target: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

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
}

impl std::fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthCheckType::Ping => write!(f, "ping"),
            HealthCheckType::TcpPort => write!(f, "tcp_port"),
            HealthCheckType::HttpGet => write!(f, "http_get"),
            HealthCheckType::PfStatus => write!(f, "pf_status"),
        }
    }
}

impl HealthCheckType {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "ping" | "icmp" => Ok(HealthCheckType::Ping),
            "tcp" | "tcp_port" => Ok(HealthCheckType::TcpPort),
            "http" | "http_get" => Ok(HealthCheckType::HttpGet),
            "pf" | "pf_status" => Ok(HealthCheckType::PfStatus),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown health check type: {s}"
            ))),
        }
    }
}

impl HealthCheck {
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
    pub version: u64,
    pub node_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rules_hash: String,
    pub nat_hash: String,
    pub data: String,
}

impl ConfigSnapshot {
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
