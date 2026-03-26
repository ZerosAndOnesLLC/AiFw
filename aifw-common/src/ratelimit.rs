use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Queue / Traffic Shaping types ---

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueueType {
    /// CoDel (Controlled Delay) — modern AQM
    Codel,
    /// HFSC (Hierarchical Fair Service Curve)
    Hfsc,
    /// Priority Queueing
    Priq,
}

impl std::fmt::Display for QueueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueueType::Codel => write!(f, "codel"),
            QueueType::Hfsc => write!(f, "hfsc"),
            QueueType::Priq => write!(f, "priq"),
        }
    }
}

impl QueueType {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "codel" => Ok(QueueType::Codel),
            "hfsc" => Ok(QueueType::Hfsc),
            "priq" | "priority" => Ok(QueueType::Priq),
            _ => Err(crate::AifwError::Validation(format!("unknown queue type: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficClass {
    /// Voice over IP — highest priority
    Voip,
    /// Interactive traffic (SSH, DNS, gaming)
    Interactive,
    /// Web/streaming — default
    Default,
    /// Bulk transfers (backups, updates)
    Bulk,
}

impl std::fmt::Display for TrafficClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrafficClass::Voip => write!(f, "voip"),
            TrafficClass::Interactive => write!(f, "interactive"),
            TrafficClass::Default => write!(f, "default"),
            TrafficClass::Bulk => write!(f, "bulk"),
        }
    }
}

impl TrafficClass {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "voip" => Ok(TrafficClass::Voip),
            "interactive" => Ok(TrafficClass::Interactive),
            "default" => Ok(TrafficClass::Default),
            "bulk" => Ok(TrafficClass::Bulk),
            _ => Err(crate::AifwError::Validation(format!("unknown traffic class: {s}"))),
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            TrafficClass::Voip => 7,
            TrafficClass::Interactive => 5,
            TrafficClass::Default => 3,
            TrafficClass::Bulk => 1,
        }
    }
}

/// Bandwidth specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bandwidth {
    pub value: u64,
    pub unit: BandwidthUnit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BandwidthUnit {
    Bps,
    Kbps,
    Mbps,
    Gbps,
}

impl std::fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.unit {
            BandwidthUnit::Bps => write!(f, "{}b", self.value),
            BandwidthUnit::Kbps => write!(f, "{}Kb", self.value),
            BandwidthUnit::Mbps => write!(f, "{}Mb", self.value),
            BandwidthUnit::Gbps => write!(f, "{}Gb", self.value),
        }
    }
}

impl Bandwidth {
    pub fn parse(s: &str) -> crate::Result<Self> {
        let s = s.trim();
        let (num_str, unit_str) = if s.ends_with("Gb") || s.ends_with("gb") {
            (&s[..s.len() - 2], "gb")
        } else if s.ends_with("Mb") || s.ends_with("mb") {
            (&s[..s.len() - 2], "mb")
        } else if s.ends_with("Kb") || s.ends_with("kb") {
            (&s[..s.len() - 2], "kb")
        } else if s.ends_with('b') || s.ends_with('B') {
            (&s[..s.len() - 1], "b")
        } else {
            (s, "b")
        };

        let value: u64 = num_str
            .parse()
            .map_err(|_| crate::AifwError::Validation(format!("invalid bandwidth: {s}")))?;

        let unit = match unit_str {
            "gb" => BandwidthUnit::Gbps,
            "mb" => BandwidthUnit::Mbps,
            "kb" => BandwidthUnit::Kbps,
            _ => BandwidthUnit::Bps,
        };

        Ok(Bandwidth { value, unit })
    }

    pub fn to_bits_per_sec(&self) -> u64 {
        match self.unit {
            BandwidthUnit::Bps => self.value,
            BandwidthUnit::Kbps => self.value * 1_000,
            BandwidthUnit::Mbps => self.value * 1_000_000,
            BandwidthUnit::Gbps => self.value * 1_000_000_000,
        }
    }
}

/// Queue configuration for an interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub id: Uuid,
    pub interface: Interface,
    pub queue_type: QueueType,
    pub bandwidth: Bandwidth,
    pub name: String,
    pub traffic_class: TrafficClass,
    /// Percentage of parent bandwidth (1-100)
    pub bandwidth_pct: Option<u8>,
    pub default: bool,
    pub status: QueueStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueueStatus {
    Active,
    Disabled,
}

impl QueueConfig {
    pub fn new(
        interface: Interface,
        queue_type: QueueType,
        bandwidth: Bandwidth,
        name: String,
        traffic_class: TrafficClass,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            interface,
            queue_type,
            bandwidth,
            name,
            traffic_class,
            bandwidth_pct: None,
            default: false,
            status: QueueStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate pf queue definition
    pub fn to_pf_queue(&self) -> String {
        let mut parts = vec![format!("queue {}", self.name)];

        if let Some(pct) = self.bandwidth_pct {
            parts.push(format!("bandwidth {pct}%"));
        } else {
            parts.push(format!("bandwidth {}", self.bandwidth));
        }

        if self.default {
            parts.push("default".to_string());
        }

        match self.queue_type {
            QueueType::Codel => parts.push("flows 1024 quantum 1514 target 5 interval 100".to_string()),
            QueueType::Hfsc => {}
            QueueType::Priq => parts.push(format!("priority {}", self.traffic_class.priority())),
        }

        parts.join(" ")
    }

    /// Generate the parent queue line for the interface
    pub fn to_pf_parent_queue(&self) -> String {
        format!(
            "queue on {} bandwidth {}",
            self.interface, self.bandwidth
        )
    }
}

// --- Per-IP Rate Limiting ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    pub id: Uuid,
    pub name: String,
    pub interface: Option<Interface>,
    pub protocol: crate::Protocol,
    pub src_addr: Address,
    pub dst_addr: Address,
    pub dst_port: Option<PortRange>,
    /// Max connections per source IP in the time window
    pub max_connections: u32,
    /// Time window in seconds
    pub window_secs: u32,
    /// Action when limit exceeded: add to overload table
    pub overload_table: String,
    /// Flush states from overloading source
    pub flush_states: bool,
    pub status: RateLimitStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitStatus {
    Active,
    Disabled,
}

impl RateLimitRule {
    pub fn new(
        name: String,
        protocol: crate::Protocol,
        max_connections: u32,
        window_secs: u32,
        overload_table: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            interface: None,
            protocol,
            src_addr: Address::Any,
            dst_addr: Address::Any,
            dst_port: None,
            max_connections,
            window_secs,
            overload_table,
            flush_states: true,
            status: RateLimitStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate pf rule with overload protection
    ///
    /// Example: `pass in quick proto tcp to any port 22 keep state
    ///           (max-src-conn 5, max-src-conn-rate 3/10, overload <bruteforce> flush global)`
    pub fn to_pf_rule(&self) -> String {
        let mut parts = vec!["pass in quick".to_string()];

        if let Some(ref iface) = self.interface {
            parts.push(format!("on {iface}"));
        }

        if self.protocol != crate::Protocol::Any {
            parts.push(format!("proto {}", self.protocol));
        }

        if self.src_addr != Address::Any {
            parts.push(format!("from {}", self.src_addr));
        }

        if self.dst_addr != Address::Any || self.dst_port.is_some() {
            let dst = if self.dst_addr != Address::Any {
                self.dst_addr.to_string()
            } else {
                "any".to_string()
            };
            parts.push(format!("to {dst}"));
            if let Some(ref port) = self.dst_port {
                parts.push(format!("port {port}"));
            }
        }

        // State tracking with overload
        let rate = format!("{}/{}", self.max_connections, self.window_secs);
        let flush = if self.flush_states { " flush global" } else { "" };
        parts.push(format!(
            "keep state (max-src-conn {}, max-src-conn-rate {rate}, overload <{}>{})",
            self.max_connections, self.overload_table, flush
        ));

        parts.push(format!("label \"ratelimit-{}\"", self.name));

        parts.join(" ")
    }

    /// Generate the pf table definition for the overload table
    pub fn to_pf_table(&self) -> String {
        format!("table <{}> persist", self.overload_table)
    }

    /// Generate the block rule for overloaded IPs
    pub fn to_pf_block_rule(&self) -> String {
        format!(
            "block in quick from <{}> label \"overload-{}\"",
            self.overload_table, self.name
        )
    }
}

/// SYN flood protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodConfig {
    pub interface: Interface,
    pub max_src_conn: u32,
    pub max_src_conn_rate: u32,
    pub rate_window_secs: u32,
    pub overload_table: String,
}

impl SynFloodConfig {
    /// Generate pf rules for SYN flood protection
    pub fn to_pf_rules(&self) -> Vec<String> {
        let table = format!("table <{}> persist", self.overload_table);
        let block = format!("block in quick from <{}>", self.overload_table);
        let pass = format!(
            "pass in on {} proto tcp keep state (max-src-conn {}, max-src-conn-rate {}/{}, overload <{}> flush global)",
            self.interface, self.max_src_conn, self.max_src_conn_rate, self.rate_window_secs, self.overload_table
        );
        vec![table, block, pass]
    }
}
