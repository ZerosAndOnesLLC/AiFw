use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// --- Queue / Traffic Shaping types ---

/// pf queueing discipline used by a [`QueueConfig`]
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

/// dummynet scheduler configuration for the FQ-CoDel backend.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FqCodelConfig {
    /// Target queueing delay in milliseconds.
    pub target_ms: u32,
    /// CoDel interval in milliseconds.
    pub interval_ms: u32,
    /// Per-flow quantum in bytes.
    pub quantum_bytes: u32,
    /// Maximum queue length in packets.
    pub limit_packets: u32,
    /// Number of flow buckets.
    pub flows: u32,
    /// Enable ECN marking.
    pub ecn: bool,
}

impl Default for FqCodelConfig {
    fn default() -> Self {
        Self {
            target_ms: 5,
            interval_ms: 100,
            quantum_bytes: 1514,
            limit_packets: 10240,
            flows: 1024,
            ecn: true,
        }
    }
}

impl FqCodelConfig {
    /// Reject values outside FreeBSD dummynet's safe scheduler bounds.
    pub fn validate(&self) -> crate::Result<()> {
        if !(1..=1_000).contains(&self.target_ms)
            || self.interval_ms < self.target_ms
            || self.interval_ms > 10_000
        {
            return Err(crate::AifwError::Validation(
                "invalid FQ-CoDel target/interval".to_string(),
            ));
        }
        if !(64..=9_000).contains(&self.quantum_bytes)
            || !(1..=20_480).contains(&self.limit_packets)
            || !(1..=65_536).contains(&self.flows)
        {
            return Err(crate::AifwError::Validation(
                "invalid FQ-CoDel quantum, limit, or flow count".to_string(),
            ));
        }
        Ok(())
    }
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
    /// Parse from a case-insensitive string ("codel", "hfsc", "priq"/"priority").
    /// Fails with `Validation` on anything else.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "codel" => Ok(QueueType::Codel),
            "hfsc" => Ok(QueueType::Hfsc),
            "priq" | "priority" => Ok(QueueType::Priq),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown queue type: {s}"
            ))),
        }
    }
}

/// Traffic category for shaping, mapped to a priority via [`Self::priority`]
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
    /// Parse from a case-insensitive string ("voip", "interactive", "default",
    /// "bulk"). Fails with `Validation` on anything else.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "voip" => Ok(TrafficClass::Voip),
            "interactive" => Ok(TrafficClass::Interactive),
            "default" => Ok(TrafficClass::Default),
            "bulk" => Ok(TrafficClass::Bulk),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown traffic class: {s}"
            ))),
        }
    }

    /// pf priq priority for this class (7 = highest/VoIP down to 1 = bulk)
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
    /// Numeric value in the given unit
    pub value: u64,
    /// Unit the value is expressed in
    pub unit: BandwidthUnit,
}

/// Unit for a [`Bandwidth`] value (decimal multiples of bits per second)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BandwidthUnit {
    /// Bits per second
    Bps,
    /// Kilobits per second (1,000 bps)
    Kbps,
    /// Megabits per second (1,000,000 bps)
    Mbps,
    /// Gigabits per second (1,000,000,000 bps)
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
    /// Parse a pf-style bandwidth string like "100Mb", "512Kb", "1Gb", or a
    /// bare number (bits per second). Fails with `Validation` if the numeric
    /// part doesn't parse.
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

    /// Convert to bits per second using decimal (1000-based) multipliers
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
    /// Unique queue ID
    pub id: Uuid,
    /// Interface the queue is attached to
    pub interface: Interface,
    /// Queueing discipline (codel/hfsc/priq)
    pub queue_type: QueueType,
    /// Queue bandwidth (used verbatim unless `bandwidth_pct` is set)
    pub bandwidth: Bandwidth,
    /// pf queue name
    pub name: String,
    /// Traffic class this queue serves (drives priq priority)
    pub traffic_class: TrafficClass,
    /// Percentage of parent bandwidth (1-100)
    pub bandwidth_pct: Option<u8>,
    /// Whether this is the interface's default queue for unmatched traffic
    pub default: bool,
    /// Whether the queue is active or disabled
    pub status: QueueStatus,
    /// Creation timestamp (UTC)
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp (UTC)
    pub updated_at: DateTime<Utc>,
    /// FQ-CoDel parameters (used when queue_type is Codel).
    #[serde(default)]
    pub fq_codel: FqCodelConfig,
}

/// Enabled/disabled state of a queue
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueueStatus {
    /// Queue is configured in pf
    Active,
    /// Queue is stored but not pushed to pf
    Disabled,
}

impl QueueConfig {
    /// Create an active, non-default queue with a random ID and both
    /// timestamps set to now
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
            fq_codel: FqCodelConfig::default(),
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
            // FQ-CoDel is rendered by the dummynet backend. Returning no PF
            // queue syntax here prevents callers from accidentally loading a
            // same-family ALTQ approximation into pf.
            QueueType::Codel => return String::new(),
            QueueType::Hfsc => {}
            QueueType::Priq => parts.push(format!("priority {}", self.traffic_class.priority())),
        }

        parts.join(" ")
    }

    /// Generate the parent queue line for the interface
    pub fn to_pf_parent_queue(&self) -> String {
        format!("queue on {} bandwidth {}", self.interface, self.bandwidth)
    }
}

// --- Per-IP Rate Limiting ---

/// Per-source-IP connection rate limit, enforced via pf `max-src-conn-rate`
/// with an overload table that offending IPs are added to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Unique rule ID
    pub id: Uuid,
    /// Rule name, used in the pf label (`ratelimit-<name>`)
    pub name: String,
    /// Interface to match; `None` applies on all interfaces
    pub interface: Option<Interface>,
    /// Protocol to match; `Any` omits the `proto` clause
    pub protocol: crate::Protocol,
    /// Source address to match; `Any` omits the `from` clause
    pub src_addr: Address,
    /// Destination address to match; `Any` omits the `to` clause
    pub dst_addr: Address,
    /// Optional destination port (range) to match
    pub dst_port: Option<PortRange>,
    /// Max connections per source IP in the time window
    pub max_connections: u32,
    /// Time window in seconds
    pub window_secs: u32,
    /// Action when limit exceeded: add to overload table
    pub overload_table: String,
    /// Flush states from overloading source
    pub flush_states: bool,
    /// Whether the rule is active or disabled
    pub status: RateLimitStatus,
    /// Creation timestamp (UTC)
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp (UTC)
    pub updated_at: DateTime<Utc>,
}

/// Enabled/disabled state of a rate limit rule
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitStatus {
    /// Rule is enforced in pf
    Active,
    /// Rule is stored but not pushed to pf
    Disabled,
}

impl RateLimitRule {
    /// Create an active rule matching any interface/address/port, with state
    /// flushing enabled, a random ID, and both timestamps set to now
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
        let flush = if self.flush_states {
            " flush global"
        } else {
            ""
        };
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
    /// Interface to protect
    pub interface: Interface,
    /// Max simultaneous TCP connections per source IP
    pub max_src_conn: u32,
    /// Max new connections per source IP within the rate window
    pub max_src_conn_rate: u32,
    /// Rate window length in seconds
    pub rate_window_secs: u32,
    /// pf table that offending source IPs are added to (and blocked from)
    pub overload_table: String,
}

impl SynFloodConfig {
    /// Generate pf rules for SYN flood protection
    pub fn to_pf_rules(&self) -> Vec<String> {
        let table = format!("table <{}> persist", self.overload_table);
        let block = format!("block in quick from <{}>", self.overload_table);
        let pass = format!(
            "pass in on {} proto tcp keep state (max-src-conn {}, max-src-conn-rate {}/{}, overload <{}> flush global)",
            self.interface,
            self.max_src_conn,
            self.max_src_conn_rate,
            self.rate_window_secs,
            self.overload_table
        );
        vec![table, block, pass]
    }
}
