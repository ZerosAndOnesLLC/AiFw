use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Types of threats the AI engine can detect
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    /// Probing many destination ports from one source
    PortScan,
    /// SYN flood or high-rate connection flood
    DDoS,
    /// Repeated failed authentication attempts against few ports
    BruteForce,
    /// Periodic command-and-control beaconing to a fixed host
    C2Beacon,
    /// Data exfiltration over abnormal DNS query volume
    DnsTunnel,
    /// Generic ML-flagged anomaly not matching a specific pattern
    Anomaly,
    /// IDS/IPS signature match — correlated with behavioral detection
    SignatureMatch,
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::PortScan => write!(f, "port_scan"),
            ThreatType::DDoS => write!(f, "ddos"),
            ThreatType::BruteForce => write!(f, "brute_force"),
            ThreatType::C2Beacon => write!(f, "c2_beacon"),
            ThreatType::DnsTunnel => write!(f, "dns_tunnel"),
            ThreatType::Anomaly => write!(f, "anomaly"),
            ThreatType::SignatureMatch => write!(f, "signature_match"),
        }
    }
}

/// Confidence/severity score for a threat (0.0 - 1.0)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ThreatScore(pub f64);

impl ThreatScore {
    /// Build a score, clamping the input into the 0.0-1.0 range
    pub fn new(score: f64) -> Self {
        Self(score.clamp(0.0, 1.0))
    }

    /// The raw score value (0.0-1.0)
    pub fn value(&self) -> f64 {
        self.0
    }

    /// Score is 0.9 or above (severity "critical")
    pub fn is_critical(&self) -> bool {
        self.0 >= 0.9
    }

    /// Score is 0.7 or above (severity "high" or worse)
    pub fn is_high(&self) -> bool {
        self.0 >= 0.7
    }

    /// Score is 0.4 or above (severity "medium" or worse)
    pub fn is_medium(&self) -> bool {
        self.0 >= 0.4
    }

    /// Severity bucket as a string: "critical", "high", "medium", or "low"
    pub fn severity(&self) -> &'static str {
        if self.is_critical() {
            "critical"
        } else if self.is_high() {
            "high"
        } else if self.is_medium() {
            "medium"
        } else {
            "low"
        }
    }
}

impl std::fmt::Display for ThreatScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2} ({})", self.0, self.severity())
    }
}

/// A detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Unique threat ID, generated at detection time
    pub id: Uuid,
    /// Category of the detected threat
    pub threat_type: ThreatType,
    /// Confidence/severity score (0.0-1.0)
    pub score: ThreatScore,
    /// IP the threatening traffic originated from
    pub source_ip: IpAddr,
    /// Targeted IP, if a single target was identified
    pub target_ip: Option<IpAddr>,
    /// Targeted ports, if identified; empty when unknown
    pub target_ports: Vec<u16>,
    /// Human-readable summary (e.g. "Port scan detected from 1.2.3.4")
    pub description: String,
    /// Metrics and details supporting the detection
    pub evidence: ThreatEvidence,
    /// When the threat was detected
    pub detected_at: DateTime<Utc>,
    /// If a temporary block was created, when it expires
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether a mitigating action has been taken
    pub mitigated: bool,
}

impl Threat {
    /// Build a threat with a fresh UUID, `detected_at` set to now, and no
    /// target/expiry/mitigation info
    pub fn new(
        threat_type: ThreatType,
        score: ThreatScore,
        source_ip: IpAddr,
        description: String,
        evidence: ThreatEvidence,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            threat_type,
            score,
            source_ip,
            target_ip: None,
            target_ports: Vec::new(),
            description,
            evidence,
            detected_at: Utc::now(),
            expires_at: None,
            mitigated: false,
        }
    }
}

/// Evidence supporting a threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvidence {
    /// Named numeric measurements behind the detection (e.g. "failed_ratio")
    pub metrics: std::collections::HashMap<String, f64>,
    /// Free-form description of what was observed
    pub details: String,
}

impl ThreatEvidence {
    /// Evidence with the given details text and no metrics
    pub fn new(details: &str) -> Self {
        Self {
            metrics: std::collections::HashMap::new(),
            details: details.to_string(),
        }
    }

    /// Builder: attach a named numeric measurement
    pub fn with_metric(mut self, key: &str, value: f64) -> Self {
        self.metrics.insert(key.to_string(), value);
        self
    }
}
