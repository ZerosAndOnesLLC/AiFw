use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Types of threats the AI engine can detect
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    PortScan,
    DDoS,
    BruteForce,
    C2Beacon,
    DnsTunnel,
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
    pub fn new(score: f64) -> Self {
        Self(score.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    pub fn is_critical(&self) -> bool {
        self.0 >= 0.9
    }

    pub fn is_high(&self) -> bool {
        self.0 >= 0.7
    }

    pub fn is_medium(&self) -> bool {
        self.0 >= 0.4
    }

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
    pub id: Uuid,
    pub threat_type: ThreatType,
    pub score: ThreatScore,
    pub source_ip: IpAddr,
    pub target_ip: Option<IpAddr>,
    pub target_ports: Vec<u16>,
    pub description: String,
    pub evidence: ThreatEvidence,
    pub detected_at: DateTime<Utc>,
    /// If a temporary block was created, when it expires
    pub expires_at: Option<DateTime<Utc>>,
    pub mitigated: bool,
}

impl Threat {
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
    pub metrics: std::collections::HashMap<String, f64>,
    pub details: String,
}

impl ThreatEvidence {
    pub fn new(details: &str) -> Self {
        Self {
            metrics: std::collections::HashMap::new(),
            details: details.to_string(),
        }
    }

    pub fn with_metric(mut self, key: &str, value: f64) -> Self {
        self.metrics.insert(key.to_string(), value);
        self
    }
}
