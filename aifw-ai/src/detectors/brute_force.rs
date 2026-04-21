use async_trait::async_trait;

use super::Detector;
use crate::features::TrafficFeatures;
use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

pub struct BruteForceDetector {
    /// Max connections to auth-related ports before flagging
    pub max_auth_connections: u64,
    /// Max failed ratio for auth ports
    pub min_failed_ratio: f64,
}

impl BruteForceDetector {
    pub fn new() -> Self {
        Self {
            max_auth_connections: 10,
            min_failed_ratio: 0.7,
        }
    }
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for BruteForceDetector {
    fn name(&self) -> &str {
        "brute_force"
    }

    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat> {
        // Check if targeting few unique ports (focused attack) with high failure
        if features.unique_dst_ports > 5 {
            return Vec::new(); // Too many ports — more likely a scan
        }
        if features.connection_count < self.max_auth_connections {
            return Vec::new();
        }
        if features.failed_conn_ratio < self.min_failed_ratio {
            return Vec::new();
        }

        let score = ThreatScore::new(
            (features.connection_count as f64 / (self.max_auth_connections as f64 * 10.0)).min(0.5)
                + features.failed_conn_ratio * 0.5,
        );

        let evidence = ThreatEvidence::new(&format!(
            "{} connections to {} port(s) with {:.0}% failure rate",
            features.connection_count,
            features.unique_dst_ports,
            features.failed_conn_ratio * 100.0,
        ))
        .with_metric("connection_count", features.connection_count as f64)
        .with_metric("failed_ratio", features.failed_conn_ratio);

        vec![Threat::new(
            ThreatType::BruteForce,
            score,
            features.source_ip,
            format!("Brute force attack from {}", features.source_ip),
            evidence,
        )]
    }
}
