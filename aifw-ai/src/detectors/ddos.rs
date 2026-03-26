use async_trait::async_trait;

use super::Detector;
use crate::features::TrafficFeatures;
use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

pub struct DdosDetector {
    /// Connections per second threshold
    pub max_conn_rate: f64,
    /// SYN count threshold
    pub max_syn_count: u64,
}

impl DdosDetector {
    pub fn new() -> Self {
        Self {
            max_conn_rate: 50.0,
            max_syn_count: 100,
        }
    }
}

impl Default for DdosDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for DdosDetector {
    fn name(&self) -> &str {
        "ddos"
    }

    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat> {
        let mut threats = Vec::new();

        // SYN flood detection
        if features.syn_count > self.max_syn_count && features.failed_conn_ratio > 0.8 {
            let score = ThreatScore::new(
                (features.syn_count as f64 / (self.max_syn_count as f64 * 5.0)).min(1.0),
            );

            let evidence = ThreatEvidence::new(&format!(
                "{} SYN packets with {:.0}% connection failure rate",
                features.syn_count,
                features.failed_conn_ratio * 100.0
            ))
            .with_metric("syn_count", features.syn_count as f64)
            .with_metric("failed_ratio", features.failed_conn_ratio);

            threats.push(Threat::new(
                ThreatType::DDoS,
                score,
                features.source_ip,
                format!("SYN flood from {}", features.source_ip),
                evidence,
            ));
        }

        // Volume-based DDoS
        if features.conn_rate > self.max_conn_rate {
            let score =
                ThreatScore::new((features.conn_rate / (self.max_conn_rate * 5.0)).min(1.0));

            let evidence = ThreatEvidence::new(&format!(
                "{:.1} connections/sec (threshold: {:.1})",
                features.conn_rate, self.max_conn_rate
            ))
            .with_metric("conn_rate", features.conn_rate)
            .with_metric("bytes_in", features.bytes_in as f64);

            threats.push(Threat::new(
                ThreatType::DDoS,
                score,
                features.source_ip,
                format!("High-rate DDoS from {}", features.source_ip),
                evidence,
            ));
        }

        threats
    }
}
