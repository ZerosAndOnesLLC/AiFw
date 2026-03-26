use async_trait::async_trait;

use super::Detector;
use crate::features::TrafficFeatures;
use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

pub struct PortScanDetector {
    /// Minimum unique ports to trigger detection
    pub min_unique_ports: u64,
    /// Minimum failed connection ratio
    pub min_failed_ratio: f64,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            min_unique_ports: 15,
            min_failed_ratio: 0.6,
        }
    }
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for PortScanDetector {
    fn name(&self) -> &str {
        "port_scan"
    }

    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat> {
        if features.unique_dst_ports < self.min_unique_ports {
            return Vec::new();
        }
        if features.failed_conn_ratio < self.min_failed_ratio {
            return Vec::new();
        }

        // Score based on port count and failure rate
        let port_score = (features.unique_dst_ports as f64 / 100.0).min(0.5);
        let fail_score = features.failed_conn_ratio * 0.5;
        let score = ThreatScore::new(port_score + fail_score);

        let evidence = ThreatEvidence::new(&format!(
            "scanned {} unique ports with {:.0}% failed connections",
            features.unique_dst_ports,
            features.failed_conn_ratio * 100.0
        ))
        .with_metric("unique_ports", features.unique_dst_ports as f64)
        .with_metric("failed_ratio", features.failed_conn_ratio);

        vec![Threat::new(
            ThreatType::PortScan,
            score,
            features.source_ip,
            format!("Port scan detected from {}", features.source_ip),
            evidence,
        )]
    }
}
