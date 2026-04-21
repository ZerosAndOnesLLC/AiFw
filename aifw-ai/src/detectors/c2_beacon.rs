use async_trait::async_trait;

use super::Detector;
use crate::features::TrafficFeatures;
use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

pub struct C2BeaconDetector {
    /// Low duration variance indicates periodic beaconing
    pub max_duration_variance: f64,
    /// Minimum connections to consider (need pattern)
    pub min_connections: u64,
}

impl C2BeaconDetector {
    pub fn new() -> Self {
        Self {
            max_duration_variance: 5.0,
            min_connections: 5,
        }
    }
}

impl Default for C2BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for C2BeaconDetector {
    fn name(&self) -> &str {
        "c2_beacon"
    }

    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat> {
        if features.connection_count < self.min_connections {
            return Vec::new();
        }

        // C2 beacons: regular intervals (low variance), small payloads, single destination
        if features.unique_dst_ips > 2 {
            return Vec::new();
        }
        if features.duration_variance > self.max_duration_variance {
            return Vec::new();
        }
        if features.avg_payload_size > 10000.0 {
            return Vec::new(); // Large payloads unlikely for beaconing
        }

        let variance_score =
            (1.0 - features.duration_variance / self.max_duration_variance).max(0.0) * 0.5;
        let regularity_score = if features.unique_dst_ips == 1 {
            0.3
        } else {
            0.1
        };
        let score = ThreatScore::new(variance_score + regularity_score);

        if score.value() < 0.3 {
            return Vec::new();
        }

        let evidence = ThreatEvidence::new(&format!(
            "{} connections to {} host(s), duration variance {:.2}, avg payload {:.0}B",
            features.connection_count,
            features.unique_dst_ips,
            features.duration_variance,
            features.avg_payload_size,
        ))
        .with_metric("duration_variance", features.duration_variance)
        .with_metric("unique_dst_ips", features.unique_dst_ips as f64)
        .with_metric("avg_payload", features.avg_payload_size);

        vec![Threat::new(
            ThreatType::C2Beacon,
            score,
            features.source_ip,
            format!("Possible C2 beacon from {}", features.source_ip),
            evidence,
        )]
    }
}
