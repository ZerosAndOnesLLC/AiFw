use async_trait::async_trait;

use super::Detector;
use crate::features::TrafficFeatures;
use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

pub struct DnsTunnelDetector {
    /// High DNS query count threshold
    pub max_dns_queries: u64,
    /// High DNS query ratio (DNS queries / total connections)
    pub max_dns_ratio: f64,
}

impl DnsTunnelDetector {
    pub fn new() -> Self {
        Self {
            max_dns_queries: 50,
            max_dns_ratio: 0.8,
        }
    }
}

impl Default for DnsTunnelDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for DnsTunnelDetector {
    fn name(&self) -> &str {
        "dns_tunnel"
    }

    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat> {
        if features.dns_query_count < self.max_dns_queries {
            return Vec::new();
        }

        let dns_ratio = if features.connection_count > 0 {
            features.dns_query_count as f64 / features.connection_count as f64
        } else {
            0.0
        };

        if dns_ratio < self.max_dns_ratio {
            return Vec::new();
        }

        let score = ThreatScore::new(
            (features.dns_query_count as f64 / (self.max_dns_queries as f64 * 5.0)).min(0.5)
                + dns_ratio * 0.5,
        );

        let evidence = ThreatEvidence::new(&format!(
            "{} DNS queries ({:.0}% of all connections), avg payload {:.0}B",
            features.dns_query_count,
            dns_ratio * 100.0,
            features.avg_payload_size,
        ))
        .with_metric("dns_queries", features.dns_query_count as f64)
        .with_metric("dns_ratio", dns_ratio)
        .with_metric("avg_payload", features.avg_payload_size);

        vec![Threat::new(
            ThreatType::DnsTunnel,
            score,
            features.source_ip,
            format!("Possible DNS tunnel from {}", features.source_ip),
            evidence,
        )]
    }
}
