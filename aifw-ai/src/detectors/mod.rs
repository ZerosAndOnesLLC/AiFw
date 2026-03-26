pub mod brute_force;
pub mod c2_beacon;
pub mod ddos;
pub mod dns_tunnel;
pub mod port_scan;

use async_trait::async_trait;

use crate::features::TrafficFeatures;
use crate::types::Threat;

/// Trait for all threat detectors
#[async_trait]
pub trait Detector: Send + Sync {
    /// Analyze traffic features and return any detected threats
    async fn analyze(&self, features: &TrafficFeatures) -> Vec<Threat>;

    /// Detector name
    fn name(&self) -> &str;
}

/// Run all detectors against a set of features
pub async fn run_all_detectors(
    detectors: &[Box<dyn Detector>],
    features: &[TrafficFeatures],
) -> Vec<Threat> {
    let mut threats = Vec::new();
    for f in features {
        for d in detectors {
            let mut detected = d.analyze(f).await;
            threats.append(&mut detected);
        }
    }
    threats
}

/// Create the default set of detectors
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(port_scan::PortScanDetector::new()),
        Box::new(ddos::DdosDetector::new()),
        Box::new(brute_force::BruteForceDetector::new()),
        Box::new(c2_beacon::C2BeaconDetector::new()),
        Box::new(dns_tunnel::DnsTunnelDetector::new()),
    ]
}
