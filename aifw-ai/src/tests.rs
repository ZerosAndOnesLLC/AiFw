#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use aifw_pf::{PfBackend, PfMock, PfState};

    use crate::detectors::{self, Detector};
    use crate::features;
    use crate::inference::{InferenceBackend, StubInference};
    use crate::response::{AutoResponder, ResponseAction, ResponseConfig};
    use crate::types::{Threat, ThreatEvidence, ThreatScore, ThreatType};

    fn make_scan_states() -> Vec<PfState> {
        // Simulate a port scan: many unique ports, mostly failed
        (1..50)
            .map(|i| PfState {
                id: i as u64,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
                src_port: 40000 + i,
                dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: i,
                state: "SYN_SENT:CLOSED".to_string(),
                packets_in: 0,
                packets_out: 1,
                bytes_in: 0,
                bytes_out: 60,
                age_secs: 1,
                iface: None,
                rtable: None,
            })
            .collect()
    }

    fn make_ddos_states() -> Vec<PfState> {
        (0..500)
            .map(|i| PfState {
                id: i as u64,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)),
                src_port: 30000 + (i % 1000),
                dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 80,
                state: "SYN_SENT:SYN_SENT".to_string(),
                packets_in: 0,
                packets_out: 1,
                bytes_in: 0,
                bytes_out: 60,
                age_secs: 1,
                iface: None,
                rtable: None,
            })
            .collect()
    }

    fn make_brute_force_states() -> Vec<PfState> {
        (0..50)
            .map(|i| PfState {
                id: i as u64,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                src_port: 50000 + i,
                dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 22,
                state: "CLOSED:CLOSED".to_string(),
                packets_in: 3,
                packets_out: 3,
                bytes_in: 200,
                bytes_out: 200,
                age_secs: 2,
                iface: None,
                rtable: None,
            })
            .collect()
    }

    fn make_c2_states() -> Vec<PfState> {
        (0..10)
            .map(|i| PfState {
                id: i as u64,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 75)),
                src_port: 60000 + i,
                dst_addr: IpAddr::V4(Ipv4Addr::new(185, 100, 50, 1)),
                dst_port: 443,
                state: "ESTABLISHED:ESTABLISHED".to_string(),
                packets_in: 2,
                packets_out: 2,
                bytes_in: 100,
                bytes_out: 50,
                age_secs: 60,
                iface: None,
                rtable: None, // regular interval
            })
            .collect()
    }

    fn make_dns_tunnel_states() -> Vec<PfState> {
        (0..100)
            .map(|i| PfState {
                id: i as u64,
                protocol: "udp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30)),
                src_port: 40000 + i,
                dst_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                dst_port: 53,
                state: "SINGLE:NO_TRAFFIC".to_string(),
                packets_in: 1,
                packets_out: 1,
                bytes_in: 500,
                bytes_out: 200,
                age_secs: 1,
                iface: None,
                rtable: None,
            })
            .collect()
    }

    // --- Feature extraction tests ---

    #[test]
    fn test_feature_extraction() {
        let states = make_scan_states();
        let features = features::extract_features(&states, 60);
        assert_eq!(features.len(), 1);
        let f = &features[0];
        assert_eq!(f.source_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)));
        assert_eq!(f.connection_count, 49);
        assert_eq!(f.unique_dst_ports, 49);
        assert_eq!(f.unique_dst_ips, 1);
        assert!(f.failed_conn_ratio > 0.9); // all SYN_SENT
    }

    #[test]
    fn test_feature_vector() {
        let states = make_scan_states();
        let features = features::extract_features(&states, 60);
        let vec = features[0].to_feature_vector();
        assert_eq!(vec.len(), 13);
    }

    // --- Detector tests ---

    #[tokio::test]
    async fn test_port_scan_detection() {
        let states = make_scan_states();
        let features = features::extract_features(&states, 60);
        let detector = detectors::port_scan::PortScanDetector::new();
        let threats = detector.analyze(&features[0]).await;
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, ThreatType::PortScan);
        assert!(threats[0].score.value() > 0.3);
    }

    #[tokio::test]
    async fn test_ddos_detection() {
        let states = make_ddos_states();
        let features = features::extract_features(&states, 10);
        let detector = detectors::ddos::DdosDetector::new();
        let f = features
            .iter()
            .find(|f| f.source_ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)))
            .unwrap();
        let threats = detector.analyze(f).await;
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.threat_type == ThreatType::DDoS));
    }

    #[tokio::test]
    async fn test_brute_force_detection() {
        let states = make_brute_force_states();
        let features = features::extract_features(&states, 60);
        let detector = detectors::brute_force::BruteForceDetector::new();
        let threats = detector.analyze(&features[0]).await;
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, ThreatType::BruteForce);
    }

    #[tokio::test]
    async fn test_c2_beacon_detection() {
        let states = make_c2_states();
        let features = features::extract_features(&states, 600);
        let detector = detectors::c2_beacon::C2BeaconDetector::new();
        let threats = detector.analyze(&features[0]).await;
        // C2 beacon detected: low variance, single dest, small payloads
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, ThreatType::C2Beacon);
    }

    #[tokio::test]
    async fn test_dns_tunnel_detection() {
        let states = make_dns_tunnel_states();
        let features = features::extract_features(&states, 60);
        let detector = detectors::dns_tunnel::DnsTunnelDetector::new();
        let threats = detector.analyze(&features[0]).await;
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, ThreatType::DnsTunnel);
    }

    #[tokio::test]
    async fn test_run_all_detectors() {
        let states = make_scan_states();
        let features = features::extract_features(&states, 60);
        let detectors = detectors::default_detectors();
        let threats = detectors::run_all_detectors(&detectors, &features).await;
        assert!(!threats.is_empty());
    }

    #[tokio::test]
    async fn test_normal_traffic_no_threats() {
        // Normal traffic: few connections, established, diverse but not excessive
        let states: Vec<PfState> = (0..5)
            .map(|i| PfState {
                id: i,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 50000 + i as u16,
                dst_addr: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                dst_port: 443,
                state: "ESTABLISHED:ESTABLISHED".to_string(),
                packets_in: 100,
                packets_out: 50,
                bytes_in: 50000,
                bytes_out: 5000,
                age_secs: 300,
                iface: None,
                rtable: None,
            })
            .collect();

        let features = features::extract_features(&states, 300);
        let detectors = detectors::default_detectors();
        let threats = detectors::run_all_detectors(&detectors, &features).await;
        // Normal traffic should produce no high-severity threats
        let high_threats: Vec<_> = threats.iter().filter(|t| t.score.is_high()).collect();
        assert!(high_threats.is_empty());
    }

    // --- Inference tests ---

    #[tokio::test]
    async fn test_stub_inference() {
        let mut backend = StubInference::new();
        backend.load_model("test-model").await.unwrap();
        assert!(backend.model_info().loaded);

        // Normal traffic features
        let normal = vec![
            5.0, 1.0, 1.0, 5000.0, 50000.0, 150.0, 0.0, 0.0, 0.02, 10000.0, 0.0, 100.0, 0.0,
        ];
        let score = backend.predict(&normal).await.unwrap();
        assert!(score < 0.5);

        // Suspicious features (high rate, many ports, many SYNs)
        let suspicious = vec![
            200.0, 50.0, 50.0, 10000.0, 0.0, 200.0, 50.0, 0.9, 20.0, 60.0, 0.0, 1.0, 0.5,
        ];
        let score = backend.predict(&suspicious).await.unwrap();
        assert!(score > 0.5);
    }

    // --- Threat score tests ---

    #[test]
    fn test_threat_score() {
        let low = ThreatScore::new(0.2);
        assert_eq!(low.severity(), "low");
        assert!(!low.is_medium());

        let med = ThreatScore::new(0.5);
        assert_eq!(med.severity(), "medium");
        assert!(med.is_medium());

        let high = ThreatScore::new(0.8);
        assert_eq!(high.severity(), "high");
        assert!(high.is_high());

        let crit = ThreatScore::new(0.95);
        assert_eq!(crit.severity(), "critical");
        assert!(crit.is_critical());

        // Clamping
        assert_eq!(ThreatScore::new(1.5).value(), 1.0);
        assert_eq!(ThreatScore::new(-0.5).value(), 0.0);
    }

    // --- Auto-response tests ---

    #[tokio::test]
    async fn test_response_action_thresholds() {
        let pf: Arc<dyn PfBackend> = Arc::new(PfMock::new());
        let responder = AutoResponder::new(pf, ResponseConfig::default());

        let make_threat = |score: f64| {
            Threat::new(
                ThreatType::PortScan,
                ThreatScore::new(score),
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                "test".to_string(),
                ThreatEvidence::new("test"),
            )
        };

        assert_eq!(
            responder.determine_action(&make_threat(0.2)),
            ResponseAction::Alert
        );
        assert_eq!(
            responder.determine_action(&make_threat(0.3)),
            ResponseAction::Alert
        );
        assert_eq!(
            responder.determine_action(&make_threat(0.6)),
            ResponseAction::RateLimit
        );
        assert_eq!(
            responder.determine_action(&make_threat(0.8)),
            ResponseAction::TempBlock
        );
        assert_eq!(
            responder.determine_action(&make_threat(0.96)),
            ResponseAction::PermBlock
        );
    }

    #[tokio::test]
    async fn test_respond_temp_block() {
        let mock = Arc::new(PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let responder = AutoResponder::new(pf, ResponseConfig::default());

        let threat = Threat::new(
            ThreatType::DDoS,
            ThreatScore::new(0.85),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            "DDoS attack".to_string(),
            ThreatEvidence::new("high rate"),
        );

        let action = responder.respond(&threat).await;
        assert_eq!(action, ResponseAction::TempBlock);

        // IP should be in the block table
        let entries = mock.get_table_entries("ai_blocked").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)));

        // Should have a temp block record
        let blocks = responder.active_temp_blocks().await;
        assert_eq!(blocks.len(), 1);

        // History should be recorded
        let history = responder.history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].action, ResponseAction::TempBlock);
    }

    #[tokio::test]
    async fn test_expire_temp_blocks() {
        let mock = Arc::new(PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let config = ResponseConfig {
            temp_block_duration_secs: 0, // expire immediately
            ..Default::default()
        };
        let responder = AutoResponder::new(pf, config);

        let threat = Threat::new(
            ThreatType::PortScan,
            ThreatScore::new(0.8),
            IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)),
            "scan".to_string(),
            ThreatEvidence::new("ports"),
        );

        responder.respond(&threat).await;

        // Expire — should remove the block since duration is 0
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let expired = responder.expire_temp_blocks().await;
        assert_eq!(expired, 1);

        let blocks = responder.active_temp_blocks().await;
        assert!(blocks.is_empty());
    }
}
