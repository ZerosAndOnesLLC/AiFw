#[cfg(test)]
mod tests {
    use aifw_common::*;
    use aifw_pf::PfBackend;
    use std::sync::Arc;

    use crate::db::Database;
    use crate::engine::RuleEngine;
    use crate::validation::validate_rule;

    fn make_test_rule() -> Rule {
        Rule::new(
            Action::Block,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 22,
                    end: 22,
                }),
            },
        )
    }

    #[test]
    fn test_validate_valid_rule() {
        let rule = make_test_rule();
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_invalid_port_range() {
        let mut rule = make_test_rule();
        rule.rule_match.dst_port = Some(PortRange {
            start: 9000,
            end: 80,
        });
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_port_requires_tcp_udp() {
        let mut rule = make_test_rule();
        rule.protocol = Protocol::Icmp;
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_priority_bounds() {
        let mut rule = make_test_rule();
        rule.priority = -1;
        assert!(validate_rule(&rule).is_err());

        rule.priority = 10001;
        assert!(validate_rule(&rule).is_err());

        rule.priority = 0;
        assert!(validate_rule(&rule).is_ok());

        rule.priority = 10000;
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_invalid_prefix() {
        let mut rule = make_test_rule();
        rule.rule_match.src_addr =
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)), 33);
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_empty_table_name() {
        let mut rule = make_test_rule();
        rule.rule_match.src_addr = Address::Table(String::new());
        assert!(validate_rule(&rule).is_err());
    }

    #[tokio::test]
    async fn test_engine_add_list_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let rule = make_test_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
    }

    #[tokio::test]
    async fn test_engine_delete_rule() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let rule = make_test_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();
        engine.delete_rule(id).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_engine_delete_nonexistent() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let result = engine.delete_rule(uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_engine_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db, pf);

        engine.add_rule(make_test_rule()).await.unwrap();

        let mut rule2 = Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
            },
        );
        rule2.priority = 50;
        engine.add_rule(rule2).await.unwrap();

        engine.apply_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw").await.unwrap();
        assert_eq!(pf_rules.len(), 2);
        // Lower priority first
        assert!(pf_rules[0].contains("443"));
        assert!(pf_rules[1].contains("22"));
    }

    #[tokio::test]
    async fn test_engine_flush_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db, pf);

        engine.add_rule(make_test_rule()).await.unwrap();
        engine.apply_rules().await.unwrap();

        let before = mock.get_rules("aifw").await.unwrap();
        assert_eq!(before.len(), 1);

        engine.flush_rules().await.unwrap();
        let after = mock.get_rules("aifw").await.unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn test_db_roundtrip() {
        let db = Database::new_in_memory().await.unwrap();

        let rule = make_test_rule();
        let id = rule.id;
        db.insert_rule(&rule).await.unwrap();

        let fetched = db.get_rule(id).await.unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.action, Action::Block);
        assert_eq!(fetched.direction, Direction::In);
        assert_eq!(fetched.protocol, Protocol::Tcp);
        assert_eq!(fetched.rule_match.dst_port.as_ref().unwrap().start, 22);
    }

    #[tokio::test]
    async fn test_db_list_ordering() {
        let db = Database::new_in_memory().await.unwrap();

        let mut r1 = make_test_rule();
        r1.priority = 200;
        let mut r2 = make_test_rule();
        r2.priority = 50;
        let mut r3 = make_test_rule();
        r3.priority = 100;

        db.insert_rule(&r1).await.unwrap();
        db.insert_rule(&r2).await.unwrap();
        db.insert_rule(&r3).await.unwrap();

        let rules = db.list_rules().await.unwrap();
        assert_eq!(rules[0].priority, 50);
        assert_eq!(rules[1].priority, 100);
        assert_eq!(rules[2].priority, 200);
    }

    #[tokio::test]
    async fn test_db_state_options_roundtrip() {
        let db = Database::new_in_memory().await.unwrap();

        let mut rule = make_test_rule();
        rule.state_options = StateOptions {
            tracking: StateTracking::ModulateState,
            policy: Some(StatePolicy::IfBound),
            adaptive_timeouts: Some(AdaptiveTimeouts {
                start: 5000,
                end: 10000,
            }),
            timeout_tcp: Some(3600),
            timeout_udp: Some(60),
            timeout_icmp: None,
        };
        let id = rule.id;
        db.insert_rule(&rule).await.unwrap();

        let fetched = db.get_rule(id).await.unwrap().unwrap();
        assert_eq!(fetched.state_options.tracking, StateTracking::ModulateState);
        assert_eq!(fetched.state_options.policy, Some(StatePolicy::IfBound));
        let adaptive = fetched.state_options.adaptive_timeouts.unwrap();
        assert_eq!(adaptive.start, 5000);
        assert_eq!(adaptive.end, 10000);
        assert_eq!(fetched.state_options.timeout_tcp, Some(3600));
        assert_eq!(fetched.state_options.timeout_udp, Some(60));
        assert_eq!(fetched.state_options.timeout_icmp, None);
    }

    #[tokio::test]
    async fn test_audit_trail() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let rule = make_test_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();
        engine.delete_rule(id).await.unwrap();

        let entries = engine.audit().list(10).await.unwrap();
        assert_eq!(entries.len(), 2);
        // Most recent first
        assert_eq!(entries[0].action, crate::audit::AuditAction::RuleRemoved);
        assert_eq!(entries[1].action, crate::audit::AuditAction::RuleAdded);
    }

    #[tokio::test]
    async fn test_audit_for_apply_and_flush() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db, pf);

        engine.add_rule(make_test_rule()).await.unwrap();
        engine.apply_rules().await.unwrap();
        engine.flush_rules().await.unwrap();

        let entries = engine.audit().list(10).await.unwrap();
        assert_eq!(entries.len(), 3); // add + apply + flush
        assert_eq!(entries[0].action, crate::audit::AuditAction::RulesFlushed);
        assert_eq!(entries[1].action, crate::audit::AuditAction::RulesApplied);
    }

    // --- NAT engine tests ---

    fn make_test_nat_rule() -> NatRule {
        NatRule::new(
            NatType::Snat,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 0)),
                24,
            ),
            Address::Any,
            NatRedirect {
                address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    203, 0, 113, 1,
                ))),
                port: None,
            },
        )
    }

    async fn create_nat_engine() -> crate::nat::NatEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        crate::nat::NatEngine::new(db.pool().clone(), pf)
    }

    #[tokio::test]
    async fn test_nat_add_list() {
        let engine = create_nat_engine().await;

        let rule = make_test_nat_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
        assert_eq!(rules[0].nat_type, NatType::Snat);
    }

    #[tokio::test]
    async fn test_nat_delete() {
        let engine = create_nat_engine().await;

        let rule = make_test_nat_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();
        engine.delete_rule(id).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_nat_delete_nonexistent() {
        let engine = create_nat_engine().await;
        assert!(engine.delete_rule(uuid::Uuid::new_v4()).await.is_err());
    }

    #[tokio::test]
    async fn test_nat_db_roundtrip() {
        let engine = create_nat_engine().await;

        let mut rule = NatRule::new(
            NatType::Dnat,
            Interface("em0".to_string()),
            Protocol::Tcp,
            Address::Any,
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1))),
            NatRedirect {
                address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    192, 168, 1, 10,
                ))),
                port: Some(PortRange {
                    start: 8080,
                    end: 8080,
                }),
            },
        );
        rule.dst_port = Some(PortRange {
            start: 80,
            end: 80,
        });
        rule.label = Some("web-redirect".to_string());
        let id = rule.id;

        engine.add_rule(rule).await.unwrap();
        let fetched = engine.get_rule(id).await.unwrap();

        assert_eq!(fetched.nat_type, NatType::Dnat);
        assert_eq!(fetched.protocol, Protocol::Tcp);
        assert_eq!(fetched.interface.0, "em0");
        assert_eq!(fetched.dst_port.as_ref().unwrap().start, 80);
        assert_eq!(fetched.redirect.port.as_ref().unwrap().start, 8080);
        assert_eq!(fetched.label.as_deref(), Some("web-redirect"));
    }

    #[tokio::test]
    async fn test_nat_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::nat::NatEngine::new(db.pool().clone(), pf);

        engine.add_rule(make_test_nat_rule()).await.unwrap();
        engine.apply_rules().await.unwrap();

        let nat_rules = mock.get_nat_rules("aifw").await.unwrap();
        assert_eq!(nat_rules.len(), 1);
        assert!(nat_rules[0].contains("nat on em0"));
    }

    #[tokio::test]
    async fn test_nat_validation_dnat_needs_port() {
        let engine = create_nat_engine().await;

        let rule = NatRule::new(
            NatType::Dnat,
            Interface("em0".to_string()),
            Protocol::Tcp,
            Address::Any,
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            NatRedirect {
                address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    10, 0, 0, 1,
                ))),
                port: None,
            },
        );
        // DNAT without any port should fail validation
        assert!(engine.add_rule(rule).await.is_err());
    }

    #[tokio::test]
    async fn test_nat_validation_needs_interface() {
        let engine = create_nat_engine().await;

        let rule = NatRule::new(
            NatType::Snat,
            Interface(String::new()),
            Protocol::Any,
            Address::Any,
            Address::Any,
            NatRedirect {
                address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    1, 2, 3, 4,
                ))),
                port: None,
            },
        );
        assert!(engine.add_rule(rule).await.is_err());
    }

    // --- Shaping engine tests ---

    async fn create_shaping_engine() -> crate::shaping::ShapingEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = crate::shaping::ShapingEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn test_queue_add_list_delete() {
        let engine = create_shaping_engine().await;

        let q = QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Codel,
            Bandwidth { value: 100, unit: BandwidthUnit::Mbps },
            "test_queue".to_string(),
            TrafficClass::Default,
        );
        let id = q.id;
        engine.add_queue(q).await.unwrap();

        let queues = engine.list_queues().await.unwrap();
        assert_eq!(queues.len(), 1);
        assert_eq!(queues[0].name, "test_queue");

        engine.delete_queue(id).await.unwrap();
        assert!(engine.list_queues().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_queue_db_roundtrip() {
        let engine = create_shaping_engine().await;

        let mut q = QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Priq,
            Bandwidth { value: 1, unit: BandwidthUnit::Gbps },
            "voip".to_string(),
            TrafficClass::Voip,
        );
        q.bandwidth_pct = Some(20);
        q.default = true;
        engine.add_queue(q).await.unwrap();

        let queues = engine.list_queues().await.unwrap();
        let fetched = &queues[0];
        assert_eq!(fetched.queue_type, QueueType::Priq);
        assert_eq!(fetched.bandwidth.value, 1);
        assert_eq!(fetched.bandwidth.unit, BandwidthUnit::Gbps);
        assert_eq!(fetched.traffic_class, TrafficClass::Voip);
        assert_eq!(fetched.bandwidth_pct, Some(20));
        assert!(fetched.default);
    }

    #[tokio::test]
    async fn test_queue_apply() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::shaping::ShapingEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        engine.add_queue(QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Codel,
            Bandwidth { value: 100, unit: BandwidthUnit::Mbps },
            "default_q".to_string(),
            TrafficClass::Default,
        )).await.unwrap();

        engine.apply_queues().await.unwrap();

        let pf_queues = mock.get_queues("aifw").await.unwrap();
        assert_eq!(pf_queues.len(), 2); // parent + child
        assert!(pf_queues[0].contains("queue on em0"));
        assert!(pf_queues[1].contains("queue default_q"));
    }

    #[tokio::test]
    async fn test_ratelimit_add_list_delete() {
        let engine = create_shaping_engine().await;

        let rl = RateLimitRule::new(
            "ssh-protect".to_string(),
            Protocol::Tcp,
            5,
            30,
            "bruteforce".to_string(),
        );
        let id = rl.id;
        engine.add_rate_limit(rl).await.unwrap();

        let rules = engine.list_rate_limits().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "ssh-protect");

        engine.delete_rate_limit(id).await.unwrap();
        assert!(engine.list_rate_limits().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_ratelimit_db_roundtrip() {
        let engine = create_shaping_engine().await;

        let mut rl = RateLimitRule::new(
            "web-limit".to_string(),
            Protocol::Tcp,
            100,
            60,
            "web_flood".to_string(),
        );
        rl.dst_port = Some(PortRange { start: 80, end: 80 });
        rl.interface = Some(Interface("em0".to_string()));
        rl.flush_states = false;
        engine.add_rate_limit(rl).await.unwrap();

        let rules = engine.list_rate_limits().await.unwrap();
        let fetched = &rules[0];
        assert_eq!(fetched.name, "web-limit");
        assert_eq!(fetched.max_connections, 100);
        assert_eq!(fetched.window_secs, 60);
        assert_eq!(fetched.overload_table, "web_flood");
        assert_eq!(fetched.dst_port.as_ref().unwrap().start, 80);
        assert_eq!(fetched.interface.as_ref().unwrap().0, "em0");
        assert!(!fetched.flush_states);
    }

    #[tokio::test]
    async fn test_ratelimit_validation() {
        let engine = create_shaping_engine().await;

        // max_connections = 0 should fail
        let rl = RateLimitRule::new("bad".to_string(), Protocol::Tcp, 0, 60, "t".to_string());
        assert!(engine.add_rate_limit(rl).await.is_err());

        // window_secs = 0 should fail
        let rl = RateLimitRule::new("bad".to_string(), Protocol::Tcp, 5, 0, "t".to_string());
        assert!(engine.add_rate_limit(rl).await.is_err());

        // empty table should fail
        let rl = RateLimitRule::new("bad".to_string(), Protocol::Tcp, 5, 60, String::new());
        assert!(engine.add_rate_limit(rl).await.is_err());
    }

    #[tokio::test]
    async fn test_ratelimit_apply() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::shaping::ShapingEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        engine.add_rate_limit(RateLimitRule::new(
            "ssh".to_string(),
            Protocol::Tcp,
            5,
            30,
            "bruteforce".to_string(),
        )).await.unwrap();

        engine.apply_rate_limits().await.unwrap();

        let pf_rules = mock.get_rules("aifw-ratelimit").await.unwrap();
        assert_eq!(pf_rules.len(), 3); // table + block + pass
        assert!(pf_rules[0].contains("table <bruteforce>"));
        assert!(pf_rules[1].contains("block in quick from <bruteforce>"));
        assert!(pf_rules[2].contains("overload <bruteforce>"));
    }

    // --- VPN engine tests ---

    async fn create_vpn_engine() -> crate::vpn::VpnEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = crate::vpn::VpnEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn test_wg_tunnel_crud() {
        let engine = create_vpn_engine().await;

        let tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 24),
        );
        let id = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        let tunnels = engine.list_wg_tunnels().await.unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].name, "wg0");
        assert_eq!(tunnels[0].listen_port, 51820);

        engine.delete_wg_tunnel(id).await.unwrap();
        assert!(engine.list_wg_tunnels().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_wg_tunnel_db_roundtrip() {
        let engine = create_vpn_engine().await;

        let mut tunnel = WgTunnel::new(
            "office".to_string(),
            Interface("wg1".to_string()),
            51821,
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1)), 24),
        );
        tunnel.dns = Some("1.1.1.1".to_string());
        tunnel.mtu = Some(1420);
        let id = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        let fetched = engine.get_wg_tunnel(id).await.unwrap();
        assert_eq!(fetched.name, "office");
        assert_eq!(fetched.interface.0, "wg1");
        assert_eq!(fetched.dns, Some("1.1.1.1".to_string()));
        assert_eq!(fetched.mtu, Some(1420));
        assert!(!fetched.private_key.is_empty());
        assert!(!fetched.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_wg_peer_crud() {
        let engine = create_vpn_engine().await;

        let tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 24),
        );
        let tid = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        let mut peer = WgPeer::new(tid, "laptop".to_string(), "fakepubkey123".to_string());
        peer.endpoint = Some("1.2.3.4:51820".to_string());
        peer.allowed_ips = vec![
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 32),
        ];
        peer.persistent_keepalive = Some(25);
        let pid = peer.id;
        engine.add_wg_peer(peer).await.unwrap();

        let peers = engine.list_wg_peers(tid).await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "laptop");
        assert_eq!(peers[0].endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(peers[0].persistent_keepalive, Some(25));

        engine.delete_wg_peer(pid).await.unwrap();
        assert!(engine.list_wg_peers(tid).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_wg_tunnel_validation() {
        let engine = create_vpn_engine().await;

        // Empty name
        let t = WgTunnel::new(
            String::new(),
            Interface("wg0".to_string()),
            51820,
            Address::Any,
        );
        assert!(engine.add_wg_tunnel(t).await.is_err());

        // Zero port
        let mut t = WgTunnel::new(
            "test".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Any,
        );
        t.listen_port = 0;
        assert!(engine.add_wg_tunnel(t).await.is_err());
    }

    #[tokio::test]
    async fn test_ipsec_sa_crud() {
        let engine = create_vpn_engine().await;

        let sa = IpsecSa::new(
            "office".to_string(),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1))),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1))),
            IpsecProtocol::Esp,
            IpsecMode::Tunnel,
        );
        let id = sa.id;
        engine.add_ipsec_sa(sa).await.unwrap();

        let sas = engine.list_ipsec_sas().await.unwrap();
        assert_eq!(sas.len(), 1);
        assert_eq!(sas[0].name, "office");
        assert_eq!(sas[0].protocol, IpsecProtocol::Esp);
        assert_eq!(sas[0].mode, IpsecMode::Tunnel);

        engine.delete_ipsec_sa(id).await.unwrap();
        assert!(engine.list_ipsec_sas().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_vpn_apply_pf_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::vpn::VpnEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        engine.add_wg_tunnel(WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 24),
        )).await.unwrap();

        engine.add_ipsec_sa(IpsecSa::new(
            "ipsec0".to_string(),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8))),
            IpsecProtocol::Esp,
            IpsecMode::Tunnel,
        )).await.unwrap();

        engine.apply_vpn_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw-vpn").await.unwrap();
        // 2 WG rules + 5 IPsec rules (tunnel mode)
        assert_eq!(pf_rules.len(), 7);
        assert!(pf_rules.iter().any(|r| r.contains("port 51820")));
        assert!(pf_rules.iter().any(|r| r.contains("proto esp")));
        assert!(pf_rules.iter().any(|r| r.contains("on enc0")));
    }
}
