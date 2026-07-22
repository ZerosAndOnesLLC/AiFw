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
                dst_port: Some(PortRange { start: 22, end: 22 }),
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
        rule.rule_match.src_addr = Address::Network(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)),
            33,
        );
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_empty_table_name() {
        let mut rule = make_test_rule();
        rule.rule_match.src_addr = Address::Table(String::new());
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_rejects_table_name_injection() {
        // SEC-H6: a table name with a newline renders into pf rule text and lets
        // pf parse the second line as its own rule. validate_rule must reject it.
        let mut rule = make_test_rule();
        rule.rule_match.src_addr = Address::Table("x\n pass quick all keep state #".to_string());
        assert!(validate_rule(&rule).is_err());

        rule.rule_match.src_addr = Address::Table("blocklist".to_string());
        assert!(validate_rule(&rule).is_ok());
    }

    #[tokio::test]
    async fn test_engine_add_list_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
        let engine = RuleEngine::new(db.pool().clone(), pf);

        let result = engine.delete_rule(uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_engine_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
    async fn test_engine_schedule_gating() {
        // apply_rules must exclude rules whose schedule window is closed and
        // keep rules whose schedule is open, disabled, or dangling (#537).
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db.pool().clone(), pf);

        let insert_schedule = |id: &str, name: &str, ranges: &str, days: &str, enabled: bool| {
            let q = sqlx::query(
                "INSERT INTO schedules (id, name, time_ranges, days_of_week, enabled, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(id.to_string())
            .bind(name.to_string())
            .bind(ranges.to_string())
            .bind(days.to_string())
            .bind(enabled)
            .bind("2026-01-01T00:00:00Z");
            let pool = db.pool().clone();
            async move { q.execute(&pool).await.unwrap() }
        };
        // No listed days → never inside the window, regardless of clock
        insert_schedule("never", "never", "00:00-00:00", "", true).await;
        // All days, full-day range → always inside the window
        insert_schedule(
            "always",
            "always",
            "00:00-00:00",
            "mon,tue,wed,thu,fri,sat,sun",
            true,
        )
        .await;
        // Disabled → doesn't constrain
        insert_schedule("off", "off", "00:00-00:00", "", false).await;

        let mut gated = make_test_rule();
        gated.schedule_id = Some("never".to_string());
        gated.label = Some("gated".to_string());
        let mut open = make_test_rule();
        open.schedule_id = Some("always".to_string());
        open.label = Some("open".to_string());
        let mut disabled_sched = make_test_rule();
        disabled_sched.schedule_id = Some("off".to_string());
        disabled_sched.label = Some("disabled-sched".to_string());
        let mut dangling = make_test_rule();
        dangling.schedule_id = Some("deleted-schedule".to_string());
        dangling.label = Some("dangling".to_string());
        for r in [gated, open, disabled_sched, dangling] {
            engine.add_rule(r).await.unwrap();
        }

        engine.apply_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw").await.unwrap();
        let joined = pf_rules.join("\n");
        assert!(
            !joined.contains("\"gated\""),
            "closed-window rule must not load: {joined}"
        );
        assert!(joined.contains("\"open\""));
        assert!(joined.contains("\"disabled-sched\""));
        assert!(joined.contains("\"dangling\""));
        assert_eq!(pf_rules.len(), 3);
    }

    #[tokio::test]
    async fn test_engine_gateway_route_to() {
        // Rules referencing a healthy gateway compile route-to; down or
        // dangling gateway references fall back to default routing (#540).
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        mock.set_fib_count(4).await;
        let inst = crate::multiwan::InstanceEngine::new(db.pool().clone(), mock.clone());
        inst.migrate().await.unwrap();
        let gw_engine = crate::multiwan::GatewayEngine::new(db.pool().clone());
        gw_engine.migrate().await.unwrap();
        let engine = RuleEngine::new(db.pool().clone(), pf);

        let insert_gw = |id: &str, name: &str, state: &str| {
            let q = sqlx::query(
                "INSERT INTO multiwan_gateways \
                 (id, name, instance_id, interface, next_hop, state, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            )
            .bind(id.to_string())
            .bind(name.to_string())
            .bind(aifw_common::DEFAULT_INSTANCE_ID.to_string())
            .bind("igb1")
            .bind("203.0.113.1")
            .bind(state.to_string())
            .bind("2026-01-01T00:00:00Z");
            let pool = db.pool().clone();
            async move { q.execute(&pool).await.unwrap() }
        };
        let up_id = uuid::Uuid::new_v4().to_string();
        let down_id = uuid::Uuid::new_v4().to_string();
        insert_gw(&up_id, "wan-up", "up").await;
        insert_gw(&down_id, "wan-down", "down").await;

        let mk = |label: &str, gw: Option<String>| {
            let mut r = Rule::new(
                Action::Pass,
                Direction::In,
                Protocol::Tcp,
                RuleMatch {
                    src_addr: Address::Any,
                    src_port: None,
                    dst_addr: Address::Any,
                    dst_port: Some(PortRange { start: 80, end: 80 }),
                },
            );
            r.label = Some(label.to_string());
            r.gateway = gw;
            r
        };
        engine
            .add_rule(mk("routed", Some(up_id.clone())))
            .await
            .unwrap();
        engine
            .add_rule(mk("gw-down", Some(down_id.clone())))
            .await
            .unwrap();
        engine
            .add_rule(mk("gw-dangling", Some(uuid::Uuid::new_v4().to_string())))
            .await
            .unwrap();

        engine.apply_rules().await.unwrap();
        let pf_rules = mock.get_rules("aifw").await.unwrap();
        let find = |label: &str| {
            pf_rules
                .iter()
                .find(|r| r.contains(&format!("\"{label}\"")))
                .unwrap_or_else(|| panic!("rule {label} missing"))
        };
        assert!(find("routed").contains("route-to (igb1 203.0.113.1)"));
        assert!(!find("gw-down").contains("route-to"));
        assert!(!find("gw-dangling").contains("route-to"));

        // Round-trip: the gateway reference survives persistence
        let rules = engine.list_rules().await.unwrap();
        let routed = rules
            .iter()
            .find(|r| r.label.as_deref() == Some("routed"))
            .unwrap();
        assert_eq!(routed.gateway.as_deref(), Some(up_id.as_str()));
    }

    #[tokio::test]
    async fn test_engine_flush_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
        let engine = RuleEngine::new(db.pool().clone(), pf);

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
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
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
        rule.dst_port = Some(PortRange { start: 80, end: 80 });
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
                address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
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
            Bandwidth {
                value: 100,
                unit: BandwidthUnit::Mbps,
            },
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
            Bandwidth {
                value: 1,
                unit: BandwidthUnit::Gbps,
            },
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

        engine
            .add_queue(QueueConfig::new(
                Interface("em0".to_string()),
                QueueType::Codel,
                Bandwidth {
                    value: 100,
                    unit: BandwidthUnit::Mbps,
                },
                "default_q".to_string(),
                TrafficClass::Default,
            ))
            .await
            .unwrap();

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

        engine
            .add_rate_limit(RateLimitRule::new(
                "ssh".to_string(),
                Protocol::Tcp,
                5,
                30,
                "bruteforce".to_string(),
            ))
            .await
            .unwrap();

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
            Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                24,
            ),
        )
        .unwrap();
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
            Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1)),
                24,
            ),
        )
        .unwrap();
        tunnel.dns = Some("1.1.1.1".to_string());
        tunnel.mtu = Some(1420);
        tunnel.address6 = Some(Address::Network("fd00:a1f0::1".parse().unwrap(), 64));
        let id = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        let fetched = engine.get_wg_tunnel(id).await.unwrap();
        assert_eq!(fetched.name, "office");
        assert_eq!(fetched.interface.0, "wg1");
        assert_eq!(fetched.dns, Some("1.1.1.1".to_string()));
        assert_eq!(fetched.mtu, Some(1420));
        assert_eq!(
            fetched.address6,
            Some(Address::Network("fd00:a1f0::1".parse().unwrap(), 64))
        );
        assert!(!fetched.private_key.is_empty());
        assert!(!fetched.public_key.is_empty());
    }

    #[tokio::test]
    async fn test_next_peer_ip_v4_skips_used() {
        let engine = create_vpn_engine().await;
        let tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network("10.0.0.1".parse().unwrap(), 24),
        )
        .unwrap();
        let tid = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        assert_eq!(engine.next_peer_ip(tid).await.unwrap(), "10.0.0.2/32");

        let mut peer = WgPeer::new(tid, "p1".to_string(), "pk1".to_string());
        peer.allowed_ips = vec![Address::Network("10.0.0.2".parse().unwrap(), 32)];
        engine.add_wg_peer(peer).await.unwrap();

        assert_eq!(engine.next_peer_ip(tid).await.unwrap(), "10.0.0.3/32");
    }

    #[tokio::test]
    async fn test_next_peer_ip_dual_stack() {
        let engine = create_vpn_engine().await;
        let mut tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network("10.0.0.1".parse().unwrap(), 24),
        )
        .unwrap();
        tunnel.address6 = Some(Address::Network("fd00:a1f0::1".parse().unwrap(), 64));
        let tid = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        assert_eq!(
            engine.next_peer_ip(tid).await.unwrap(),
            "10.0.0.2/32, fd00:a1f0::2/128"
        );

        let mut peer = WgPeer::new(tid, "p1".to_string(), "pk1".to_string());
        peer.allowed_ips = vec![
            Address::Network("10.0.0.2".parse().unwrap(), 32),
            Address::Network("fd00:a1f0::2".parse().unwrap(), 128),
        ];
        engine.add_wg_peer(peer).await.unwrap();

        assert_eq!(
            engine.next_peer_ip(tid).await.unwrap(),
            "10.0.0.3/32, fd00:a1f0::3/128"
        );
    }

    #[tokio::test]
    async fn test_next_peer_ip_v6_only_tunnel() {
        let engine = create_vpn_engine().await;
        let tunnel = WgTunnel::new(
            "wg6".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network("fd00:b::1".parse().unwrap(), 64),
        )
        .unwrap();
        let tid = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        assert_eq!(engine.next_peer_ip(tid).await.unwrap(), "fd00:b::2/128");
    }

    #[tokio::test]
    async fn test_wg_tunnel_address6_validation() {
        let engine = create_vpn_engine().await;

        // address6 must actually be IPv6
        let mut t = WgTunnel::new(
            "bad6".to_string(),
            Interface("wg0".to_string()),
            51830,
            Address::Network("10.9.0.1".parse().unwrap(), 24),
        )
        .unwrap();
        t.address6 = Some(Address::Network("192.168.1.1".parse().unwrap(), 24));
        assert!(engine.add_wg_tunnel(t).await.is_err());

        // with address6 set, the primary address must be IPv4
        let mut t = WgTunnel::new(
            "doublev6".to_string(),
            Interface("wg0".to_string()),
            51831,
            Address::Network("fd00:1::1".parse().unwrap(), 64),
        )
        .unwrap();
        t.address6 = Some(Address::Network("fd00:2::1".parse().unwrap(), 64));
        assert!(engine.add_wg_tunnel(t).await.is_err());
    }

    #[tokio::test]
    async fn test_wg_peer_crud() {
        let engine = create_vpn_engine().await;

        let tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                24,
            ),
        )
        .unwrap();
        let tid = tunnel.id;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        let mut peer = WgPeer::new(tid, "laptop".to_string(), "fakepubkey123".to_string());
        peer.endpoint = Some("1.2.3.4:51820".to_string());
        peer.allowed_ips = vec![Address::Network(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            32,
        )];
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

    // PERF-H7: list_all_wg_peers_grouped returns one bucket per tunnel and
    // matches the per-tunnel list_wg_peers results (no N+1 needed).
    #[tokio::test]
    async fn test_wg_peers_grouped() {
        let engine = create_vpn_engine().await;

        let t1 = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Any,
        )
        .unwrap();
        let t2 = WgTunnel::new(
            "wg1".to_string(),
            Interface("wg1".to_string()),
            51821,
            Address::Any,
        )
        .unwrap();
        let (id1, id2) = (t1.id, t2.id);
        engine.add_wg_tunnel(t1).await.unwrap();
        engine.add_wg_tunnel(t2).await.unwrap();

        let peer = |tid, name: &str, pk: &str, last: u8| {
            let mut p = WgPeer::new(tid, name.to_string(), pk.to_string());
            p.allowed_ips = vec![Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last)),
                32,
            )];
            p
        };
        engine.add_wg_peer(peer(id1, "a", "pubA", 2)).await.unwrap();
        engine.add_wg_peer(peer(id1, "b", "pubB", 3)).await.unwrap();
        engine.add_wg_peer(peer(id2, "c", "pubC", 4)).await.unwrap();

        let grouped = engine.list_all_wg_peers_grouped().await.unwrap();
        assert_eq!(grouped.get(&id1).map(|v| v.len()), Some(2));
        assert_eq!(grouped.get(&id2).map(|v| v.len()), Some(1));
        // Empty tunnel (none added) has no bucket.
        assert!(!grouped.contains_key(&uuid::Uuid::new_v4()));
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
        )
        .unwrap();
        assert!(engine.add_wg_tunnel(t).await.is_err());

        // Zero port
        let mut t = WgTunnel::new(
            "test".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Any,
        )
        .unwrap();
        t.listen_port = 0;
        assert!(engine.add_wg_tunnel(t).await.is_err());

        // PERF-H5: duplicate listen_port is rejected via the targeted query.
        let first = WgTunnel::new(
            "first".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Any,
        )
        .unwrap();
        engine.add_wg_tunnel(first).await.unwrap();

        let dup = WgTunnel::new(
            "second".to_string(),
            Interface("wg1".to_string()),
            51820,
            Address::Any,
        )
        .unwrap();
        assert!(
            engine.add_wg_tunnel(dup).await.is_err(),
            "second tunnel on the same port must be rejected"
        );

        // A different port is fine.
        let ok = WgTunnel::new(
            "third".to_string(),
            Interface("wg2".to_string()),
            51821,
            Address::Any,
        )
        .unwrap();
        assert!(engine.add_wg_tunnel(ok).await.is_ok());
    }

    #[tokio::test]
    async fn test_ipsec_sa_crud() {
        let engine = create_vpn_engine().await;

        let sa = IpsecSa::new(
            "office".to_string(),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                198, 51, 100, 1,
            ))),
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

        // WAN role drives the auto-generated WireGuard outbound NAT rule
        sqlx::query(
            "INSERT INTO interface_roles (interface_name, role, updated_at) VALUES ('em0', 'WAN', '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let mut tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                24,
            ),
        )
        .unwrap();
        tunnel.status = VpnStatus::Up;
        engine.add_wg_tunnel(tunnel).await.unwrap();

        // Legacy CRUD-only SA (#530): must NOT emit pf rules — it has no
        // data plane, so its pf holes were pure attack surface.
        engine
            .add_ipsec_sa(IpsecSa::new(
                "ipsec0".to_string(),
                Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))),
                Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8))),
                IpsecProtocol::Esp,
                IpsecMode::Tunnel,
            ))
            .await
            .unwrap();

        // Real IPsec tunnel (#530 ipsec_tunnels): emits IKE/ESP/enc0 rules.
        let ipsec_engine = crate::ipsec::IpsecEngine::new(
            db.pool().clone(),
            std::sync::Arc::new(crate::ipsec::MockIkeControl::new()),
            std::sync::Arc::new(crate::ipsec::MemConfStore::new()),
        );
        ipsec_engine.migrate().await.unwrap();
        ipsec_engine
            .add_tunnel(aifw_common::IpsecTunnel::new(
                "site-a".to_string(),
                "203.0.113.10".to_string(),
                "correct-horse-battery-staple".to_string(),
                vec!["10.0.0.0/24".to_string()],
                vec!["10.1.0.0/24".to_string()],
            ))
            .await
            .unwrap();

        engine.apply_vpn_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw-vpn").await.unwrap();
        // 1 NAT rule + 2 WG rules + 5 tunnel rules; legacy SA contributes 0
        assert_eq!(pf_rules.len(), 8);
        // NAT must precede filter rules or pfctl rejects the ruleset
        assert_eq!(pf_rules[0], "nat on em0 from 10.0.0.0/24 to any -> (em0)");
        assert!(pf_rules.iter().any(|r| r.contains("port 51820")));
        assert!(pf_rules.iter().any(|r| r.contains("proto esp")));
        assert!(pf_rules.iter().any(|r| r.contains("on enc0")));
        assert!(pf_rules.iter().any(|r| r.contains("203.0.113.10")));
        // legacy SA endpoints must not appear anywhere
        assert!(!pf_rules.iter().any(|r| r.contains("5.6.7.8")));
    }

    #[tokio::test]
    async fn test_vpn_down_tunnel_emits_no_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::vpn::VpnEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        sqlx::query(
            "INSERT INTO interface_roles (interface_name, role, updated_at) VALUES ('em0', 'WAN', '2026-01-01T00:00:00Z')",
        )
        .execute(db.pool())
        .await
        .unwrap();

        // Status defaults to Down — must not open the listen port or NAT
        engine
            .add_wg_tunnel(
                WgTunnel::new(
                    "wg0".to_string(),
                    Interface("wg0".to_string()),
                    51820,
                    Address::Network(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                        24,
                    ),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        engine.apply_vpn_rules().await.unwrap();
        let pf_rules = mock.get_rules("aifw-vpn").await.unwrap();
        assert!(
            pf_rules.is_empty(),
            "down tunnel leaked rules: {pf_rules:?}"
        );
    }

    // --- Geo-IP engine tests ---

    async fn create_geoip_engine() -> crate::geoip::GeoIpEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = crate::geoip::GeoIpEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn test_geoip_rule_crud() {
        let engine = create_geoip_engine().await;

        let rule = GeoIpRule::new(CountryCode::new("CN").unwrap(), GeoIpAction::Block);
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].country.0, "CN");
        assert_eq!(rules[0].action, GeoIpAction::Block);

        engine.delete_rule(id).await.unwrap();
        assert!(engine.list_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_geoip_db_load_and_lookup() {
        let engine = create_geoip_engine().await;

        let blocks = "network,geoname_id,registered_country_geoname_id\n\
                       1.0.0.0/24,2077456,2077456\n\
                       1.0.1.0/24,1814991,1814991\n\
                       5.0.0.0/8,1814991,1814991\n";
        let locations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code\n\
                         2077456,en,OC,Oceania,AU\n\
                         1814991,en,AS,Asia,CN\n";

        let count = engine.load_database(blocks, locations).await.unwrap();
        assert!(count > 0);

        let (countries, _) = engine.db_stats().await;
        assert_eq!(countries, 2); // AU and CN

        // Lookup AU IP
        let result = engine.lookup("1.0.0.1".parse().unwrap()).await;
        assert_eq!(result.country.unwrap().0, "AU");

        // Lookup CN IP
        let result = engine.lookup("1.0.1.100".parse().unwrap()).await;
        assert_eq!(result.country.unwrap().0, "CN");

        // Lookup unknown
        let result = engine.lookup("192.168.1.1".parse().unwrap()).await;
        assert!(result.country.is_none());
    }

    #[tokio::test]
    async fn test_geoip_country_cidrs() {
        let engine = create_geoip_engine().await;

        let blocks = "network,geoname_id,x\n1.0.0.0/24,100,100\n1.0.1.0/24,100,100\n";
        let locations = "geoname_id,x,x,x,country_iso_code\n100,en,AS,Asia,JP\n";

        engine.load_database(blocks, locations).await.unwrap();

        let cidrs = engine.get_country_cidrs("JP").await;
        assert!(!cidrs.is_empty());

        let cidrs_unknown = engine.get_country_cidrs("ZZ").await;
        assert!(cidrs_unknown.is_empty());
    }

    #[tokio::test]
    async fn test_geoip_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::geoip::GeoIpEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        engine
            .add_rule(GeoIpRule::new(
                CountryCode::new("RU").unwrap(),
                GeoIpAction::Block,
            ))
            .await
            .unwrap();

        engine
            .add_rule(GeoIpRule::new(
                CountryCode::new("US").unwrap(),
                GeoIpAction::Allow,
            ))
            .await
            .unwrap();

        engine.apply_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw-geoip").await.unwrap();
        assert_eq!(pf_rules.len(), 4); // 2 tables + 2 rules
        assert!(pf_rules.iter().any(|r| r.contains("geoip_ru")));
        assert!(pf_rules.iter().any(|r| r.contains("geoip_us")));
        assert!(pf_rules.iter().any(|r| r.contains("block drop")));
        assert!(pf_rules.iter().any(|r| r.contains("pass")));
    }

    // --- TLS engine tests ---

    async fn create_tls_engine() -> crate::tls::TlsEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = crate::tls::TlsEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn test_sni_rule_crud() {
        let engine = create_tls_engine().await;

        let rule = SniRule::new("*.malware.com".to_string(), SniAction::Block);
        let id = rule.id;
        engine.add_sni_rule(rule).await.unwrap();

        let rules = engine.list_sni_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "*.malware.com");

        engine.delete_sni_rule(id).await.unwrap();
        assert!(engine.list_sni_rules().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_sni_check() {
        let engine = create_tls_engine().await;

        engine
            .add_sni_rule(SniRule::new("*.evil.com".to_string(), SniAction::Block))
            .await
            .unwrap();
        engine
            .add_sni_rule(SniRule::new("good.com".to_string(), SniAction::Allow))
            .await
            .unwrap();

        assert_eq!(
            engine.check_sni("sub.evil.com").await,
            Some(SniAction::Block)
        );
        assert_eq!(engine.check_sni("evil.com").await, Some(SniAction::Block));
        assert_eq!(engine.check_sni("good.com").await, Some(SniAction::Allow));
        assert_eq!(engine.check_sni("unknown.com").await, None);
    }

    #[tokio::test]
    async fn test_sni_validation() {
        let engine = create_tls_engine().await;
        let rule = SniRule::new(String::new(), SniAction::Block);
        assert!(engine.add_sni_rule(rule).await.is_err());
    }

    #[tokio::test]
    async fn test_ja3_blocklist() {
        let engine = create_tls_engine().await;

        engine
            .add_ja3_block("abc123", "known malware")
            .await
            .unwrap();
        engine
            .add_ja3_block("def456", "suspicious client")
            .await
            .unwrap();

        assert!(engine.is_ja3_blocked("abc123").await);
        assert!(engine.is_ja3_blocked("def456").await);
        assert!(!engine.is_ja3_blocked("other").await);

        let blocks = engine.list_ja3_blocks().await.unwrap();
        assert_eq!(blocks.len(), 2);

        engine.remove_ja3_block("abc123").await.unwrap();
        assert!(!engine.is_ja3_blocked("abc123").await);
    }

    #[tokio::test]
    async fn test_tls_apply_with_mitm() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();

        let mitm = MitmProxyConfig {
            enabled: true,
            listen_port: 8443,
            interface: Interface("em0".to_string()),
            intercept_ports: vec![443],
            ..Default::default()
        };

        let engine = crate::tls::TlsEngine::new(db.pool().clone(), pf).with_mitm_config(mitm);
        engine.migrate().await.unwrap();

        engine.apply_rules().await.unwrap();

        let rules = mock.get_rules("aifw-tls").await.unwrap();
        assert!(rules.iter().any(|r| r.contains("rdr on em0")));
        assert!(rules.iter().any(|r| r.contains("port 443")));
    }

    // --- HA / Cluster engine tests ---

    async fn create_cluster_engine() -> crate::ha::ClusterEngine {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = crate::ha::ClusterEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn test_carp_vip_crud() {
        let engine = create_cluster_engine().await;

        let vip = CarpVip::new(
            1,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 100)),
            24,
            Interface("em0".to_string()),
            "secret".to_string(),
        );
        let id = vip.id;
        engine.add_carp_vip(vip).await.unwrap();

        let vips = engine.list_carp_vips().await.unwrap();
        assert_eq!(vips.len(), 1);
        assert_eq!(vips[0].vhid, 1);
        assert_eq!(vips[0].password, "secret");

        engine.delete_carp_vip(id).await.unwrap();
        assert!(engine.list_carp_vips().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_carp_vip_validation() {
        let engine = create_cluster_engine().await;

        // VHID 0 should fail
        let vip = CarpVip::new(
            0,
            "10.0.0.1".parse().unwrap(),
            24,
            Interface("em0".into()),
            "pw".into(),
        );
        assert!(engine.add_carp_vip(vip).await.is_err());

        // Empty password should fail
        let vip = CarpVip::new(
            1,
            "10.0.0.1".parse().unwrap(),
            24,
            Interface("em0".into()),
            String::new(),
        );
        assert!(engine.add_carp_vip(vip).await.is_err());
    }

    #[tokio::test]
    async fn test_pfsync_config() {
        let engine = create_cluster_engine().await;

        let config = PfsyncConfig::new(Interface("em1".to_string()));
        engine.set_pfsync(config).await.unwrap();

        let fetched = engine.get_pfsync().await.unwrap().unwrap();
        assert_eq!(fetched.sync_interface.0, "em1");
        assert!(fetched.defer);
        assert!(fetched.enabled);
    }

    #[tokio::test]
    async fn test_cluster_node_crud() {
        let engine = create_cluster_engine().await;

        let node = ClusterNode::new(
            "fw1".to_string(),
            "10.0.0.1".parse().unwrap(),
            ClusterRole::Primary,
        );
        let id = node.id;
        engine.add_node(node).await.unwrap();

        let nodes = engine.list_nodes().await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "fw1");
        assert_eq!(nodes[0].role, ClusterRole::Primary);
        assert_eq!(nodes[0].health, NodeHealth::Unknown);

        // Update health
        engine
            .update_node_health(id, NodeHealth::Healthy)
            .await
            .unwrap();
        let nodes = engine.list_nodes().await.unwrap();
        assert_eq!(nodes[0].health, NodeHealth::Healthy);

        engine.delete_node(id).await.unwrap();
        assert!(engine.list_nodes().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_health_check_crud() {
        let engine = create_cluster_engine().await;

        let check = HealthCheck::new(
            "peer-ping".to_string(),
            HealthCheckType::Ping,
            "10.0.0.2".to_string(),
        );
        let id = check.id;
        engine.add_health_check(check).await.unwrap();

        let checks = engine.list_health_checks().await.unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "peer-ping");
        assert_eq!(checks[0].check_type, HealthCheckType::Ping);

        engine.delete_health_check(id).await.unwrap();
        assert!(engine.list_health_checks().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_ha_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = crate::ha::ClusterEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        engine
            .add_carp_vip(CarpVip::new(
                1,
                "10.0.0.100".parse().unwrap(),
                24,
                Interface("em0".into()),
                "pw".into(),
            ))
            .await
            .unwrap();

        let mut pfsync = PfsyncConfig::new(Interface("em1".into()));
        pfsync.sync_peer = Some("10.0.0.2".parse().unwrap());
        engine.set_pfsync(pfsync).await.unwrap();

        engine.apply_ha_rules().await.unwrap();

        let rules = mock.get_rules("aifw-ha").await.unwrap();
        assert!(rules.iter().any(|r| r.contains("proto carp")));
        assert!(rules.iter().any(|r| r.contains("proto pfsync")));
    }

    // --- Config system tests ---

    use crate::config::FirewallConfig;
    use crate::config_manager::ConfigManager;

    async fn create_config_mgr() -> ConfigManager {
        let db = Database::new_in_memory().await.unwrap();
        let mgr = ConfigManager::new(db.pool().clone());
        mgr.migrate().await.unwrap();
        mgr
    }

    #[test]
    fn test_config_json_roundtrip() {
        let config = FirewallConfig::default();
        let json = config.to_json();
        let parsed = FirewallConfig::from_json(&json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.system.hostname, "aifw");
    }

    #[test]
    fn test_config_hash_deterministic() {
        let c1 = FirewallConfig::default();
        let c2 = FirewallConfig::default();
        assert_eq!(c1.hash(), c2.hash());
    }

    #[test]
    fn test_config_hash_changes() {
        let mut c1 = FirewallConfig::default();
        let c2 = FirewallConfig::default();
        c1.system.hostname = "changed".to_string();
        assert_ne!(c1.hash(), c2.hash());
    }

    #[test]
    fn test_config_resource_count() {
        let mut config = FirewallConfig::default();
        assert_eq!(config.resource_count(), 0);

        config.rules.push(crate::config::RuleConfig {
            id: "1".into(),
            priority: 10,
            action: aifw_common::Action::Pass,
            direction: aifw_common::Direction::In,
            protocol: aifw_common::Protocol::Tcp,
            interface: None,
            src_addr: None,
            src_port_start: None,
            src_port_end: None,
            dst_addr: None,
            dst_port_start: Some(443),
            dst_port_end: Some(443),
            log: false,
            quick: true,
            label: Some("https".into()),
            state_tracking: aifw_common::StateTracking::KeepState,
            status: aifw_common::RuleStatus::Active,
            ip_version: aifw_common::IpVersion::Both,
            src_invert: false,
            dst_invert: false,
            schedule_id: None,
            gateway: None,
        });
        assert_eq!(config.resource_count(), 1);
    }

    #[tokio::test]
    async fn test_config_save_and_load() {
        let mgr = create_config_mgr().await;
        let config = FirewallConfig::default();

        let v = mgr
            .save_version(&config, "test", Some("initial"))
            .await
            .unwrap();
        assert_eq!(v, 1);

        mgr.mark_applied(v).await.unwrap();
        let (active_v, loaded) = mgr.get_active().await.unwrap().unwrap();
        assert_eq!(active_v, 1);
        assert_eq!(loaded.system.hostname, "aifw");
    }

    #[tokio::test]
    async fn test_config_versioning() {
        let mgr = create_config_mgr().await;

        let mut c1 = FirewallConfig::default();
        c1.system.hostname = "v1".into();
        let v1 = mgr
            .save_version(&c1, "test", Some("version 1"))
            .await
            .unwrap();
        mgr.mark_applied(v1).await.unwrap();

        let mut c2 = FirewallConfig::default();
        c2.system.hostname = "v2".into();
        let v2 = mgr
            .save_version(&c2, "test", Some("version 2"))
            .await
            .unwrap();
        mgr.mark_applied(v2).await.unwrap();

        // Active should be v2
        let (active_v, active_cfg) = mgr.get_active().await.unwrap().unwrap();
        assert_eq!(active_v, v2);
        assert_eq!(active_cfg.system.hostname, "v2");

        // Can still load v1
        let loaded_v1 = mgr.get_version(v1).await.unwrap();
        assert_eq!(loaded_v1.system.hostname, "v1");

        assert_eq!(mgr.version_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_config_rollback() {
        let mgr = create_config_mgr().await;

        let mut c1 = FirewallConfig::default();
        c1.system.hostname = "original".into();
        let v1 = mgr.save_version(&c1, "test", None).await.unwrap();
        mgr.mark_applied(v1).await.unwrap();

        let mut c2 = FirewallConfig::default();
        c2.system.hostname = "changed".into();
        let v2 = mgr.save_version(&c2, "test", None).await.unwrap();
        mgr.mark_applied(v2).await.unwrap();

        // Rollback to v1
        mgr.rollback(v1, |_| async { Ok(()) }).await.unwrap();

        let (active_v, active_cfg) = mgr.get_active().await.unwrap().unwrap();
        assert_eq!(active_v, v1);
        assert_eq!(active_cfg.system.hostname, "original");
    }

    #[tokio::test]
    async fn test_config_atomic_apply_success() {
        let mgr = create_config_mgr().await;
        let config = FirewallConfig::default();

        let v = mgr
            .save_and_apply(&config, "test", Some("success"), |_| async { Ok(()) })
            .await
            .unwrap();

        let (active_v, _) = mgr.get_active().await.unwrap().unwrap();
        assert_eq!(active_v, v);
    }

    #[tokio::test]
    async fn test_config_atomic_apply_failure() {
        let mgr = create_config_mgr().await;
        let config = FirewallConfig::default();

        let result = mgr
            .save_and_apply(&config, "test", Some("fail"), |_| async {
                Err("pf apply failed".to_string())
            })
            .await;

        assert!(result.is_err());
        // No active config since apply failed
        assert!(mgr.get_active().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_config_history() {
        let mgr = create_config_mgr().await;

        for i in 0..5 {
            let mut c = FirewallConfig::default();
            c.system.hostname = format!("host-{i}");
            let v = mgr
                .save_version(&c, "test", Some(&format!("v{i}")))
                .await
                .unwrap();
            mgr.mark_applied(v).await.unwrap();
        }

        let history = mgr.history(10).await.unwrap();
        assert_eq!(history.len(), 5);
        // Most recent first
        assert_eq!(history[0].version, 5);
        assert!(history[0].applied);
    }

    #[tokio::test]
    async fn test_config_diff() {
        let mgr = create_config_mgr().await;

        let c1 = FirewallConfig::default();
        let v1 = mgr.save_version(&c1, "test", None).await.unwrap();

        let mut c2 = FirewallConfig::default();
        c2.rules.push(crate::config::RuleConfig {
            id: "1".into(),
            priority: 10,
            action: aifw_common::Action::Block,
            direction: aifw_common::Direction::In,
            protocol: aifw_common::Protocol::Any,
            interface: None,
            src_addr: None,
            src_port_start: None,
            src_port_end: None,
            dst_addr: None,
            dst_port_start: None,
            dst_port_end: None,
            log: false,
            quick: true,
            label: None,
            state_tracking: aifw_common::StateTracking::KeepState,
            status: aifw_common::RuleStatus::Active,
            ip_version: aifw_common::IpVersion::Both,
            src_invert: false,
            dst_invert: false,
            schedule_id: None,
            gateway: None,
        });
        let v2 = mgr.save_version(&c2, "test", None).await.unwrap();

        let diff = mgr.diff(v1, v2).await.unwrap();
        assert!(!diff.identical);
        assert_eq!(diff.rules_diff.v1_count, 0);
        assert_eq!(diff.rules_diff.v2_count, 1);
        assert_eq!(diff.rules_diff.added, 1);
    }

    #[tokio::test]
    async fn test_config_diff_identical() {
        let mgr = create_config_mgr().await;
        let config = FirewallConfig::default();

        let v1 = mgr.save_version(&config, "test", None).await.unwrap();
        let v2 = mgr.save_version(&config, "test", None).await.unwrap();

        let diff = mgr.diff(v1, v2).await.unwrap();
        assert!(diff.identical);
    }

    #[test]
    fn system_config_defaults_for_new_fields() {
        let c = crate::SystemConfig::default();
        assert_eq!(c.domain, "");
        assert_eq!(c.timezone, "UTC");
        assert_eq!(c.login_banner, "");
        assert_eq!(c.motd, "");
        assert_eq!(c.console.kind, crate::ConsoleKind::Video);
        assert_eq!(c.console.baud, 115200);
        assert!(c.ssh.enabled);
        assert_eq!(c.ssh.port, 22);
        assert!(!c.ssh.password_auth);
        assert!(!c.ssh.permit_root_login);
    }

    #[test]
    fn old_config_json_loads_with_defaults() {
        // JSON from before the new fields existed — must still deserialize.
        let legacy = r#"{
            "schema_version": 1,
            "system": {
                "hostname": "test",
                "dns_servers": ["1.1.1.1"],
                "wan_interface": "em0",
                "lan_interface": null,
                "lan_ip": null,
                "api_listen": "0.0.0.0",
                "api_port": 8080,
                "ui_enabled": true
            },
            "auth": { "access_token_expiry_mins": 60, "refresh_token_expiry_days": 7, "require_totp": false, "require_totp_for_oauth": false, "auto_create_oauth_users": false }
        }"#;
        let c = crate::FirewallConfig::from_json(legacy).expect("legacy JSON must load");
        assert_eq!(c.system.hostname, "test");
        assert_eq!(c.system.domain, ""); // default
        assert_eq!(c.system.timezone, "UTC"); // default
        assert_eq!(c.system.ssh.port, 22); // default
        assert!(
            c.dns_resolver.is_none(),
            "pre-#589 backups must restore with the resolver section absent, not defaulted"
        );
    }

    #[test]
    fn dns_resolver_section_round_trips() {
        let c = crate::FirewallConfig {
            dns_resolver: Some(crate::config::DnsResolverSection {
                forwarding_servers: vec!["9.9.9.9".into()],
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        c.validate().expect("valid resolver section must pass");

        let json = c.to_json();
        let back = crate::FirewallConfig::from_json(&json).expect("round trip");
        let r = back.dns_resolver.expect("section must survive round trip");
        assert_eq!(r.forwarding_servers, vec!["9.9.9.9".to_string()]);
        assert!(r.enabled);
    }

    #[test]
    fn dns_resolver_section_validates_forwarder_ips() {
        let c = crate::FirewallConfig {
            dns_resolver: Some(crate::config::DnsResolverSection {
                forwarding_servers: vec!["not-an-ip; rm -rf /".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            c.validate().is_err(),
            "non-IP forwarding_servers entries must fail validation"
        );
    }
}
