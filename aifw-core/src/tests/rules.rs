use super::*;

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
    engine.add(rule).await.unwrap();

    let rules = engine.list().await.unwrap();
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
    engine.add(rule).await.unwrap();
    engine.delete(id).await.unwrap();

    let rules = engine.list().await.unwrap();
    assert!(rules.is_empty());
}

#[tokio::test]
async fn test_engine_delete_nonexistent() {
    let db = Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let engine = RuleEngine::new(db.pool().clone(), pf);

    let result = engine.delete(uuid::Uuid::new_v4()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_engine_apply_rules() {
    let db = Database::new_in_memory().await.unwrap();
    let mock = Arc::new(aifw_pf::PfMock::new());
    let pf: Arc<dyn PfBackend> = mock.clone();
    let engine = RuleEngine::new(db.pool().clone(), pf);

    engine.add(make_test_rule()).await.unwrap();

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
    engine.add(rule2).await.unwrap();

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
        engine.add(r).await.unwrap();
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
    engine.add(mk("routed", Some(up_id.clone()))).await.unwrap();
    engine
        .add(mk("gw-down", Some(down_id.clone())))
        .await
        .unwrap();
    engine
        .add(mk("gw-dangling", Some(uuid::Uuid::new_v4().to_string())))
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
    let rules = engine.list().await.unwrap();
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

    engine.add(make_test_rule()).await.unwrap();
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
    engine.add(rule).await.unwrap();
    engine.delete(id).await.unwrap();

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

    engine.add(make_test_rule()).await.unwrap();
    engine.apply_rules().await.unwrap();
    engine.flush_rules().await.unwrap();

    let entries = engine.audit().list(10).await.unwrap();
    assert_eq!(entries.len(), 3); // add + apply + flush
    assert_eq!(entries[0].action, crate::audit::AuditAction::RulesFlushed);
    assert_eq!(entries[1].action, crate::audit::AuditAction::RulesApplied);
}
