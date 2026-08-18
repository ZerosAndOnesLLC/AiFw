use super::*;

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
    assert!(pf_queues.is_empty()); // FQ-CoDel is entirely dummynet
}

#[test]
fn test_fq_codel_uses_dummynet_not_false_pf_queue_options() {
    let q = QueueConfig::new(
        Interface("em0".to_string()),
        QueueType::Codel,
        Bandwidth {
            value: 100,
            unit: BandwidthUnit::Mbps,
        },
        "bulk".to_string(),
        TrafficClass::Bulk,
    );
    assert!(q.to_pf_queue().is_empty());
    assert!(!q.to_pf_queue().contains("flows 1024"));
    assert!(q.fq_codel.validate().is_ok());
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
