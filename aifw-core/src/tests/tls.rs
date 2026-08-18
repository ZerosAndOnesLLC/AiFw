use super::*;

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
