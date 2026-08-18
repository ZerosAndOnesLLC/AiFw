use super::*;

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
