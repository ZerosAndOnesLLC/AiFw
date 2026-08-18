use super::*;

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

/// #298: WireGuard private keys are sealed in the DB but the engine
/// hands back plaintext.
#[tokio::test]
async fn test_wg_private_key_sealed_at_rest() {
    let db = Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let engine = crate::vpn::VpnEngine::new(db.pool().clone(), pf);
    engine.migrate().await.unwrap();
    let tunnel = WgTunnel::new(
        "sealed".to_string(),
        Interface("wg7".to_string()),
        51877,
        Address::Network(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 77, 0, 1)),
            24,
        ),
    )
    .unwrap();
    let id = tunnel.id;
    let plain_key = tunnel.private_key.clone();
    engine.add_wg_tunnel(tunnel).await.unwrap();

    let (stored,): (String,) = sqlx::query_as("SELECT private_key FROM wg_tunnels WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(
        crate::secrets::is_sealed(&stored),
        "private_key must be sealed in the DB"
    );
    assert_ne!(stored, plain_key);
    assert_eq!(
        engine.get_wg_tunnel(id).await.unwrap().private_key,
        plain_key
    );

    // A legacy plaintext row (pre-#298 DB) still reads back unchanged.
    sqlx::query("UPDATE wg_tunnels SET private_key = ?1 WHERE id = ?2")
        .bind(&plain_key)
        .bind(id.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        engine.get_wg_tunnel(id).await.unwrap().private_key,
        plain_key
    );
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
