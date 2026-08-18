use super::*;

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
    engine.add(rule).await.unwrap();

    let rules = engine.list().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, id);
    assert_eq!(rules[0].nat_type, NatType::Snat);
}

#[tokio::test]
async fn test_nat_delete() {
    let engine = create_nat_engine().await;

    let rule = make_test_nat_rule();
    let id = rule.id;
    engine.add(rule).await.unwrap();
    engine.delete(id).await.unwrap();

    let rules = engine.list().await.unwrap();
    assert!(rules.is_empty());
}

#[tokio::test]
async fn test_nat_delete_nonexistent() {
    let engine = create_nat_engine().await;
    assert!(engine.delete(uuid::Uuid::new_v4()).await.is_err());
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

    engine.add(rule).await.unwrap();
    let fetched = engine.get(id).await.unwrap();

    assert_eq!(fetched.nat_type, NatType::Dnat);
    assert_eq!(fetched.protocol, Protocol::Tcp);
    assert_eq!(fetched.interface.0, "em0");
    assert_eq!(fetched.dst_port.as_ref().unwrap().start, 80);
    assert_eq!(fetched.redirect.port.as_ref().unwrap().start, 8080);
    assert_eq!(fetched.label.as_deref(), Some("web-redirect"));
}

/// #253: static_port persists through the DB and nonat/static_port
/// validation rejects nonsensical combinations.
#[tokio::test]
async fn test_nat_static_port_and_nonat_roundtrip() {
    let engine = create_nat_engine().await;

    let mut masq = NatRule::new(
        NatType::Masquerade,
        Interface("em0".to_string()),
        Protocol::Any,
        Address::Any,
        Address::Any,
        NatRedirect {
            address: Address::Any,
            port: None,
        },
    );
    masq.static_port = true;
    let masq_id = masq.id;
    engine.add(masq).await.unwrap();
    let fetched = engine.get(masq_id).await.unwrap();
    assert!(fetched.static_port, "static_port must round-trip");
    assert!(fetched.to_pf_rule().ends_with("static-port"));

    // Update can clear it again.
    let mut cleared = fetched.clone();
    cleared.static_port = false;
    engine.update(&cleared).await.unwrap();
    assert!(!engine.get(masq_id).await.unwrap().static_port);

    // nonat round-trips and renders `no nat`.
    let nonat = NatRule::new(
        NatType::NoNat,
        Interface("em0".to_string()),
        Protocol::Any,
        Address::Any,
        Address::Any,
        NatRedirect {
            address: Address::Any,
            port: None,
        },
    );
    let nonat_id = nonat.id;
    engine.add(nonat).await.unwrap();
    let fetched = engine.get(nonat_id).await.unwrap();
    assert_eq!(fetched.nat_type, NatType::NoNat);
    assert!(fetched.to_pf_rule().starts_with("no nat on em0"));

    // static_port on a DNAT rule is rejected.
    let mut bad = NatRule::new(
        NatType::Dnat,
        Interface("em0".to_string()),
        Protocol::Tcp,
        Address::Any,
        Address::Any,
        NatRedirect {
            address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 10,
            ))),
            port: Some(PortRange { start: 80, end: 80 }),
        },
    );
    bad.static_port = true;
    assert!(engine.add(bad).await.is_err());

    // nonat with a redirect target is rejected.
    let bad = NatRule::new(
        NatType::NoNat,
        Interface("em0".to_string()),
        Protocol::Any,
        Address::Any,
        Address::Any,
        NatRedirect {
            address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
            port: None,
        },
    );
    assert!(engine.add(bad).await.is_err());
}

#[tokio::test]
async fn test_nat_apply_rules() {
    let db = Database::new_in_memory().await.unwrap();
    let mock = Arc::new(aifw_pf::PfMock::new());
    let pf: Arc<dyn PfBackend> = mock.clone();
    let engine = crate::nat::NatEngine::new(db.pool().clone(), pf);

    engine.add(make_test_nat_rule()).await.unwrap();
    engine.apply_rules().await.unwrap();

    let nat_rules = mock.get_nat_rules("aifw-nat").await.unwrap();
    assert_eq!(nat_rules.len(), 1);
    assert!(nat_rules[0].contains("nat on em0"));
}

#[tokio::test]
async fn test_nat_apply_mixed_classes_and_flush() {
    let db = Database::new_in_memory().await.unwrap();
    let mock = Arc::new(aifw_pf::PfMock::new());
    let pf: Arc<dyn PfBackend> = mock.clone();
    let engine =
        crate::nat::NatEngine::new(db.pool().clone(), pf).with_anchor("aifw-nat".to_string());

    engine.add(make_test_nat_rule()).await.unwrap();
    engine.add(make_test_nat64_rule()).await.unwrap();
    engine.apply_rules().await.unwrap();

    // nat-class rule lands in the nat ruleset; the af-to pass rule is
    // filter-class and must land in the filter ruleset (#531).
    let nat_rules = mock.get_nat_rules("aifw-nat").await.unwrap();
    assert_eq!(nat_rules.len(), 1);
    assert!(nat_rules[0].starts_with("nat on em0"));
    let filter_rules = mock.get_rules("aifw-nat").await.unwrap();
    assert_eq!(filter_rules.len(), 1);
    assert!(filter_rules[0].contains("af-to inet from 203.0.113.1"));

    // per-class post-apply verification passes
    engine.verify_applied().await.unwrap();

    // flush clears both classes
    engine.flush_rules().await.unwrap();
    assert!(mock.get_nat_rules("aifw-nat").await.unwrap().is_empty());
    assert!(mock.get_rules("aifw-nat").await.unwrap().is_empty());
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
            address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            port: None,
        },
    );
    // DNAT without any port should fail validation
    assert!(engine.add(rule).await.is_err());
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
    assert!(engine.add(rule).await.is_err());
}

fn make_test_nat64_rule() -> NatRule {
    NatRule::new(
        NatType::Nat64,
        Interface("em0".to_string()),
        Protocol::Any,
        Address::Any,
        Address::Network(std::net::IpAddr::V6("64:ff9b::".parse().unwrap()), 96),
        NatRedirect {
            address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
            port: None,
        },
    )
}

#[tokio::test]
async fn test_nat64_validation_accepts_well_formed_rule() {
    let engine = create_nat_engine().await;
    engine.add(make_test_nat64_rule()).await.unwrap();

    // NAT46 mirror: v4 match, v6 translation source
    let nat46 = NatRule::new(
        NatType::Nat46,
        Interface("em0".to_string()),
        Protocol::Tcp,
        Address::Any,
        Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 1, 1))),
        NatRedirect {
            address: Address::Single(std::net::IpAddr::V6("2001:db8:2::1".parse().unwrap())),
            port: None,
        },
    );
    engine.add(nat46).await.unwrap();
}

#[tokio::test]
async fn test_nat64_validation_rejects_bad_families() {
    let engine = create_nat_engine().await;

    // dst not a /96 prefix
    let mut rule = make_test_nat64_rule();
    rule.dst_addr = Address::Network(std::net::IpAddr::V6("64:ff9b::".parse().unwrap()), 64);
    assert!(engine.add(rule).await.is_err());

    // dst IPv4
    let mut rule = make_test_nat64_rule();
    rule.dst_addr = Address::Network(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)),
        8,
    );
    assert!(engine.add(rule).await.is_err());

    // source in the wrong (translated) family
    let mut rule = make_test_nat64_rule();
    rule.src_addr = Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    assert!(engine.add(rule).await.is_err());

    // translation source IPv6 (must be IPv4 for nat64)
    let mut rule = make_test_nat64_rule();
    rule.redirect.address = Address::Single(std::net::IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert!(engine.add(rule).await.is_err());

    // translation source as network (must be a single host)
    let mut rule = make_test_nat64_rule();
    rule.redirect.address = Address::Network(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 0)),
        24,
    );
    assert!(engine.add(rule).await.is_err());

    // redirect port unsupported by af-to
    let mut rule = make_test_nat64_rule();
    rule.redirect.port = Some(PortRange { start: 80, end: 80 });
    assert!(engine.add(rule).await.is_err());

    // pf tables can't determine family
    let mut rule = make_test_nat64_rule();
    rule.src_addr = Address::Table("v6clients".to_string());
    assert!(engine.add(rule).await.is_err());
}

#[tokio::test]
async fn test_nat46_validation_rejects_bad_families() {
    let engine = create_nat_engine().await;

    let make = || {
        NatRule::new(
            NatType::Nat46,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Any,
            Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 1, 1))),
            NatRedirect {
                address: Address::Single(std::net::IpAddr::V6("2001:db8:2::1".parse().unwrap())),
                port: None,
            },
        )
    };

    // dst IPv6 (must be the concrete IPv4 target)
    let mut rule = make();
    rule.dst_addr = Address::Single(std::net::IpAddr::V6("2001:db8::5".parse().unwrap()));
    assert!(engine.add(rule).await.is_err());

    // dst Any (a concrete IPv4 destination is required)
    let mut rule = make();
    rule.dst_addr = Address::Any;
    assert!(engine.add(rule).await.is_err());

    // translation source IPv4 (must be IPv6 for nat46)
    let mut rule = make();
    rule.redirect.address = Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
        203, 0, 113, 1,
    )));
    assert!(engine.add(rule).await.is_err());

    // #596: explicit translated destination must be a single IPv6 host
    let mut rule = make();
    rule.af_to_dst = Some(Address::Single(std::net::IpAddr::V4(
        std::net::Ipv4Addr::new(192, 0, 2, 80),
    )));
    assert!(engine.add(rule).await.is_err());
    let mut rule = make();
    rule.af_to_dst = Some(Address::Network(
        std::net::IpAddr::V6("2001:db8:2::".parse().unwrap()),
        64,
    ));
    assert!(engine.add(rule).await.is_err());
    let mut rule = make();
    rule.af_to_dst = Some(Address::Single(std::net::IpAddr::V6(
        "2001:db8:2::80".parse().unwrap(),
    )));
    let added = engine.add(rule).await.unwrap();
    // round-trips through SQLite
    let stored = engine
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.id == added.id)
        .unwrap();
    assert_eq!(
        stored.af_to_dst,
        Some(Address::Single(std::net::IpAddr::V6(
            "2001:db8:2::80".parse().unwrap()
        )))
    );
    assert!(
        stored
            .to_pf_rule()
            .ends_with("af-to inet6 from 2001:db8:2::1 to 2001:db8:2::80")
    );

    // af_to_dst is meaningless on other NAT types
    let mut snat = NatRule::new(
        NatType::Snat,
        Interface("em0".to_string()),
        Protocol::Any,
        Address::Any,
        Address::Any,
        NatRedirect {
            address: Address::Single(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 1,
            ))),
            port: None,
        },
    );
    snat.af_to_dst = Some(Address::Single(std::net::IpAddr::V6(
        "2001:db8:2::80".parse().unwrap(),
    )));
    assert!(engine.add(snat).await.is_err());
}
