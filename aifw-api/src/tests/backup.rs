use super::*;

#[tokio::test]
async fn test_restore_roundtrip_succeeds() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let config = crate::backup::build_current_config(&state).await.unwrap();
    crate::backup::apply_firewall_config(&state, &config, &Default::default())
        .await
        .expect("restoring the current config must succeed");
}

#[tokio::test]
async fn test_restore_round_trips_dns_resolver_config() {
    // #589: resolver settings live in dns_resolver_config, not
    // /etc/resolv.conf — a backup/restore must carry them.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();

    let resolver = crate::dns_resolver::ResolverConfig {
        forwarding_servers: vec!["9.9.9.9".to_string()],
        blocklists_enabled: true,
        ..Default::default()
    };
    let mut conn = state.pool.acquire().await.unwrap();
    crate::dns_resolver::save_config_on(&mut conn, &resolver)
        .await
        .unwrap();
    drop(conn);

    let config = crate::backup::build_current_config(&state).await.unwrap();
    let exported = config
        .dns_resolver
        .as_ref()
        .expect("export must include resolver");
    assert_eq!(exported.forwarding_servers, vec!["9.9.9.9".to_string()]);
    assert!(exported.blocklists_enabled);

    // Simulate drift after the backup was taken.
    sqlx::query(
        "INSERT OR REPLACE INTO dns_resolver_config (key, value) VALUES ('forwarding_servers', '8.8.4.4')",
    )
    .execute(&state.pool)
    .await
    .unwrap();

    crate::backup::apply_firewall_config(&state, &config, &Default::default())
        .await
        .expect("restore must succeed");

    let (servers,): (String,) =
        sqlx::query_as("SELECT value FROM dns_resolver_config WHERE key = 'forwarding_servers'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(
        servers, "9.9.9.9",
        "restore must reinstate the backed-up forwarders"
    );
}

#[tokio::test]
async fn test_restore_round_trips_syslog_config() {
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();

    let syslog_cfg = aifw_common::syslog::SyslogConfig {
        enabled: true,
        host: "192.0.2.50".into(),
        port: 5514,
        transport: aifw_common::syslog::Transport::Tcp,
        pf_enabled: true,
        ..Default::default()
    };
    aifw_common::syslog::save(&state.pool, &syslog_cfg)
        .await
        .unwrap();

    let config = crate::backup::build_current_config(&state).await.unwrap();
    let exported = config.syslog.as_ref().expect("export must include syslog");
    assert_eq!(exported.host, "192.0.2.50");
    assert!(exported.pf_enabled);

    // Simulate drift after the backup was taken.
    aifw_common::syslog::save(&state.pool, &Default::default())
        .await
        .unwrap();

    crate::backup::apply_firewall_config(&state, &config, &Default::default())
        .await
        .expect("restore must succeed");

    let restored = aifw_common::syslog::load(&state.pool).await;
    assert_eq!(restored, syslog_cfg, "restore must reinstate syslog config");
    // The API process applied it immediately.
    assert_eq!(*state.syslog.current(), syslog_cfg);
}

#[tokio::test]
async fn test_restore_without_resolver_section_leaves_config_untouched() {
    // A pre-#589 backup has no dns_resolver section — restoring it must
    // not reset the box's resolver config to defaults.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    sqlx::query(
        "INSERT OR REPLACE INTO dns_resolver_config (key, value) VALUES ('forwarding_servers', '9.9.9.9')",
    )
    .execute(&state.pool)
    .await
    .unwrap();

    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    config.dns_resolver = None;
    crate::backup::apply_firewall_config(&state, &config, &Default::default())
        .await
        .expect("restore must succeed");

    let (servers,): (String,) =
        sqlx::query_as("SELECT value FROM dns_resolver_config WHERE key = 'forwarding_servers'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(
        servers, "9.9.9.9",
        "legacy restore must not clobber resolver config"
    );
}

#[tokio::test]
async fn test_restore_fails_instead_of_partial_apply() {
    // A required step failing (here: clearing a table that no longer
    // exists) must abort the restore with an error, never return Ok after
    // a partial apply (#535).
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let config = crate::backup::build_current_config(&state).await.unwrap();
    sqlx::query("DROP TABLE nat_rules")
        .execute(&state.pool)
        .await
        .unwrap();
    let res = crate::backup::apply_firewall_config(&state, &config, &Default::default()).await;
    assert!(res.is_err(), "partial apply must not report success");
}

#[tokio::test]
async fn test_mid_apply_failure_rolls_back_db_transaction() {
    // Force a failure LATE in the apply (the DHCP clear runs after every
    // rules/NAT/alias insert) and verify the single restore transaction
    // (#158) rewinds everything — the pre-restore rows must survive
    // untouched even without the snapshot-reapply wrapper.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let rule = aifw_common::Rule::new(
        aifw_common::Action::Pass,
        aifw_common::Direction::In,
        aifw_common::Protocol::Tcp,
        aifw_common::RuleMatch {
            src_addr: aifw_common::Address::Any,
            src_port: None,
            dst_addr: aifw_common::Address::Any,
            dst_port: None,
        },
    );
    let rule_id = state.rule_engine.add_rule(rule).await.unwrap().id;

    let config = crate::backup::build_current_config(&state).await.unwrap();
    sqlx::query("DROP TABLE dhcp_subnets")
        .execute(&state.pool)
        .await
        .unwrap();
    let res = crate::backup::apply_firewall_config(&state, &config, &Default::default()).await;
    assert!(res.is_err(), "late failure must abort the restore");

    let rules = state.rule_engine.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1, "transaction rollback must keep prior rows");
    assert_eq!(rules[0].id, rule_id);
}

#[tokio::test]
async fn test_restore_1k_rules_round_trips() {
    // #158 acceptance: a large config restores through the single
    // transaction and every row survives the round trip.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    for i in 0..1000 {
        config.rules.push(aifw_core::config::RuleConfig {
            id: uuid::Uuid::new_v4().to_string(),
            priority: i,
            action: aifw_common::Action::Pass,
            direction: aifw_common::Direction::In,
            protocol: aifw_common::Protocol::Tcp,
            interface: None,
            src_addr: Some("any".to_string()),
            src_port_start: None,
            src_port_end: None,
            dst_addr: Some("any".to_string()),
            dst_port_start: Some(1000 + i as u16),
            dst_port_end: Some(1000 + i as u16),
            log: false,
            quick: true,
            label: Some(format!("bulk-{i}")),
            state_tracking: aifw_common::StateTracking::KeepState,
            status: aifw_common::RuleStatus::Active,
            ip_version: aifw_common::IpVersion::Both,
            src_invert: false,
            dst_invert: false,
            schedule_id: None,
            gateway: None,
        });
    }
    let started = std::time::Instant::now();
    crate::backup::apply_firewall_config(&state, &config, &Default::default())
        .await
        .expect("bulk restore must succeed");
    let elapsed = started.elapsed();
    let rules = state.rule_engine.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1000, "every rule must survive the round trip");
    // Generous bound — the point is one transaction, not per-row fsyncs.
    assert!(elapsed.as_secs() < 30, "bulk restore took {elapsed:?}");
}

#[tokio::test]
async fn test_restore_failure_injection_every_db_stage() {
    // #535: for every table the restore touches, a failure at that stage
    // must abort the restore with the transaction rolled back — the
    // pre-restore rules must survive untouched at every injection point.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .try_init();
    for table in [
        "nat_rules",
        "aliases",
        "static_routes",
        "geoip_rules",
        "wg_tunnels",
        "wg_peers",
        "ipsec_sas",
        "ipsec_tunnels",
        "queue_configs",
        "rate_limit_rules",
        "sni_rules",
        "ja3_blocklist",
        "carp_vips",
        "pfsync_config",
        "cluster_nodes",
        "auth_config",
        "dhcp_subnets",
        "dhcp_reservations",
        "dhcp_config",
        "dhcp_ddns_config",
        "dhcp_ha_config",
    ] {
        let state = crate::create_app_state_in_memory(plain_auth_settings())
            .await
            .unwrap();
        state.rule_engine.add_rule(any_tcp_rule()).await.unwrap();
        let config = crate::backup::build_current_config(&state).await.unwrap();
        // Replace the table with a read-only VIEW of the same name: the
        // engine migrates' CREATE TABLE IF NOT EXISTS no-op on it (so
        // pre-tx migrates can't undo the injection, unlike a plain DROP)
        // and the restore's DELETE/INSERT then fails at exactly this
        // stage.
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE {table}")))
            .execute(&state.pool)
            .await
            .unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE VIEW {table} AS SELECT 1 AS x"
        )))
        .execute(&state.pool)
        .await
        .unwrap();
        let res = crate::backup::apply_firewall_config(&state, &config, &Default::default()).await;
        assert!(res.is_err(), "failure at {table} must abort the restore");
        let rules = state.rule_engine.list_rules().await.unwrap();
        assert_eq!(
            rules.len(),
            1,
            "failure at {table} must leave prior rules untouched"
        );
    }
}

#[tokio::test]
async fn test_restore_mid_tx_failure_rolls_back_and_audits() {
    // Outcome 2 of the #535 contract: apply fails (duplicate alias name
    // violates the UNIQUE constraint mid-transaction), prior state is
    // restored, and the rollback is audited.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    state.rule_engine.add_rule(any_tcp_rule()).await.unwrap();
    state
        .alias_engine
        .add(aifw_common::Alias {
            id: uuid::Uuid::new_v4(),
            name: "keepme".to_string(),
            alias_type: aifw_common::AliasType::Host,
            entries: vec!["192.0.2.1".to_string()],
            description: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    for _ in 0..2 {
        config.aliases.push(aifw_core::config::AliasConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name: "dup_name".to_string(),
            alias_type: "host".to_string(),
            entries: vec!["198.51.100.1".to_string()],
            description: None,
            enabled: false,
        });
    }

    let res =
        crate::backup::apply_firewall_config_or_rollback(&state, &config, &Default::default())
            .await;
    assert!(res.is_err(), "duplicate alias must abort the restore");

    let aliases = state.alias_engine.list().await.unwrap();
    assert_eq!(aliases.len(), 1, "prior alias set must be restored");
    assert_eq!(aliases[0].name, "keepme");
    assert_eq!(state.rule_engine.list_rules().await.unwrap().len(), 1);

    let (audits,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE details LIKE '%rolled back to pre-restore state%'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
    assert!(audits >= 1, "rollback must be audited");
}

#[tokio::test]
async fn test_restore_pf_failure_after_commit_rolls_back_cleanly() {
    // Outcome 2 via the data plane: the target config needs a pf op the
    // snapshot doesn't (geo-IP table populate), so injecting that
    // failure aborts the target apply and the snapshot re-applies clean.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    state.rule_engine.add_rule(any_tcp_rule()).await.unwrap();
    let mock = state
        .pf
        .as_any()
        .downcast_ref::<aifw_pf::PfMock>()
        .expect("tests run on the mock backend");
    mock.fail_op("replace_table_entries").await;

    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    config.geoip.push(aifw_core::config::GeoIpEntry {
        id: uuid::Uuid::new_v4().to_string(),
        country: "CN".to_string(),
        action: aifw_common::GeoIpAction::Block,
        label: None,
        status: aifw_common::GeoIpRuleStatus::Active,
    });

    let res =
        crate::backup::apply_firewall_config_or_rollback(&state, &config, &Default::default())
            .await;
    assert!(res.is_err(), "pf failure must abort the restore");
    assert_eq!(
        state.geoip_engine.list_rules().await.unwrap().len(),
        0,
        "geo-ip rows from the failed target must be rolled back"
    );
    assert_eq!(state.rule_engine.list_rules().await.unwrap().len(), 1);
}

#[tokio::test]
async fn test_restore_rollback_failure_is_audited_high_severity() {
    // Outcome 3 of the #535 contract: the apply fails AND the rollback
    // fails (persistent pf failure hits both); the operator gets an
    // explicit rollback-failed audit row, never silent partial success.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    state.rule_engine.add_rule(any_tcp_rule()).await.unwrap();
    let mock = state
        .pf
        .as_any()
        .downcast_ref::<aifw_pf::PfMock>()
        .expect("tests run on the mock backend");
    mock.fail_op("load_rules").await;

    let config = crate::backup::build_current_config(&state).await.unwrap();
    let res =
        crate::backup::apply_firewall_config_or_rollback(&state, &config, &Default::default())
            .await;
    assert!(res.is_err());

    let (audits,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM audit_log WHERE details LIKE '%rollback failed%'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert!(audits >= 1, "failed rollback must be audited");
    mock.clear_fail("load_rules").await;
}

#[tokio::test]
async fn test_commit_confirm_refuses_invalid_rollback_snapshot() {
    // Arming with a snapshot that can't roll back would leave the timer
    // to fail silently at expiry (#535) — it must be refused up front.
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let res = crate::backup::commit_confirm_arm_with_snapshot(
        state,
        "{not valid json".to_string(),
        "test".to_string(),
        5,
    )
    .await;
    assert_eq!(res, Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR));
}

#[tokio::test]
async fn test_post_apply_verification_detects_pf_drift() {
    // verify_applied must fail when the pf anchor no longer matches the
    // database (#535 post-apply verification).
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let rule = aifw_common::Rule::new(
        aifw_common::Action::Pass,
        aifw_common::Direction::In,
        aifw_common::Protocol::Tcp,
        aifw_common::RuleMatch {
            src_addr: aifw_common::Address::Any,
            src_port: None,
            dst_addr: aifw_common::Address::Any,
            dst_port: None,
        },
    );
    state.rule_engine.add_rule(rule).await.unwrap();
    state.rule_engine.apply_rules().await.unwrap();
    state
        .rule_engine
        .verify_applied()
        .await
        .expect("freshly applied ruleset must verify");

    state.pf.flush_rules("aifw").await.unwrap();
    assert!(
        state.rule_engine.verify_applied().await.is_err(),
        "flushed anchor must fail verification"
    );
}

#[tokio::test]
async fn test_prevalidation_rejects_bad_config_without_mutation() {
    // A config that would abort mid-apply (rule priority out of range)
    // must be rejected up front with 400 and zero rows touched (#535).
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let rule = aifw_common::Rule::new(
        aifw_common::Action::Pass,
        aifw_common::Direction::In,
        aifw_common::Protocol::Tcp,
        aifw_common::RuleMatch {
            src_addr: aifw_common::Address::Any,
            src_port: None,
            dst_addr: aifw_common::Address::Any,
            dst_port: None,
        },
    );
    state.rule_engine.add_rule(rule).await.unwrap();

    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    config.rules[0].priority = 20_000; // validate_rule caps at 10000

    let res =
        crate::backup::apply_firewall_config_or_rollback(&state, &config, &Default::default())
            .await;
    assert_eq!(res, Err(axum::http::StatusCode::BAD_REQUEST));
    let rules = state.rule_engine.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1, "prevalidation failure must not touch rows");
}

#[tokio::test]
async fn test_prevalidation_rejects_duplicate_wg_ports() {
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let mut config = crate::backup::build_current_config(&state).await.unwrap();
    for name in ["wg-a", "wg-b"] {
        config
            .vpn
            .wireguard
            .push(aifw_core::config::WireguardTunnelConfig {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.to_string(),
                interface: "wg0".to_string(),
                listen_port: 51820,
                address: "10.9.0.1/24".to_string(),
                address6: None,
                private_key: "k".into(),
                public_key: "K".into(),
                dns: None,
                mtu: None,
                peers: vec![],
            });
    }
    let res =
        crate::backup::apply_firewall_config_or_rollback(&state, &config, &Default::default())
            .await;
    assert_eq!(res, Err(axum::http::StatusCode::BAD_REQUEST));
}

/// #313: exports never carry live secrets — GET redacts, POST wraps
/// under a passphrase — and imports resolve/unlock them again.
#[tokio::test]
async fn test_config_export_secrets_redacted_and_passphrase_round_trip() {
    use aifw_core::config_secrets::{PW_PREFIX, REDACTED};
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let cluster = state.cluster_engine.clone();
    let vip = cluster
        .add_carp_vip(aifw_common::CarpVip {
            id: uuid::Uuid::new_v4(),
            vhid: 7,
            virtual_ip: "192.0.2.10".parse().unwrap(),
            prefix: 24,
            interface: aifw_common::Interface("em0".into()),
            password: "carp-secret".into(),
            status: aifw_common::CarpStatus::Init,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let server = TestServer::new(crate::build_router(state, None, "*", false));
    let token = create_user_and_login(&server).await;

    // GET: redacted
    let resp = server
        .get("/api/v1/config/export")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let redacted: Value = resp.json();
    assert_eq!(redacted["secrets"], "redacted");
    assert_eq!(
        redacted["config"]["ha"]["carp_vips"][0]["password"],
        REDACTED
    );
    assert!(redacted["config"].get("secrets").is_none());

    // POST: passphrase-wrapped; short passphrase rejected
    let resp = server
        .post("/api/v1/config/export")
        .authorization_bearer(&token)
        .json(&json!({"passphrase": "short"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let resp = server
        .post("/api/v1/config/export")
        .authorization_bearer(&token)
        .json(&json!({"passphrase": "correct horse battery"}))
        .await;
    resp.assert_status_ok();
    let wrapped: Value = resp.json();
    assert_eq!(wrapped["secrets"], "passphrase");
    let pw_val = wrapped["config"]["ha"]["carp_vips"][0]["password"]
        .as_str()
        .unwrap();
    assert!(pw_val.starts_with(PW_PREFIX), "{pw_val}");
    assert!(!pw_val.contains("carp-secret"));
    assert_eq!(wrapped["config"]["secrets"]["kdf"], "argon2id");

    // Preview of the redacted file: this box holds every secret
    let resp = server
        .post("/api/v1/config/import-preview")
        .authorization_bearer(&token)
        .json(&redacted)
        .await;
    resp.assert_status_ok();
    let preview: Value = resp.json();
    assert_eq!(preview["secrets"]["state"], "redacted");
    assert_eq!(preview["secrets"]["count"], 1);
    assert_eq!(preview["unresolved_secrets"].as_array().unwrap().len(), 0);

    // Importing the redacted file fills the secret from live state
    let resp = server
        .post("/api/v1/config/import")
        .authorization_bearer(&token)
        .json(&redacted)
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let vips = cluster.list_carp_vips().await.unwrap();
    assert_eq!(vips.len(), 1);
    assert_eq!(vips[0].password, "carp-secret");

    // Wrapped file: no passphrase → 400, wrong → 400, right → applied
    let resp = server
        .post("/api/v1/config/import")
        .authorization_bearer(&token)
        .json(&wrapped)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("passphrase"), "{}", resp.text());
    let mut with_bad = wrapped.clone();
    with_bad["passphrase"] = json!("wrong passphrase");
    let resp = server
        .post("/api/v1/config/import")
        .authorization_bearer(&token)
        .json(&with_bad)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let mut with_good = wrapped.clone();
    with_good["passphrase"] = json!("correct horse battery");
    let resp = server
        .post("/api/v1/config/import")
        .authorization_bearer(&token)
        .json(&with_good)
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let vips = cluster.list_carp_vips().await.unwrap();
    assert_eq!(vips[0].password, "carp-secret");

    // Box no longer holds the VIP: redacted import is refused by name
    cluster.delete_carp_vip(vip.id).await.unwrap();
    let resp = server
        .post("/api/v1/config/import-preview")
        .authorization_bearer(&token)
        .json(&redacted)
        .await;
    let preview: Value = resp.json();
    assert_eq!(
        preview["unresolved_secrets"][0],
        format!("carp[{}].password", vip.id)
    );
    let resp = server
        .post("/api/v1/config/import")
        .authorization_bearer(&token)
        .json(&redacted)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(resp.text().contains(&vip.id.to_string()), "{}", resp.text());
    assert!(cluster.list_carp_vips().await.unwrap().is_empty());

    // History view is a display surface — redacted too
    let resp = server
        .get("/api/v1/config/history")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
}
