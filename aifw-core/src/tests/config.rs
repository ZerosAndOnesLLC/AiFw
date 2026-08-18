use super::*;

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
