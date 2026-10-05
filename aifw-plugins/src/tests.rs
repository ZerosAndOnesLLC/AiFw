use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::context::{LogLevel, PluginContext};
use crate::error::PluginError;
use crate::hooks::*;
use crate::manager::{PluginManager, SettingsPatch};
use crate::plugin::*;
use crate::registry::Factory;
use crate::rules::{RuleSink, check_rule, check_table_name};
use crate::schema::{self, ListItem, PluginSettings, SelectOption, SettingField};
use crate::store::{PluginStore, StoredConfig};

/// Configurable behaviour for the probe plugin.
#[derive(Clone, Default)]
struct Behaviour {
    hooks: Vec<HookPoint>,
    reply: HookAction,
    init_error: bool,
    init_panic: bool,
    hook_sleep: Option<Duration>,
    hook_panic: bool,
    reject_settings: bool,
    rules: Vec<String>,
    touch_table: Option<&'static str>,
}

/// Records what the manager hands the plugin.
#[derive(Default)]
struct Seen {
    settings: Mutex<Option<PluginSettings>>,
    events: Mutex<Vec<HookEvent>>,
    shutdowns: Mutex<u32>,
}

struct Probe {
    name: &'static str,
    b: Behaviour,
    seen: Arc<Seen>,
}

#[async_trait]
impl Plugin for Probe {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: self.name.to_string(),
            title: format!("Probe {}", self.name),
            version: "0.0.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            hooks: self.b.hooks.clone(),
        }
    }

    fn settings_schema(&self) -> Vec<SettingField> {
        vec![
            SettingField::integer("limit", "Limit", 1, 10, 5),
            SettingField::text("token", "Token", 64).secret(),
        ]
    }

    fn validate_settings(&self, _s: &PluginSettings) -> crate::Result<()> {
        if self.b.reject_settings {
            Err(PluginError::Validation("configure something first".into()))
        } else {
            Ok(())
        }
    }

    fn actions(&self) -> Vec<ActionInfo> {
        vec![
            ActionInfo::new("echo", "Echo", "returns its argument")
                .arg(SettingField::text("msg", "Message", 32)),
        ]
    }

    async fn init(&mut self, settings: &PluginSettings, ctx: &PluginContext) -> crate::Result<()> {
        if self.b.init_panic {
            panic!("boom");
        }
        if self.b.init_error {
            return Err("cannot start".into());
        }
        if let Some(t) = self.b.touch_table {
            ctx.add_to_table(t, IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)))
                .await?;
        }
        if !self.b.rules.is_empty() {
            ctx.set_rules(self.b.rules.clone()).await?;
        }
        *self.seen.settings.lock().unwrap() = Some(settings.clone());
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        if self.b.hook_panic {
            panic!("hook boom");
        }
        if let Some(d) = self.b.hook_sleep {
            tokio::time::sleep(d).await;
        }
        self.seen.events.lock().unwrap().push(event.clone());
        self.b.reply.clone()
    }

    async fn run_action(
        &self,
        action: &str,
        args: Value,
        _ctx: &PluginContext,
    ) -> crate::Result<Value> {
        assert_eq!(action, "echo");
        Ok(args)
    }

    async fn status(&self, _ctx: &PluginContext) -> Value {
        json!({"ok": true})
    }

    async fn shutdown(&self, _ctx: &PluginContext) -> crate::Result<()> {
        *self.seen.shutdowns.lock().unwrap() += 1;
        Ok(())
    }
}

fn probe(name: &'static str, b: Behaviour) -> (Factory, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    let f: Factory = Arc::new(move || {
        Box::new(Probe {
            name,
            b: b.clone(),
            seen: s.clone(),
        }) as Box<dyn Plugin>
    });
    (f, seen)
}

struct Fixture {
    mgr: PluginManager,
    pf: Arc<dyn aifw_pf::PfBackend>,
    pool: sqlx::SqlitePool,
}

async fn fixture(factories: Vec<Factory>) -> Fixture {
    let db = aifw_core::Database::new_in_memory().await.unwrap();
    let pool = db.pool().clone();
    PluginStore::new(pool.clone()).migrate().await.unwrap();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let mgr = PluginManager::with_factories(pf.clone(), pool.clone(), factories).unwrap();
    mgr.start().await;
    Fixture { mgr, pf, pool }
}

fn hooks(h: &[HookPoint]) -> Behaviour {
    Behaviour {
        hooks: h.to_vec(),
        ..Default::default()
    }
}

fn log_event() -> HookEvent {
    HookEvent {
        hook: HookPoint::LogEvent,
        data: HookEventData::Log {
            action: "rule_added".to_string(),
            details: "block ssh".to_string(),
            source: "engine".to_string(),
        },
    }
}

fn api_event() -> HookEvent {
    HookEvent {
        hook: HookPoint::ApiRequest,
        data: HookEventData::Api {
            method: "GET".into(),
            path: "/api/v1/rules".into(),
            remote_addr: None,
        },
    }
}

// ---- registration & lifecycle -------------------------------------------

#[tokio::test]
async fn rejects_duplicate_and_invalid_names() {
    let db = aifw_core::Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let (a, _) = probe("dup", Behaviour::default());
    let (b, _) = probe("dup", Behaviour::default());
    assert!(PluginManager::with_factories(pf.clone(), db.pool().clone(), vec![a, b]).is_err());
    let (c, _) = probe("Bad Name", Behaviour::default());
    assert!(PluginManager::with_factories(pf, db.pool().clone(), vec![c]).is_err());
}

#[tokio::test]
async fn plugins_start_disabled_and_stay_listed_when_disabled() {
    let (f, seen) = probe("p", hooks(&[HookPoint::LogEvent]));
    let fx = fixture(vec![f]).await;

    let s = fx.mgr.get("p").unwrap();
    assert_eq!(s.state, PluginState::Stopped);
    assert!(!s.enabled);

    let s = fx.mgr.set_enabled("p", true).await.unwrap();
    assert_eq!(s.state, PluginState::Running);
    assert!(fx.mgr.wants(HookPoint::LogEvent));

    let s = fx.mgr.set_enabled("p", false).await.unwrap();
    assert_eq!(s.state, PluginState::Stopped);
    assert!(!fx.mgr.wants(HookPoint::LogEvent));
    assert_eq!(fx.mgr.list().len(), 1, "disabled plugin must stay listed");
    assert_eq!(*seen.shutdowns.lock().unwrap(), 1);

    // Re-enable works without a restart.
    assert_eq!(
        fx.mgr.set_enabled("p", true).await.unwrap().state,
        PluginState::Running
    );
}

#[tokio::test]
async fn unknown_plugin_is_not_found() {
    let fx = fixture(vec![]).await;
    assert!(matches!(
        fx.mgr.set_enabled("nope", true).await,
        Err(PluginError::NotFound(_))
    ));
}

#[tokio::test]
async fn init_failure_sets_error_state() {
    let (f, _) = probe(
        "p",
        Behaviour {
            init_error: true,
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    let s = fx.mgr.set_enabled("p", true).await.unwrap();
    assert_eq!(s.state, PluginState::Error);
    assert!(s.enabled);
    assert!(s.last_error.unwrap().contains("cannot start"));
    let logs = fx.mgr.logs("p", 10, LogLevel::Error).unwrap();
    assert!(logs[0].message.contains("failed to start"));

    // Disabling clears the error.
    let s = fx.mgr.set_enabled("p", false).await.unwrap();
    assert_eq!(s.state, PluginState::Stopped);
    assert!(s.last_error.is_none());
}

#[tokio::test]
async fn init_panic_is_contained() {
    let (f, _) = probe(
        "p",
        Behaviour {
            init_panic: true,
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    let s = fx.mgr.set_enabled("p", true).await.unwrap();
    assert_eq!(s.state, PluginState::Error);
    assert_eq!(s.last_error.as_deref(), Some("init panicked"));
}

#[tokio::test]
async fn enable_refused_when_settings_invalid() {
    let (f, _) = probe(
        "p",
        Behaviour {
            reject_settings: true,
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    assert!(matches!(
        fx.mgr.set_enabled("p", true).await,
        Err(PluginError::Validation(_))
    ));
    assert!(
        !fx.mgr.get("p").unwrap().enabled,
        "refused enable must not persist"
    );
}

#[tokio::test]
async fn enabled_state_survives_restart() {
    let (f, _) = probe("p", Behaviour::default());
    let fx = fixture(vec![f]).await;
    fx.mgr.set_enabled("p", true).await.unwrap();

    let (f2, _) = probe("p", Behaviour::default());
    let mgr2 = PluginManager::with_factories(fx.pf.clone(), fx.pool.clone(), vec![f2]).unwrap();
    mgr2.start().await;
    assert_eq!(mgr2.get("p").unwrap().state, PluginState::Running);
}

#[tokio::test]
async fn reconcile_applies_out_of_band_writes() {
    let (f, _) = probe("p", Behaviour::default());
    let fx = fixture(vec![f]).await;
    // The CLI / restore write the store directly.
    let cfg = StoredConfig {
        enabled: true,
        ..Default::default()
    };
    fx.mgr.store().save("p", &cfg).await.unwrap();
    assert_eq!(fx.mgr.get("p").unwrap().state, PluginState::Stopped);
    fx.mgr.reconcile().await;
    assert_eq!(fx.mgr.get("p").unwrap().state, PluginState::Running);
}

// ---- settings ---------------------------------------------------------------

#[tokio::test]
async fn settings_validated_persisted_and_applied() {
    let (f, seen) = probe("p", Behaviour::default());
    let fx = fixture(vec![f]).await;
    fx.mgr.set_enabled("p", true).await.unwrap();

    // Defaults reach init.
    assert_eq!(
        seen.settings.lock().unwrap().as_ref().unwrap().i64("limit"),
        Some(5)
    );

    // Out of range → 400-class error, nothing persisted.
    let bad = SettingsPatch {
        values: serde_json::from_value(json!({"limit": 99})).unwrap(),
        ..Default::default()
    };
    assert!(matches!(
        fx.mgr.update_settings("p", bad).await,
        Err(PluginError::Validation(_))
    ));

    // Secret passed as a plain value is refused.
    let wrong = SettingsPatch {
        values: serde_json::from_value(json!({"token": "x"})).unwrap(),
        ..Default::default()
    };
    assert!(fx.mgr.update_settings("p", wrong).await.is_err());

    let ok = SettingsPatch {
        values: serde_json::from_value(json!({"limit": 7})).unwrap(),
        secrets: serde_json::from_value(json!({"token": "s3cret"})).unwrap(),
    };
    let detail = fx.mgr.update_settings("p", ok).await.unwrap();
    assert_eq!(detail.values["limit"], 7);
    assert_eq!(detail.secrets_set, vec!["token".to_string()]);
    assert!(
        !detail.effective.contains_key("token"),
        "secrets never returned"
    );

    // Running plugin was restarted with the new settings, secret included.
    let s = seen.settings.lock().unwrap().clone().unwrap();
    assert_eq!(s.i64("limit"), Some(7));
    assert_eq!(s.str("token"), Some("s3cret"));

    // Secret is sealed at rest.
    let raw: Option<String> =
        sqlx::query_scalar("SELECT secrets FROM plugin_config WHERE name = 'p'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    let raw = raw.unwrap();
    assert!(aifw_core::secrets::is_sealed(&raw));
    assert!(!raw.contains("s3cret"));

    // null resets to default / clears the secret.
    let reset = SettingsPatch {
        values: serde_json::from_value(json!({"limit": null})).unwrap(),
        secrets: serde_json::from_value(json!({"token": null})).unwrap(),
    };
    let detail = fx.mgr.update_settings("p", reset).await.unwrap();
    assert!(detail.values.is_empty());
    assert!(detail.secrets_set.is_empty());
    assert_eq!(detail.effective["limit"], 5);
}

#[test]
fn schema_normalizes_and_rejects() {
    let schema = vec![
        SettingField::list("nets", "Networks", ListItem::Cidr, 3),
        SettingField::select(
            "mode",
            "Mode",
            vec![SelectOption::new("a", "A"), SelectOption::new("b", "B")],
            "a",
        ),
        SettingField::url("hook", "Hook", true),
        SettingField::bool("on", "On", false),
    ];
    let m = |v: Value| serde_json::from_value(v).unwrap();
    let empty = serde_json::Map::new();

    let (vals, _) = schema::normalize(
        &schema,
        &m(json!({"nets": ["10.0.0.0/8", " 10.0.0.0/8 ", "", "2001:db8::1"]})),
        &empty,
    )
    .unwrap();
    assert_eq!(vals["nets"], json!(["10.0.0.0/8", "2001:db8::1"]));

    for bad in [
        json!({"nets": ["300.1.1.1"]}),
        json!({"nets": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]}),
        json!({"mode": "c"}),
        json!({"hook": "http://example.com"}),
        json!({"on": "yes"}),
        json!({"unknown": 1}),
    ] {
        assert!(
            schema::normalize(&schema, &m(bad.clone()), &empty).is_err(),
            "{bad} should be rejected"
        );
    }

    let eff = schema::effective(&schema, &empty, &empty);
    assert_eq!(eff.str("mode"), Some("a"));
    assert!(!eff.bool("on"));
    assert!(eff.strings("nets").is_empty());
}

// ---- dispatch -----------------------------------------------------------------

#[tokio::test]
async fn dispatch_only_reaches_running_subscribers() {
    let (a, seen_a) = probe("a", hooks(&[HookPoint::LogEvent]));
    let (b, seen_b) = probe("b", hooks(&[HookPoint::Timer]));
    let (c, seen_c) = probe("c", hooks(&[HookPoint::LogEvent]));
    let fx = fixture(vec![a, b, c]).await;
    fx.mgr.set_enabled("a", true).await.unwrap();
    fx.mgr.set_enabled("b", true).await.unwrap();
    // c stays disabled.

    fx.mgr.dispatch(log_event()).await;
    assert_eq!(seen_a.events.lock().unwrap().len(), 1);
    assert!(seen_b.events.lock().unwrap().is_empty());
    assert!(seen_c.events.lock().unwrap().is_empty());
    assert_eq!(fx.mgr.get("a").unwrap().stats.events, 1);
}

#[tokio::test]
async fn block_only_honored_for_api_requests() {
    let (f, _) = probe(
        "p",
        Behaviour {
            hooks: vec![HookPoint::ApiRequest, HookPoint::LogEvent],
            reply: HookAction::Block,
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    fx.mgr.set_enabled("p", true).await.unwrap();
    assert!(fx.mgr.dispatch(api_event()).await.blocked);
    assert!(!fx.mgr.dispatch(log_event()).await.blocked);
}

#[tokio::test]
async fn slow_and_panicking_plugins_are_isolated() {
    let (slow, _) = probe(
        "slow",
        Behaviour {
            hooks: vec![HookPoint::ApiRequest],
            hook_sleep: Some(Duration::from_secs(2)),
            reply: HookAction::Block,
            ..Default::default()
        },
    );
    let (bad, _) = probe(
        "bad",
        Behaviour {
            hooks: vec![HookPoint::ApiRequest],
            hook_panic: true,
            ..Default::default()
        },
    );
    let (good, seen_good) = probe("good", hooks(&[HookPoint::ApiRequest]));
    let fx = fixture(vec![slow, bad, good]).await;
    for n in ["slow", "bad", "good"] {
        fx.mgr.set_enabled(n, true).await.unwrap();
    }

    let started = std::time::Instant::now();
    let out = fx.mgr.dispatch(api_event()).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "API hook budget must cap the wait"
    );
    assert!(!out.blocked, "a timed-out Block must not apply");
    assert_eq!(seen_good.events.lock().unwrap().len(), 1);
    assert_eq!(fx.mgr.get("slow").unwrap().stats.timeouts, 1);
    assert_eq!(fx.mgr.get("bad").unwrap().stats.panics, 1);
    assert_eq!(fx.mgr.get("bad").unwrap().state, PluginState::Running);
}

#[tokio::test]
async fn returned_actions_are_sandboxed_and_flattened() {
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let (f, _) = probe(
        "p",
        Behaviour {
            hooks: vec![HookPoint::LogEvent],
            reply: HookAction::Multi(vec![
                HookAction::AddToTable {
                    table: "plugin_test".into(),
                    ip,
                },
                HookAction::AddToTable {
                    table: "bruteforce".into(),
                    ip,
                },
                HookAction::Multi(vec![HookAction::Log("hello from plugin".into())]),
            ]),
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    fx.mgr.set_enabled("p", true).await.unwrap();
    fx.mgr.dispatch(log_event()).await;

    let ours = fx.pf.get_table_entries("plugin_test").await.unwrap();
    assert_eq!(ours.len(), 1);
    let system = fx.pf.get_table_entries("bruteforce").await.unwrap();
    assert!(system.is_empty(), "system tables must be off limits");

    let s = fx.mgr.get("p").unwrap().stats;
    assert_eq!(s.errors, 1);
    assert_eq!(s.actions, 3);
    let logs = fx.mgr.logs("p", 50, LogLevel::Info).unwrap();
    assert!(logs.iter().any(|l| l.message == "hello from plugin"));
}

// ---- pf effects ---------------------------------------------------------------

#[tokio::test]
async fn stop_removes_rules_and_flushes_tables() {
    let rule = "block drop in quick from <plugin_probe>".to_string();
    let (f, _) = probe(
        "p",
        Behaviour {
            rules: vec![rule.clone()],
            touch_table: Some("plugin_probe"),
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    fx.mgr.set_enabled("p", true).await.unwrap();
    let anchor = aifw_common::anchors::PLUGINS;
    assert_eq!(fx.pf.get_rules(anchor).await.unwrap(), vec![rule.clone()]);
    assert_eq!(fx.mgr.detail("p").await.unwrap().rules, vec![rule]);
    assert_eq!(
        fx.pf.get_table_entries("plugin_probe").await.unwrap().len(),
        1
    );

    fx.mgr.set_enabled("p", false).await.unwrap();
    assert!(fx.pf.get_rules(anchor).await.unwrap().is_empty());
    assert!(
        fx.pf
            .get_table_entries("plugin_probe")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn invalid_rules_fail_init() {
    let (f, _) = probe(
        "p",
        Behaviour {
            rules: vec!["pass in all".to_string()],
            ..Default::default()
        },
    );
    let fx = fixture(vec![f]).await;
    let s = fx.mgr.set_enabled("p", true).await.unwrap();
    assert_eq!(s.state, PluginState::Error);
}

#[test]
fn rule_validation() {
    for ok in [
        "block drop in log quick from <plugin_threat_feeds> label \"plugin:threat-feeds:in\"",
        "block drop out quick to <plugin_x>",
        "match in log from <plugin_x>",
        "block in quick from ! <plugin_allow> to <plugin_x>",
    ] {
        assert!(check_rule(ok).is_ok(), "{ok}");
    }
    for bad in [
        "pass in all",
        "block in quick from <bruteforce>",
        "block in quick from any",
        "block in quick from <plugin_x> rdr-to 1.2.3.4",
        "match in from <plugin_x> route-to (em0 1.2.3.4)",
        "block in from <plugin_x>; pass all",
        "block in from <plugin_x>\npass all",
        "anchor foo from <plugin_x>",
    ] {
        assert!(check_rule(bad).is_err(), "{bad}");
    }
    assert!(check_table_name("plugin_ok_1").is_ok());
    for bad in [
        "plugin_",
        "ai_blocked",
        "plugin_bad-name",
        "plugin_aaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert!(check_table_name(bad).is_err(), "{bad}");
    }
}

// ---- context ------------------------------------------------------------------

#[tokio::test]
async fn kv_is_namespaced_per_plugin() {
    let db = aifw_core::Database::new_in_memory().await.unwrap();
    let pool = db.pool().clone();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let sink = Arc::new(RuleSink::new(pf.clone(), "aifw-plugins"));
    let a = PluginContext::new("a", pf.clone(), pool.clone(), sink.clone());
    let b = PluginContext::new("b", pf, pool, sink);

    a.kv_set("k", "1").await.unwrap();
    assert_eq!(a.kv_get("k").await.unwrap().as_deref(), Some("1"));
    assert_eq!(b.kv_get("k").await.unwrap(), None);
    a.kv_set_json("j", &vec![1, 2]).await.unwrap();
    assert_eq!(
        a.kv_get_json::<Vec<i32>>("j").await.unwrap(),
        Some(vec![1, 2])
    );
    a.kv_delete("k").await.unwrap();
    assert_eq!(a.kv_get("k").await.unwrap(), None);
}

#[tokio::test]
async fn activity_log_is_bounded_and_newest_first() {
    let db = aifw_core::Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let sink = Arc::new(RuleSink::new(pf.clone(), "aifw-plugins"));
    let ctx = PluginContext::new("a", pf, db.pool().clone(), sink);
    for i in 0..600 {
        ctx.info(format!("m{i}"));
    }
    ctx.warn("last");
    let all = ctx.recent_logs(1000, LogLevel::Info);
    assert_eq!(all.len(), 500);
    assert_eq!(all[0].message, "last");
    let warns = ctx.recent_logs(1000, LogLevel::Warn);
    assert_eq!(warns.len(), 1);
}

// ---- actions & status -------------------------------------------------------------

#[tokio::test]
async fn actions_require_running_plugin_and_valid_args() {
    let (f, _) = probe("p", Behaviour::default());
    let fx = fixture(vec![f]).await;
    assert!(matches!(
        fx.mgr.run_action("p", "echo", json!({"msg": "hi"})).await,
        Err(PluginError::Validation(_))
    ));
    fx.mgr.set_enabled("p", true).await.unwrap();
    let v = fx
        .mgr
        .run_action("p", "echo", json!({"msg": "hi"}))
        .await
        .unwrap();
    assert_eq!(v["msg"], "hi");
    assert!(matches!(
        fx.mgr.run_action("p", "nope", Value::Null).await,
        Err(PluginError::NotFound(_))
    ));
    assert!(
        fx.mgr
            .run_action("p", "echo", json!({"bogus": 1}))
            .await
            .is_err()
    );
    assert_eq!(fx.mgr.status("p").await.unwrap(), json!({"ok": true}));
}
