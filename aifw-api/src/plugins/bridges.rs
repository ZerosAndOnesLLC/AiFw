//! Event sources for plugin hooks that live outside the request path, plus
//! the plugin boot / reconcile loop. Every bridge idles (one atomic load per
//! tick) unless a running plugin subscribes to its hook, and when it wakes
//! up it starts from "now" — enabling a plugin never replays history.

use std::time::Duration;

use aifw_plugins::{HookEvent, HookEventData, HookPoint};

use super::tails::{self, Source};
use super::vpn_watch;
use crate::AppState;

/// How often config written outside the API (CLI, restore, cluster sync)
/// is picked up.
const RECONCILE_EVERY: Duration = Duration::from_secs(10);
const TIMER_EVERY: Duration = Duration::from_secs(60);

/// Start enabled plugins and every hook bridge. Called once from
/// `async_main` after engines are up.
pub async fn start(state: AppState) {
    state.plugin_manager.start().await;

    let mgr = state.plugin_manager.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RECONCILE_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            mgr.reconcile().await;
        }
    });

    start_timer(state.clone());
    for src in [Source::Audit, Source::Ids, Source::Gateway] {
        tails::spawn(state.clone(), src);
    }
    vpn_watch::spawn(state);
}

fn start_timer(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TIMER_EVERY);
        loop {
            tick.tick().await;
            if !state.plugin_manager.wants(HookPoint::Timer) {
                continue;
            }
            let timestamp = chrono::Utc::now().timestamp().max(0) as u64;
            state
                .plugin_manager
                .dispatch(HookEvent {
                    hook: HookPoint::Timer,
                    data: HookEventData::Tick { timestamp },
                })
                .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use aifw_plugins::{Plugin, PluginContext, PluginInfo, PluginSettings, registry::Factory};

    /// Test plugin that records every event it receives.
    struct CapturePlugin {
        hooks: Vec<HookPoint>,
        events: Arc<Mutex<Vec<HookEvent>>>,
    }

    #[async_trait::async_trait]
    impl Plugin for CapturePlugin {
        fn info(&self) -> PluginInfo {
            PluginInfo {
                name: "capture".to_string(),
                title: "Capture".to_string(),
                version: "0.0.0".to_string(),
                description: "test capture plugin".to_string(),
                author: "test".to_string(),
                hooks: self.hooks.clone(),
            }
        }

        async fn init(
            &mut self,
            _settings: &PluginSettings,
            _ctx: &PluginContext,
        ) -> aifw_plugins::Result<()> {
            Ok(())
        }

        async fn on_hook(
            &self,
            event: &HookEvent,
            _ctx: &PluginContext,
        ) -> aifw_plugins::HookAction {
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event.clone());
            aifw_plugins::HookAction::Continue
        }
    }

    pub(crate) fn test_auth_settings() -> crate::auth::AuthSettings {
        crate::auth::AuthSettings {
            jwt_secret: "test-secret-key".to_string(),
            access_token_expiry_mins: 60,
            refresh_token_expiry_days: 7,
            require_totp: false,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
            max_login_attempts: 5,
            lockout_duration_secs: 300,
            allow_registration: true,
            password_min_length: 8,
        }
    }

    /// App state whose plugin manager holds only an enabled capture plugin.
    pub(crate) async fn state_with_capture(
        hooks: Vec<HookPoint>,
    ) -> (AppState, Arc<Mutex<Vec<HookEvent>>>) {
        let mut state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        let factory: Factory = Arc::new(move || {
            Box::new(CapturePlugin {
                hooks: hooks.clone(),
                events: ev.clone(),
            }) as Box<dyn Plugin>
        });
        state.plugin_manager = Arc::new(
            aifw_plugins::PluginManager::with_factories(
                state.pf.clone(),
                state.pool.clone(),
                vec![factory],
            )
            .unwrap(),
        );
        state
            .plugin_manager
            .set_enabled("capture", true)
            .await
            .unwrap();
        (state, events)
    }

    #[tokio::test]
    async fn audit_log_entries_reach_log_event_hook() {
        let (state, events) = state_with_capture(vec![HookPoint::LogEvent]).await;
        let mut tail = tails::Tail::default();
        tail.seek_end(&state, Source::Audit).await;

        aifw_core::audit::AuditLog::new(state.pool.clone())
            .log(
                aifw_core::audit::AuditAction::ConfigChanged,
                None,
                "test details",
                "test",
            )
            .await
            .unwrap();
        tail.poll(&state, Source::Audit).await;
        // A second poll must not redeliver.
        tail.poll(&state, Source::Audit).await;

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 1);
        match &captured[0].data {
            HookEventData::Log {
                action,
                details,
                source,
            } => {
                assert_eq!(action, "config_changed");
                assert_eq!(details, "test details");
                assert_eq!(source, "test");
            }
            other => panic!("unexpected event data: {other:?}"),
        }
    }

    async fn insert_alert(pool: &sqlx::SqlitePool, id: &str, src: &str) {
        sqlx::query(
            "INSERT INTO ids_alerts (id, timestamp, signature_id, signature_msg, severity, \
             src_ip, src_port, dst_ip, dst_port, protocol, action, rule_source) \
             VALUES (?1, '2026-10-05T00:00:00Z', 2001, 'ET SCAN test', 1, ?2, 4444, \
             '10.0.0.1', 22, 'tcp', 'alert', 'suricata')",
        )
        .bind(id)
        .bind(src)
        .execute(pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn ids_alerts_reach_ids_alert_hook_without_backlog() {
        let (state, events) = state_with_capture(vec![HookPoint::IdsAlert]).await;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ids_alerts (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, \
             signature_id INTEGER, signature_msg TEXT NOT NULL, severity INTEGER NOT NULL, \
             src_ip TEXT NOT NULL, src_port INTEGER, dst_ip TEXT NOT NULL, dst_port INTEGER, \
             protocol TEXT NOT NULL, action TEXT NOT NULL, rule_source TEXT NOT NULL)",
        )
        .execute(&state.pool)
        .await
        .unwrap();
        insert_alert(&state.pool, "old", "198.51.100.1").await;

        let mut tail = tails::Tail::default();
        tail.seek_end(&state, Source::Ids).await;
        insert_alert(&state.pool, "new", "203.0.113.9").await;
        insert_alert(&state.pool, "bad", "not-an-ip").await;
        tail.poll(&state, Source::Ids).await;

        let captured = events.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "history and unparseable rows are skipped"
        );
        match &captured[0].data {
            HookEventData::IdsAlertEvent {
                alert_id,
                severity,
                src_ip,
                signature_id,
                ..
            } => {
                assert_eq!(alert_id, "new");
                assert_eq!(*severity, 1);
                assert_eq!(src_ip.to_string(), "203.0.113.9");
                assert_eq!(*signature_id, Some(2001));
            }
            other => panic!("unexpected event data: {other:?}"),
        }
    }

    #[tokio::test]
    async fn gateway_events_are_deduplicated() {
        let (state, events) = state_with_capture(vec![HookPoint::GatewayEvent]).await;
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&state.pool)
            .await
            .unwrap();
        let mut tail = tails::Tail::default();
        tail.seek_end(&state, Source::Gateway).await;
        for (from, to) in [("up", "down"), ("up", "down"), ("down", "up")] {
            sqlx::query(
                "INSERT INTO multiwan_gateway_events (gateway_id, ts, from_state, to_state, reason) \
                 VALUES ('gw1', '2026-10-05T00:00:00Z', ?1, ?2, 'loss 40% > 20%')",
            )
            .bind(from)
            .bind(to)
            .execute(&state.pool)
            .await
            .unwrap();
        }
        tail.poll(&state, Source::Gateway).await;

        let captured = events.lock().unwrap();
        let states: Vec<String> = captured
            .iter()
            .map(|e| match &e.data {
                HookEventData::Gateway {
                    to_state,
                    gateway_name,
                    ..
                } => {
                    assert_eq!(gateway_name, "gw1", "falls back to the id");
                    to_state.clone()
                }
                other => panic!("unexpected event data: {other:?}"),
            })
            .collect();
        assert_eq!(states, vec!["down", "up"]);
    }

    #[tokio::test]
    async fn nothing_dispatched_without_subscribers() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();
        assert!(!state.plugin_manager.wants(HookPoint::LogEvent));
        assert!(!state.plugin_manager.wants(HookPoint::ApiRequest));
    }
}
