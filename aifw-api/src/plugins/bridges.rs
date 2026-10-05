//! Event sources for plugin hooks that live outside the request path, plus
//! the plugin boot / reconcile loop. Every bridge idles (one atomic load per
//! tick) unless a running plugin subscribes to its hook, and when it wakes
//! up it starts from "now" — enabling a plugin never replays history.

use std::time::Duration;

use aifw_plugins::{HookEvent, HookEventData, HookPoint};
use sqlx::SqlitePool;

use crate::AppState;

/// How often config written outside the API (CLI, restore, cluster sync)
/// is picked up.
const RECONCILE_EVERY: Duration = Duration::from_secs(10);
const TIMER_EVERY: Duration = Duration::from_secs(60);
const AUDIT_POLL_EVERY: Duration = Duration::from_secs(5);

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
    start_audit_tail(state);
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

/// Current tail position (max rowid) of the audit_log table.
async fn audit_log_tail(pool: &SqlitePool) -> i64 {
    match sqlx::query_scalar("SELECT COALESCE(MAX(rowid), 0) FROM audit_log")
        .fetch_one(pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "plugins: audit tail position query failed");
            0
        }
    }
}

/// Dispatch audit rows past `last_rowid` as `LogEvent` hooks (#488) and
/// return the new cursor. Split from the loop so tests can drive one poll.
async fn dispatch_new_audit_entries(state: &AppState, last_rowid: i64) -> i64 {
    let rows: Vec<(i64, String, String, String)> = match sqlx::query_as(
        "SELECT rowid, action, details, source FROM audit_log \
         WHERE rowid > ?1 ORDER BY rowid ASC LIMIT 200",
    )
    .bind(last_rowid)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "plugins: audit hook tail query failed");
            return last_rowid;
        }
    };

    let mut cursor = last_rowid;
    for (rowid, action, details, source) in rows {
        cursor = rowid;
        state
            .plugin_manager
            .dispatch(HookEvent {
                hook: HookPoint::LogEvent,
                data: HookEventData::Log {
                    action,
                    details,
                    source,
                },
            })
            .await;
    }
    cursor
}

/// Tail audit_log into `LogEvent` hooks. Audit rows are written inside the
/// aifw-core engines, which can't depend on aifw-plugins, so the API
/// bridges the two here.
fn start_audit_tail(state: AppState) {
    tokio::spawn(async move {
        let mut cursor = 0;
        let mut active = false;
        let mut tick = tokio::time::interval(AUDIT_POLL_EVERY);
        loop {
            tick.tick().await;
            if !state.plugin_manager.wants(HookPoint::LogEvent) {
                active = false;
                continue;
            }
            if !active {
                // Just became active — skip events from the idle gap.
                cursor = audit_log_tail(&state.pool).await;
                active = true;
                continue;
            }
            cursor = dispatch_new_audit_entries(&state, cursor).await;
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
        let cursor = audit_log_tail(&state.pool).await;

        aifw_core::audit::AuditLog::new(state.pool.clone())
            .log(
                aifw_core::audit::AuditAction::ConfigChanged,
                None,
                "test details",
                "test",
            )
            .await
            .unwrap();

        let new_cursor = dispatch_new_audit_entries(&state, cursor).await;
        assert!(new_cursor > cursor, "cursor must advance past the new row");

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

    #[tokio::test]
    async fn nothing_dispatched_without_subscribers() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();
        assert!(!state.plugin_manager.wants(HookPoint::LogEvent));
        assert!(!state.plugin_manager.wants(HookPoint::ApiRequest));
    }
}
