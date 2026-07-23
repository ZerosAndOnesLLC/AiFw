use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;
use sqlx::sqlite::SqlitePool;

use crate::AppState;

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS plugin_config (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, settings TEXT)")
        .execute(pool).await?;
    Ok(())
}

#[derive(Serialize)]
pub struct PluginListEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub state: String,
    pub hooks: Vec<String>,
}

#[derive(Serialize)]
pub struct PluginsResponse {
    pub plugins: Vec<PluginListEntry>,
    pub total: usize,
    pub running: usize,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// Canonical registered name (`PluginInfo::name`) of a built-in plugin.
/// Accepts both the registered name (what the UI sends, taken from the
/// plugin list) and the legacy short keys the API historically matched on.
pub(crate) fn canonical_builtin(name: &str) -> Option<&'static str> {
    match name {
        "custom-logger" | "logging" => Some("custom-logger"),
        "ip-reputation" | "ip_reputation" => Some("ip-reputation"),
        "webhook-notifier" | "webhook" => Some("webhook-notifier"),
        _ => None,
    }
}

/// Create a fresh instance of a built-in plugin by name (either spelling).
pub(crate) fn instantiate_builtin(name: &str) -> Option<Box<dyn aifw_plugins::Plugin>> {
    match canonical_builtin(name)? {
        "custom-logger" => Some(Box::new(aifw_plugins::examples::LoggingPlugin::new())),
        "ip-reputation" => Some(Box::new(aifw_plugins::examples::IpReputationPlugin::new())),
        "webhook-notifier" => Some(Box::new(aifw_plugins::examples::WebhookPlugin::new())),
        _ => None,
    }
}

/// Load a plugin's persisted settings from the DB. Missing rows or
/// malformed JSON yield an empty map.
pub(crate) async fn load_settings(
    pool: &SqlitePool,
    name: &str,
) -> std::collections::HashMap<String, serde_json::Value> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT settings FROM plugin_config WHERE name = ?1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    row.and_then(|(s,)| s)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub async fn list_plugins(
    State(state): State<AppState>,
) -> Result<Json<PluginsResponse>, StatusCode> {
    let mgr = state.plugin_manager.read().await;
    let list = mgr.list_plugins();
    let running = mgr.running_count();
    let total = mgr.count();

    let plugins: Vec<PluginListEntry> = list
        .iter()
        .map(|(info, pstate)| PluginListEntry {
            name: info.name.clone(),
            version: info.version.clone(),
            description: info.description.clone(),
            author: info.author.clone(),
            state: pstate.to_string(),
            hooks: info.hooks.iter().map(|h| h.to_string()).collect(),
        })
        .collect();

    Ok(Json(PluginsResponse {
        plugins,
        total,
        running,
    }))
}

pub async fn enable_plugin(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // Persist to DB
    let _ = sqlx::query("INSERT INTO plugin_config (name, enabled) VALUES (?1, ?2) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled")
        .bind(name).bind(enabled as i32)
        .execute(&state.pool).await;

    let mut mgr = state.plugin_manager.write().await;
    // Plugins are registered under their PluginInfo::name — normalize so
    // legacy short keys ("logging") hit the same instance ("custom-logger").
    let reg_name = canonical_builtin(name).unwrap_or(name);

    if !enabled {
        let _ = mgr.unload(reg_name).await;
        // Sync the atomic shadow counter (PERF-C12).
        state
            .plugin_running_count
            .store(mgr.running_count(), std::sync::atomic::Ordering::Relaxed);
        Ok(Json(MessageResponse {
            message: format!("Plugin '{name}' disabled."),
        }))
    } else {
        // Re-register with enabled=true — need to create a new instance
        if let Some(p) = instantiate_builtin(name) {
            // Plugins read settings only in init(), so pass the persisted
            // settings — otherwise a saved webhook URL etc. never applies (#586).
            let settings = load_settings(&state.pool, name).await;
            // Unload old instance if exists
            let _ = mgr.unload(reg_name).await;
            let _ = mgr
                .register(
                    p,
                    aifw_plugins::PluginConfig {
                        enabled: true,
                        settings,
                    },
                )
                .await;
            state
                .plugin_running_count
                .store(mgr.running_count(), std::sync::atomic::Ordering::Relaxed);
            Ok(Json(MessageResponse {
                message: format!("Plugin '{name}' enabled and running."),
            }))
        } else {
            Ok(Json(MessageResponse {
                message: format!("Unknown plugin '{name}'."),
            }))
        }
    }
}

pub async fn get_plugin_config(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let row = sqlx::query_as::<_, (i32, Option<String>)>(
        "SELECT enabled, settings FROM plugin_config WHERE name = ?1",
    )
    .bind(&name)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "plugins: failed to query plugin config");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (enabled, settings) = row.unwrap_or((0, None));
    let settings_json: serde_json::Value = settings
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({}));

    Ok(Json(serde_json::json!({
        "name": name,
        "enabled": enabled != 0,
        "settings": settings_json,
    })))
}

pub async fn update_plugin_config(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let settings = payload
        .get("settings")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let settings_str = serde_json::to_string(&settings).unwrap_or_default();

    sqlx::query(
        "INSERT INTO plugin_config (name, enabled, settings) VALUES (?1, 0, ?2) ON CONFLICT(name) DO UPDATE SET settings=excluded.settings"
    ).bind(&name).bind(&settings_str).execute(&state.pool).await
    .map_err(|e| {
        tracing::error!(error = %e, plugin = %name, "plugins: failed to persist config");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Plugins read settings only in init(), so a running instance keeps its
    // old config until re-registered — restart it with the new settings (#586).
    let mut mgr = state.plugin_manager.write().await;
    let reg_name = canonical_builtin(&name).unwrap_or(&name);
    let running = mgr
        .list_plugins()
        .iter()
        .any(|(info, s)| info.name == reg_name && *s == aifw_plugins::PluginState::Running);
    if !running {
        return Ok(Json(MessageResponse {
            message: format!("Plugin '{name}' config updated."),
        }));
    }

    let Some(plugin) = instantiate_builtin(&name) else {
        return Ok(Json(MessageResponse {
            message: format!("Plugin '{name}' config updated."),
        }));
    };
    let settings_map: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_value(settings).unwrap_or_default();

    if let Err(e) = mgr.unload(reg_name).await {
        tracing::warn!(error = %e, plugin = %name, "plugins: unload before config reload failed");
    }
    let message = match mgr
        .register(
            plugin,
            aifw_plugins::PluginConfig {
                enabled: true,
                settings: settings_map,
            },
        )
        .await
    {
        Ok(()) => format!("Plugin '{name}' config updated and applied."),
        Err(e) => {
            tracing::error!(error = %e, plugin = %name, "plugins: restart with new config failed");
            // Keep the plugin listed (stopped) so the UI can still show it.
            if let Some(p) = instantiate_builtin(&name)
                && let Err(e2) = mgr.register(p, aifw_plugins::PluginConfig::default()).await
            {
                tracing::warn!(error = %e2, plugin = %name, "plugins: fallback re-register failed");
            }
            format!(
                "Plugin '{name}' config saved, but restarting it with the new settings failed: {e}"
            )
        }
    };
    state
        .plugin_running_count
        .store(mgr.running_count(), std::sync::atomic::Ordering::Relaxed);

    Ok(Json(MessageResponse { message }))
}

pub async fn get_plugin_logs(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // For the logging plugin, return its captured entries
    let mgr = state.plugin_manager.read().await;
    let list = mgr.list_plugins();

    // Check if plugin exists and is the logging plugin
    let found = list.iter().any(|(info, _)| info.name == name);
    if !found {
        return Ok(Json(
            serde_json::json!({ "entries": [], "message": "Plugin not found" }),
        ));
    }

    // We can't directly access plugin internals through the trait,
    // but we can report the hook dispatch count via stats
    Ok(Json(serde_json::json!({
        "name": name,
        "message": "Plugin logs available when plugin exposes a log endpoint",
        "stats": {
            "total_plugins": list.len(),
            "running": list.iter().filter(|(_, s)| *s == aifw_plugins::PluginState::Running).count(),
        }
    })))
}

pub async fn discover_plugins() -> Result<Json<serde_json::Value>, StatusCode> {
    let discovered = aifw_plugins::discovery::discover_plugins();
    Ok(Json(serde_json::json!({
        "plugins": discovered,
        "plugin_dir": "/usr/local/lib/aifw/plugins",
    })))
}

/// Dispatch a hook event to all running plugins.
///
/// Short-circuits on the atomic shadow counter — no plugins running means
/// no read-lock acquisition and an empty action list. Otherwise snapshots
/// the dispatch set under a short read lock and dispatches after dropping
/// it (PERF-H17 #361), so a slow plugin can't block enable/disable.
pub async fn dispatch_hook(
    state: &AppState,
    event: aifw_plugins::HookEvent,
) -> Vec<aifw_plugins::HookAction> {
    if state
        .plugin_running_count
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
    {
        return Vec::new();
    }
    let plugins = state.plugin_manager.read().await.dispatch_set();
    plugins.dispatch(&event).await
}

/// Current tail position (max rowid) of the audit_log table.
async fn audit_log_tail(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(rowid), 0) FROM audit_log")
        .fetch_one(pool)
        .await
        .unwrap_or(0)
}

/// Fetch audit rows past `last_rowid` and dispatch each to plugins as a
/// `LogEvent` hook (#488). Returns the new cursor. Table-mutation actions
/// returned by plugins are applied to pf, mirroring the ConnectionNew site
/// in ws.rs. Split from the spawn loop so tests can drive a single poll.
async fn dispatch_new_audit_entries(state: &AppState, last_rowid: i64) -> i64 {
    let rows: Vec<(i64, String, String, String)> = match sqlx::query_as(
        "SELECT rowid, action, details, source FROM audit_log WHERE rowid > ?1 ORDER BY rowid ASC LIMIT 200",
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
        let event = aifw_plugins::HookEvent {
            hook: aifw_plugins::HookPoint::LogEvent,
            data: aifw_plugins::hooks::HookEventData::Log {
                action,
                details,
                source,
            },
        };
        for act in dispatch_hook(state, event).await {
            match act {
                aifw_plugins::HookAction::AddToTable { ref table, ip } => {
                    if let Err(e) = state.pf.add_table_entry(table, ip).await {
                        tracing::warn!(error = %e, %table, %ip, "plugins: AddToTable from LogEvent hook failed");
                    }
                }
                aifw_plugins::HookAction::RemoveFromTable { ref table, ip } => {
                    if let Err(e) = state.pf.remove_table_entry(table, ip).await {
                        tracing::warn!(error = %e, %table, %ip, "plugins: RemoveFromTable from LogEvent hook failed");
                    }
                }
                _ => {}
            }
        }
    }
    cursor
}

/// Background task: tail the audit_log table and fan new entries out to
/// plugins subscribed to the `LogEvent` hook (#488). Audit rows are written
/// inside the aifw-core engines (rule/NAT/config mutations), and aifw-core
/// cannot depend on aifw-plugins — so the API bridges the two here.
///
/// Entries written while no plugin is running are skipped: the cursor
/// re-snaps to the table tail on the 0→N running transition, so enabling a
/// plugin doesn't replay a backlog of historical events into it.
pub fn start_audit_hook_dispatcher(state: AppState) {
    tokio::spawn(async move {
        let mut cursor = audit_log_tail(&state.pool).await;
        let mut was_active = false;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let active = state
                .plugin_running_count
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0;
            if !active {
                was_active = false;
                continue;
            }
            if !was_active {
                // Plugins just became active — skip events from the idle gap.
                cursor = audit_log_tail(&state.pool).await;
                was_active = true;
                continue;
            }
            cursor = dispatch_new_audit_entries(&state, cursor).await;
        }
    });
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use std::sync::Arc;

    /// Test plugin that records every event it receives.
    struct CapturePlugin {
        events: Arc<tokio::sync::Mutex<Vec<aifw_plugins::HookEvent>>>,
    }

    #[async_trait::async_trait]
    impl aifw_plugins::Plugin for CapturePlugin {
        fn info(&self) -> aifw_plugins::PluginInfo {
            aifw_plugins::PluginInfo {
                name: "capture".to_string(),
                version: "0.0.0".to_string(),
                description: "test capture plugin".to_string(),
                author: "test".to_string(),
                hooks: vec![aifw_plugins::HookPoint::LogEvent],
            }
        }

        async fn init(
            &mut self,
            _config: &aifw_plugins::PluginConfig,
            _ctx: &aifw_plugins::PluginContext,
        ) -> aifw_plugins::Result<()> {
            Ok(())
        }

        async fn on_hook(
            &self,
            event: &aifw_plugins::HookEvent,
            _ctx: &aifw_plugins::PluginContext,
        ) -> aifw_plugins::HookAction {
            self.events.lock().await.push(event.clone());
            aifw_plugins::HookAction::Continue
        }

        async fn shutdown(&mut self) -> aifw_plugins::Result<()> {
            Ok(())
        }
    }

    fn test_auth_settings() -> crate::auth::AuthSettings {
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

    #[tokio::test]
    async fn audit_log_entries_reach_log_event_hook() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();

        let events = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        {
            let mut mgr = state.plugin_manager.write().await;
            mgr.register(
                Box::new(CapturePlugin {
                    events: events.clone(),
                }),
                aifw_plugins::PluginConfig {
                    enabled: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            state
                .plugin_running_count
                .store(mgr.running_count(), std::sync::atomic::Ordering::Relaxed);
        }

        let cursor = audit_log_tail(&state.pool).await;

        // Write an audit row the same way the aifw-core engines do.
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

        let captured = events.lock().await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].hook, aifw_plugins::HookPoint::LogEvent);
        match &captured[0].data {
            aifw_plugins::hooks::HookEventData::Log {
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

    /// Drift guard: `canonical_builtin` must return exactly the name each
    /// built-in registers under (`PluginInfo::name`) — the UI keys every
    /// toggle/config call on that name.
    #[test]
    fn canonical_builtin_matches_plugin_info_names() {
        for key in ["custom-logger", "ip-reputation", "webhook-notifier"] {
            let canonical = canonical_builtin(key).expect("builtin key must resolve");
            let info = instantiate_builtin(key)
                .expect("builtin must instantiate")
                .info();
            assert_eq!(canonical, info.name, "canonical name drifted for '{key}'");
        }
    }

    #[tokio::test]
    async fn update_config_restarts_running_plugin() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();

        // Enable the built-in logging plugin through the handler, using the
        // registered name the UI sends (from the plugin list).
        let resp = enable_plugin(
            axum::extract::State(state.clone()),
            Json(serde_json::json!({"name": "custom-logger", "enabled": true})),
        )
        .await
        .unwrap();
        assert!(
            resp.0.message.contains("enabled"),
            "unexpected enable message: {}",
            resp.0.message
        );

        // Save new settings — the running instance must be restarted with them.
        let resp = update_plugin_config(
            axum::extract::State(state.clone()),
            axum::extract::Path("custom-logger".to_string()),
            Json(serde_json::json!({"settings": {"max_entries": 5}})),
        )
        .await
        .unwrap();
        assert!(
            resp.0.message.contains("applied"),
            "expected applied message, got: {}",
            resp.0.message
        );

        let mgr = state.plugin_manager.read().await;
        let running = mgr.list_plugins().iter().any(|(info, s)| {
            info.name == "custom-logger" && *s == aifw_plugins::PluginState::Running
        });
        assert!(running, "plugin must still be running after config update");
        assert_eq!(
            state
                .plugin_running_count
                .load(std::sync::atomic::Ordering::Relaxed),
            mgr.running_count(),
            "shadow counter must stay in sync"
        );
    }

    #[tokio::test]
    async fn update_config_on_stopped_plugin_only_persists() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();

        let resp = update_plugin_config(
            axum::extract::State(state.clone()),
            axum::extract::Path("custom-logger".to_string()),
            Json(serde_json::json!({"settings": {"max_entries": 7}})),
        )
        .await
        .unwrap();
        assert!(
            !resp.0.message.contains("applied"),
            "stopped plugin must not report an applied restart: {}",
            resp.0.message
        );

        // Settings persisted and readable back.
        let cfg = get_plugin_config(
            axum::extract::State(state.clone()),
            axum::extract::Path("custom-logger".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(cfg.0["settings"]["max_entries"], 7);

        // Enabling afterwards must pick the saved settings up (init-time read).
        let resp = enable_plugin(
            axum::extract::State(state.clone()),
            Json(serde_json::json!({"name": "custom-logger", "enabled": true})),
        )
        .await
        .unwrap();
        assert!(
            resp.0.message.contains("enabled"),
            "unexpected enable message: {}",
            resp.0.message
        );
        let mgr = state.plugin_manager.read().await;
        assert!(mgr.list_plugins().iter().any(|(info, s)| {
            info.name == "custom-logger" && *s == aifw_plugins::PluginState::Running
        }));
    }

    #[tokio::test]
    async fn dispatch_hook_short_circuits_with_no_plugins() {
        let state = crate::create_app_state_in_memory(test_auth_settings())
            .await
            .unwrap();

        // Shadow counter is 0 — dispatch must return empty without touching
        // the manager lock.
        let actions = dispatch_hook(
            &state,
            aifw_plugins::HookEvent {
                hook: aifw_plugins::HookPoint::LogEvent,
                data: aifw_plugins::hooks::HookEventData::Log {
                    action: "x".to_string(),
                    details: "y".to_string(),
                    source: "z".to_string(),
                },
            },
        )
        .await;
        assert!(actions.is_empty());
    }
}
