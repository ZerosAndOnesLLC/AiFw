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

    if !enabled {
        let _ = mgr.unload(name).await;
        // Sync the atomic shadow counter (PERF-C12).
        state
            .plugin_running_count
            .store(mgr.running_count(), std::sync::atomic::Ordering::Relaxed);
        Ok(Json(MessageResponse {
            message: format!("Plugin '{name}' disabled."),
        }))
    } else {
        // Re-register with enabled=true — need to create a new instance
        let plugin: Option<Box<dyn aifw_plugins::Plugin>> = match name {
            "logging" => Some(Box::new(aifw_plugins::examples::LoggingPlugin::new())),
            "ip_reputation" => Some(Box::new(aifw_plugins::examples::IpReputationPlugin::new())),
            "webhook" => Some(Box::new(aifw_plugins::examples::WebhookPlugin::new())),
            _ => None,
        };
        if let Some(p) = plugin {
            // Unload old instance if exists
            let _ = mgr.unload(name).await;
            let _ = mgr
                .register(
                    p,
                    aifw_plugins::PluginConfig {
                        enabled: true,
                        ..Default::default()
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

    let _ = sqlx::query(
        "INSERT INTO plugin_config (name, enabled, settings) VALUES (?1, 0, ?2) ON CONFLICT(name) DO UPDATE SET settings=excluded.settings"
    ).bind(&name).bind(&settings_str).execute(&state.pool).await;

    Ok(Json(MessageResponse {
        message: format!("Plugin '{name}' config updated."),
    }))
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
