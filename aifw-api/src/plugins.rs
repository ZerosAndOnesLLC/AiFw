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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

/// Dispatch a hook event to all plugins (called internally by other modules)
#[allow(dead_code)]
pub async fn dispatch_hook(
    state: &AppState,
    event: aifw_plugins::HookEvent,
) -> Vec<aifw_plugins::HookAction> {
    let mgr = state.plugin_manager.read().await;
    mgr.dispatch(&event).await
}
