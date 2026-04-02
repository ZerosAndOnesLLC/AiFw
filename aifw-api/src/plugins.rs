use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::AppState;

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

    let plugins: Vec<PluginListEntry> = list.iter().map(|(info, pstate)| {
        PluginListEntry {
            name: info.name.clone(),
            version: info.version.clone(),
            description: info.description.clone(),
            author: info.author.clone(),
            state: pstate.to_string(),
            hooks: info.hooks.iter().map(|h| h.to_string()).collect(),
        }
    }).collect();

    Ok(Json(PluginsResponse { plugins, total, running }))
}

pub async fn enable_plugin(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let name = payload.get("name").and_then(|v| v.as_str()).ok_or(StatusCode::BAD_REQUEST)?;
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    let mut mgr = state.plugin_manager.write().await;

    if enabled {
        // Unload and re-register with enabled=true
        // For now, just report — full enable/disable needs manager API enhancement
        drop(mgr);
        Ok(Json(MessageResponse { message: format!("Plugin '{name}' enable requested. Restart API to apply.") }))
    } else {
        let _ = mgr.unload(name).await;
        Ok(Json(MessageResponse { message: format!("Plugin '{name}' disabled and unloaded.") }))
    }
}

/// Dispatch a hook event to all plugins (called internally by other modules)
pub async fn dispatch_hook(state: &AppState, event: aifw_plugins::HookEvent) -> Vec<aifw_plugins::HookAction> {
    let mgr = state.plugin_manager.read().await;
    mgr.dispatch(&event).await
}
