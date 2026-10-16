//! `/api/v1/plugins/*` handlers. Thin: every rule (name lookup, settings
//! validation, lifecycle) lives in `aifw_plugins::PluginManager`; handlers
//! translate requests, map errors to status + message, and audit changes.

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AppState;
use crate::auth::AuthUser;
use aifw_plugins::{
    HookPoint, LogEntry, LogLevel, PluginDetail, PluginError, PluginSummary, SettingsPatch,
};

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

type ApiError = (StatusCode, Json<MessageResponse>);
type ApiResult<T> = Result<Json<T>, ApiError>;

/// Map a plugin error to a status code plus a message the UI can show.
fn api_error(e: PluginError) -> ApiError {
    let status = match &e {
        PluginError::NotFound(_) => StatusCode::NOT_FOUND,
        PluginError::Validation(_) => StatusCode::BAD_REQUEST,
        PluginError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        PluginError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        // Failures raised by the plugin itself (an action that couldn't
        // reach a webhook, a table write pf refused) are the operator's to
        // read, not a server bug.
        PluginError::Plugin(_) | PluginError::Table(_) | PluginError::Rule(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
    };
    let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::error!(error = %e, "plugins: request failed");
        "internal error; see the API log".to_string()
    } else {
        e.to_string()
    };
    (status, Json(MessageResponse { message }))
}

async fn audit(state: &AppState, user: &AuthUser, details: String) {
    if let Err(e) = aifw_core::audit::AuditLog::new(state.pool.clone())
        .log(
            aifw_core::audit::AuditAction::ConfigChanged,
            None,
            &format!("{details} (by {})", user.username),
            "plugins",
        )
        .await
    {
        tracing::warn!(error = %e, "plugins: audit log write failed");
    }
}

#[derive(Serialize)]
pub struct HookInfo {
    pub id: HookPoint,
    pub description: &'static str,
}

#[derive(Serialize)]
pub struct PluginsResponse {
    pub plugins: Vec<PluginSummary>,
    pub total: usize,
    pub running: usize,
    /// Every hook point AiFw fires, for the "available hooks" reference.
    pub hooks: Vec<HookInfo>,
}

pub async fn list_plugins(State(state): State<AppState>) -> Json<PluginsResponse> {
    let mgr = &state.plugin_manager;
    Json(PluginsResponse {
        plugins: mgr.list(),
        total: mgr.count(),
        running: mgr.running_count(),
        hooks: HookPoint::ALL
            .iter()
            .map(|h| HookInfo {
                id: *h,
                description: h.description(),
            })
            .collect(),
    })
}

pub async fn get_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<PluginDetail> {
    state
        .plugin_manager
        .detail(&name)
        .await
        .map(Json)
        .map_err(api_error)
}

#[derive(Deserialize)]
pub struct EnabledRequest {
    pub enabled: bool,
}

pub async fn set_enabled(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(name): Path<String>,
    Json(req): Json<EnabledRequest>,
) -> ApiResult<PluginSummary> {
    let summary = state
        .plugin_manager
        .set_enabled(&name, req.enabled)
        .await
        .map_err(api_error)?;
    let verb = if req.enabled { "enabled" } else { "disabled" };
    audit(&state, &user, format!("plugin '{name}' {verb}")).await;
    Ok(Json(summary))
}

pub async fn update_settings(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(name): Path<String>,
    Json(patch): Json<SettingsPatch>,
) -> ApiResult<PluginDetail> {
    // Audit the keys that changed, never the values (secrets).
    let mut keys: Vec<&str> = patch
        .values
        .keys()
        .chain(patch.secrets.keys())
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let details = format!("plugin '{name}' settings changed: {}", keys.join(", "));
    let detail = state
        .plugin_manager
        .update_settings(&name, patch)
        .await
        .map_err(api_error)?;
    audit(&state, &user, details).await;
    Ok(Json(detail))
}

pub async fn reset_plugin(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(name): Path<String>,
) -> ApiResult<PluginSummary> {
    let summary = state.plugin_manager.reset(&name).await.map_err(api_error)?;
    audit(&state, &user, format!("plugin '{name}' reset to defaults")).await;
    Ok(Json(summary))
}

pub async fn get_status(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Value> {
    state
        .plugin_manager
        .status(&name)
        .await
        .map(Json)
        .map_err(api_error)
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<usize>,
    pub level: Option<LogLevel>,
}

#[derive(Serialize)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
}

pub async fn get_logs(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> ApiResult<LogsResponse> {
    let limit = q.limit.unwrap_or(200).clamp(1, 500);
    state
        .plugin_manager
        .logs(&name, limit, q.level.unwrap_or(LogLevel::Info))
        .map(|entries| Json(LogsResponse { entries }))
        .map_err(api_error)
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub result: Value,
}

pub async fn run_action(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path((name, action)): Path<(String, String)>,
    body: Option<Json<Value>>,
) -> ApiResult<ActionResponse> {
    let args = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let result = state
        .plugin_manager
        .run_action(&name, &action, args)
        .await
        .map_err(api_error)?;
    audit(
        &state,
        &user,
        format!("plugin '{name}' action '{action}' run"),
    )
    .await;
    Ok(Json(ActionResponse { result }))
}
