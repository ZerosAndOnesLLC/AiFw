use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::ids::{
    IdsAlert, IdsConfig, IdsMode, IdsRule, IdsRuleset, IdsSuppression, RuleFormat, SuppressType,
};

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

fn bad_request() -> StatusCode {
    StatusCode::BAD_REQUEST
}

/// Map an `IdsClientError` to an HTTP response body. `Unavailable` and
/// `Timeout` become 503 — aifw-ids is the source of truth for live IDS
/// state and we don't want to lie when it's offline. Server-side errors
/// (rule parse, config validation) come back as 400. Anything else is 500.
fn ipc_to_response<T: serde::Serialize>(
    r: Result<T, aifw_ids_ipc::IdsClientError>,
) -> Result<axum::Json<T>, (axum::http::StatusCode, String)> {
    match r {
        Ok(v) => Ok(axum::Json(v)),
        Err(aifw_ids_ipc::IdsClientError::Unavailable(_))
        | Err(aifw_ids_ipc::IdsClientError::Timeout) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "ids service unavailable".to_string(),
        )),
        Err(aifw_ids_ipc::IdsClientError::Server(e)) => {
            Err((axum::http::StatusCode::BAD_REQUEST, e))
        }
        Err(e) => Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
        )),
    }
}

// ============ Configuration ============

pub async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<IdsConfig>>, (StatusCode, String)> {
    let config = ipc_to_response(state.ids_client.get_config().await)?;
    Ok(Json(ApiResponse { data: config.0 }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    pub mode: Option<String>,
    pub home_net: Option<Vec<String>>,
    pub external_net: Option<Vec<String>>,
    pub interfaces: Option<Vec<String>>,
    pub alert_retention_days: Option<u32>,
    pub eve_log_enabled: Option<bool>,
    pub eve_log_path: Option<String>,
    pub syslog_target: Option<String>,
    pub worker_count: Option<u32>,
    pub flow_table_size: Option<u32>,
    pub stream_depth: Option<u32>,
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<ApiResponse<IdsConfig>>, (StatusCode, String)> {
    // Pull the current config over IPC, merge fields, push it back.
    let mut config = ipc_to_response(state.ids_client.get_config().await)?.0;

    if let Some(mode) = &req.mode {
        config.mode = match mode.as_str() {
            "ids" => IdsMode::Ids,
            "ips" => IdsMode::Ips,
            "disabled" => IdsMode::Disabled,
            _ => return Err((bad_request(), "invalid mode".into())),
        };
    }
    if let Some(home_net) = req.home_net {
        config.home_net = home_net;
    }
    if let Some(external_net) = req.external_net {
        config.external_net = external_net;
    }
    if let Some(interfaces) = req.interfaces {
        config.interfaces = interfaces;
    }
    if let Some(days) = req.alert_retention_days {
        config.alert_retention_days = days;
    }
    if let Some(enabled) = req.eve_log_enabled {
        config.eve_log_enabled = enabled;
    }
    if let Some(path) = req.eve_log_path {
        config.eve_log_path = Some(path);
    }
    if let Some(target) = req.syslog_target {
        config.syslog_target = Some(target);
    }
    config.worker_count = req.worker_count.or(config.worker_count);
    config.flow_table_size = req.flow_table_size.or(config.flow_table_size);
    config.stream_depth = req.stream_depth.or(config.stream_depth);

    let _ = ipc_to_response(state.ids_client.set_config(config.clone()).await)?;

    Ok(Json(ApiResponse { data: config }))
}

pub async fn reload(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    let _ = ipc_to_response(state.ids_client.reload().await)?;
    Ok(Json(MessageResponse {
        message: "rules reloaded".into(),
    }))
}

// ============ Alerts ============
//
// Alert reads/writes are direct against the `ids_alerts` SQLite table.
// aifw-ids is the writer; aifw-api is read-only here. The IPC layer
// provides only `tail_alerts` for the in-memory ring; pagination, filtering,
// and acknowledge-by-id stay SQL since the table is the durable record.

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub severity: Option<u8>,
    pub src_ip: Option<String>,
    pub signature_id: Option<u32>,
    pub acknowledged: Option<bool>,
    pub classification: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<ApiResponse<Vec<IdsAlert>>>, StatusCode> {
    let out = aifw_ids::output::sqlite::SqliteOutput::new(state.pool.clone());
    let alerts = out
        .query_alerts(
            q.severity,
            q.src_ip.as_deref(),
            q.signature_id,
            q.acknowledged,
            q.classification.as_deref(),
            q.limit.unwrap_or(50),
            q.offset.unwrap_or(0),
        )
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: alerts }))
}

pub async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<IdsAlert>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let out = aifw_ids::output::sqlite::SqliteOutput::new(state.pool.clone());
    let alert = out
        .get_alert(uuid)
        .await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: alert }))
}

pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let out = aifw_ids::output::sqlite::SqliteOutput::new(state.pool.clone());
    out.acknowledge(uuid).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "alert acknowledged".into(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ClassifyAlertRequest {
    pub classification: String,
    pub notes: Option<String>,
}

pub async fn classify_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ClassifyAlertRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let valid = ["unreviewed", "confirmed", "false_positive", "investigating"];
    if !valid.contains(&req.classification.as_str()) {
        return Err(bad_request());
    }
    let out = aifw_ids::output::sqlite::SqliteOutput::new(state.pool.clone());
    out.classify(uuid, &req.classification, req.notes.as_deref())
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("alert classified as {}", req.classification),
    }))
}

pub async fn purge_alerts(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Drops every row from ids_alerts. The retention sweep in aifw-ids handles
    // the routine case; this is an operator escape hatch for bulk cleanup.
    let res = sqlx::query("DELETE FROM ids_alerts")
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("{} alerts purged", res.rows_affected()),
    }))
}

pub async fn alert_buffer_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Surfaces the in-memory ring-buffer stats from aifw-ids via IPC.
    // Pre-cutover this was an in-process AlertBuffer; the field shape is
    // best-effort compatible (count + alerts_total at minimum).
    let stats = ipc_to_response(state.ids_client.get_stats().await)?.0;
    Ok(Json(serde_json::json!({
        "alerts_total": stats.alerts_total,
        "running": stats.running,
        "uptime_secs": stats.uptime_secs,
    })))
}

// ============ Rulesets ============
//
// Rulesets/rules tables live in SQLite. aifw-ids is the only writer that
// touches the in-memory rule DB, so toggling enable/format/etc. requires
// an IPC reload to take effect — but the table edits themselves are plain
// CRUD on `state.pool`.

pub async fn list_rulesets(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<IdsRuleset>>>, StatusCode> {
    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());
    let rulesets = mgr.list_rulesets().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rulesets }))
}

#[derive(Debug, Deserialize)]
pub struct CreateRulesetRequest {
    pub name: String,
    pub source_url: Option<String>,
    pub rule_format: String,
    pub enabled: Option<bool>,
    pub auto_update: Option<bool>,
    pub update_interval_hours: Option<u32>,
}

pub async fn create_ruleset(
    State(state): State<AppState>,
    Json(req): Json<CreateRulesetRequest>,
) -> Result<(StatusCode, Json<ApiResponse<IdsRuleset>>), StatusCode> {
    let format = RuleFormat::from_str(&req.rule_format).ok_or(bad_request())?;

    let ruleset = IdsRuleset {
        id: Uuid::new_v4(),
        name: req.name,
        source_url: req.source_url,
        rule_format: format,
        enabled: req.enabled.unwrap_or(true),
        auto_update: req.auto_update.unwrap_or(true),
        update_interval_hours: req.update_interval_hours.unwrap_or(24),
        last_updated: None,
        rule_count: 0,
        created_at: Utc::now(),
    };

    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());
    mgr.add_ruleset(&ruleset).await.map_err(|_| internal())?;

    Ok((StatusCode::CREATED, Json(ApiResponse { data: ruleset })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRulesetRequest {
    pub name: Option<String>,
    pub source_url: Option<String>,
    pub rule_format: Option<String>,
    pub enabled: Option<bool>,
    pub auto_update: Option<bool>,
    pub update_interval_hours: Option<u32>,
}

pub async fn update_ruleset(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRulesetRequest>,
) -> Result<Json<ApiResponse<IdsRuleset>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());

    // Load existing ruleset
    let existing = mgr.list_rulesets().await.map_err(|_| internal())?;
    let mut ruleset = existing
        .into_iter()
        .find(|r| r.id == uuid)
        .ok_or(StatusCode::NOT_FOUND)?;

    if let Some(name) = req.name {
        ruleset.name = name;
    }
    if let Some(url) = req.source_url {
        ruleset.source_url = Some(url);
    }
    if let Some(fmt) = &req.rule_format {
        ruleset.rule_format = RuleFormat::from_str(fmt).ok_or(bad_request())?;
    }
    if let Some(enabled) = req.enabled {
        ruleset.enabled = enabled;
    }
    if let Some(auto_update) = req.auto_update {
        ruleset.auto_update = auto_update;
    }
    if let Some(interval) = req.update_interval_hours {
        ruleset.update_interval_hours = interval;
    }

    mgr.update_ruleset(&ruleset).await.map_err(|_| internal())?;

    // If enabling a ruleset with no rules and a source URL, download them first
    if ruleset.enabled && ruleset.rule_count == 0 && ruleset.source_url.is_some() {
        match mgr.download_and_store_rules(&ruleset).await {
            Ok(count) => {
                tracing::info!(count, ruleset = %ruleset.name, "rules downloaded and stored");
                // Reload the ruleset to get updated rule_count
                if let Ok(rulesets) = mgr.list_rulesets().await
                    && let Some(updated) = rulesets.into_iter().find(|r| r.id == uuid)
                {
                    ruleset = updated;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, ruleset = %ruleset.name, "failed to download rules");
            }
        }
    }

    // Ask aifw-ids to recompile so the enable/disable change takes effect.
    // Best-effort — if aifw-ids is offline the DB still reflects the change
    // and a later reload will pick it up.
    if let Err(e) = state.ids_client.reload().await {
        tracing::warn!(error = %e, "ids reload failed after ruleset update");
    }

    Ok(Json(ApiResponse { data: ruleset }))
}

pub async fn delete_ruleset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());
    mgr.delete_ruleset(uuid).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "ruleset deleted".into(),
    }))
}

// ============ Rules ============

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RulesQuery {
    pub ruleset_id: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub q: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_rules(
    State(state): State<AppState>,
    Query(q): Query<RulesQuery>,
) -> Result<Json<ApiResponse<Vec<IdsRule>>>, StatusCode> {
    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());
    let ruleset_id = q
        .ruleset_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok());
    let rules = mgr
        .list_rules(
            ruleset_id,
            q.enabled.unwrap_or(false),
            q.limit.unwrap_or(50),
            q.offset.unwrap_or(0),
        )
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<IdsRule>>, StatusCode> {
    let row: Option<(String, String, Option<i64>, String, Option<String>, i64, bool, Option<String>, i64, Option<String>, String)> =
        sqlx::query_as(
            "SELECT id, ruleset_id, sid, rule_text, msg, severity, enabled, action_override, hit_count, last_hit, created_at FROM ids_rules WHERE id = ?"
        )
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| internal())?;

    let row = row.ok_or(StatusCode::NOT_FOUND)?;
    let rule = IdsRule {
        id: Uuid::parse_str(&row.0).map_err(|_| internal())?,
        ruleset_id: Uuid::parse_str(&row.1).map_err(|_| internal())?,
        sid: row.2.map(|s| s as u32),
        rule_text: row.3,
        msg: row.4,
        severity: aifw_common::ids::IdsSeverity(row.5 as u8),
        enabled: row.6,
        action_override: row
            .7
            .and_then(|s| aifw_common::ids::IdsAction::from_str(&s)),
        hit_count: row.8 as u64,
        last_hit: row.9.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }),
        created_at: chrono::DateTime::parse_from_rfc3339(&row.10)
            .ok()
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now),
    };
    Ok(Json(ApiResponse { data: rule }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleRequest {
    pub enabled: Option<bool>,
    pub action_override: Option<String>,
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());

    if let Some(enabled) = req.enabled {
        mgr.toggle_rule(uuid, enabled)
            .await
            .map_err(|_| internal())?;
        // Best-effort propagate to the running engine via IPC.
        let _ = state.ids_client.set_rule(&id, enabled).await;
    }
    if let Some(ref action) = req.action_override {
        let action_str = if action.is_empty() {
            None
        } else {
            Some(action.as_str())
        };
        mgr.override_rule_action(uuid, action_str)
            .await
            .map_err(|_| internal())?;
    }

    Ok(Json(MessageResponse {
        message: "rule updated".into(),
    }))
}

pub async fn search_rules(
    State(state): State<AppState>,
    Query(q): Query<RulesQuery>,
) -> Result<Json<ApiResponse<Vec<IdsRule>>>, StatusCode> {
    // For now, search is the same as list with filtering
    list_rules(State(state), Query(q)).await
}

// ============ Suppressions ============
//
// Pure SQLite CRUD — direct queries against `ids_suppressions`.

pub async fn list_suppressions(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<ApiResponse<Vec<IdsSuppression>>>, StatusCode> {
    // Bound the response so busy deployments (10k+ suppressions) don't
    // load the whole table into memory + JSON on every list call.
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows: Vec<(String, i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, sid, suppress_type, ip_cidr, created_at FROM ids_suppressions \
         ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let suppressions: Vec<IdsSuppression> = rows
        .into_iter()
        .filter_map(|(id, sid, stype, cidr, created)| {
            Some(IdsSuppression {
                id: Uuid::parse_str(&id).ok()?,
                sid: sid as u32,
                suppress_type: SuppressType::from_str(&stype)?,
                ip_cidr: cidr,
                created_at: chrono::DateTime::parse_from_rfc3339(&created)
                    .ok()?
                    .with_timezone(&Utc),
            })
        })
        .collect();

    Ok(Json(ApiResponse { data: suppressions }))
}

#[derive(Debug, Deserialize)]
pub struct CreateSuppressionRequest {
    pub sid: u32,
    pub suppress_type: String,
    pub ip_cidr: Option<String>,
}

pub async fn create_suppression(
    State(state): State<AppState>,
    Json(req): Json<CreateSuppressionRequest>,
) -> Result<(StatusCode, Json<ApiResponse<IdsSuppression>>), StatusCode> {
    let suppress_type = SuppressType::from_str(&req.suppress_type).ok_or(bad_request())?;

    let suppression = IdsSuppression {
        id: Uuid::new_v4(),
        sid: req.sid,
        suppress_type,
        ip_cidr: req.ip_cidr,
        created_at: Utc::now(),
    };

    sqlx::query(
        "INSERT INTO ids_suppressions (id, sid, suppress_type, ip_cidr) VALUES (?, ?, ?, ?)",
    )
    .bind(suppression.id.to_string())
    .bind(suppression.sid as i64)
    .bind(suppression.suppress_type.to_string())
    .bind(&suppression.ip_cidr)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok((StatusCode::CREATED, Json(ApiResponse { data: suppression })))
}

pub async fn delete_suppression(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    sqlx::query("DELETE FROM ids_suppressions WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "suppression deleted".into(),
    }))
}

// ============ Stats ============

pub async fn get_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<IdsStatsResponse>>, (StatusCode, String)> {
    // Live counters (rules_loaded, packets_inspected, alerts_total, etc.)
    // come over IPC from aifw-ids. Aggregate breakdowns (by-severity,
    // top-signatures, top-sources) are SQL queries on `ids_alerts` and stay
    // direct-DB. Rulesets: also direct-DB.
    let stats = ipc_to_response(state.ids_client.get_stats().await)?.0;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(state.pool.clone());

    let raw_counts = output.count_by_severity().await.unwrap_or_default();
    let severity_counts: Vec<(String, i64)> = raw_counts
        .into_iter()
        .map(|(sev, count)| {
            let label = match sev {
                1 => "critical",
                2 => "high",
                3 => "medium",
                _ => "info",
            };
            (label.to_string(), count)
        })
        .collect();

    let top_sigs = output.top_signatures(10).await.unwrap_or_default();
    let top_sources = output.top_sources(10).await.unwrap_or_default();

    let mgr = aifw_ids::rules::manager::RulesetManager::new(state.pool.clone());
    let rulesets = mgr.list_rulesets().await.unwrap_or_default();
    let total_rulesets = rulesets.len() as u32;
    let enabled_rulesets = rulesets.iter().filter(|r| r.enabled).count() as u32;

    Ok(Json(ApiResponse {
        data: IdsStatsResponse {
            mode: stats.mode.clone(),
            severity_counts,
            top_signatures: top_sigs,
            top_sources,
            loaded_rules: stats.rules_loaded,
            enabled_rulesets,
            total_rulesets,
            running: stats.running,
            packets_inspected: stats.packets_inspected,
            alerts_total: stats.alerts_total,
            flow_count: stats.flow_count,
            flow_reassembly_bytes: stats.flow_reassembly_bytes,
            uptime_secs: stats.uptime_secs,
        },
    }))
}

#[derive(Debug, Serialize)]
pub struct IdsStatsResponse {
    pub mode: String,
    pub severity_counts: Vec<(String, i64)>,
    pub top_signatures: Vec<(String, i64)>,
    pub top_sources: Vec<(String, i64)>,
    pub loaded_rules: u32,
    pub enabled_rulesets: u32,
    pub total_rulesets: u32,
    pub running: bool,
    pub packets_inspected: u64,
    pub alerts_total: u64,
    pub flow_count: u64,
    pub flow_reassembly_bytes: u64,
    pub uptime_secs: u64,
}
