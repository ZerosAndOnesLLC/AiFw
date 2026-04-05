use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::ids::{
    IdsAlert, IdsConfig, IdsMode, IdsRule, IdsRuleset, IdsStats,
    IdsSuppression, RuleFormat, SuppressType,
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

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

fn bad_request() -> StatusCode {
    StatusCode::BAD_REQUEST
}

// ============ Configuration ============

pub async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<IdsConfig>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let config = engine.load_config().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: config }))
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
) -> Result<Json<ApiResponse<IdsConfig>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let mut config = engine.load_config().await.map_err(|_| internal())?;

    if let Some(mode) = &req.mode {
        config.mode = match mode.as_str() {
            "ids" => IdsMode::Ids,
            "ips" => IdsMode::Ips,
            "disabled" => IdsMode::Disabled,
            _ => return Err(bad_request()),
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

    engine.save_config(&config).await.map_err(|_| internal())?;

    Ok(Json(ApiResponse { data: config }))
}

pub async fn reload(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
    let count = mgr
        .compile_rules(engine.rule_db())
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("{count} rules compiled and loaded"),
    }))
}

// ============ Alerts ============

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub severity: Option<u8>,
    pub src_ip: Option<String>,
    pub signature_id: Option<u32>,
    pub acknowledged: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_alerts(
    State(state): State<AppState>,
    Query(q): Query<AlertsQuery>,
) -> Result<Json<ApiResponse<Vec<IdsAlert>>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(engine.pool().clone());
    let alerts = output
        .query_alerts(
            q.severity,
            q.src_ip.as_deref(),
            q.signature_id,
            q.acknowledged,
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(engine.pool().clone());
    let alert = output
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(engine.pool().clone());
    output.acknowledge(uuid).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "alert acknowledged".into(),
    }))
}

pub async fn purge_alerts(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let config = engine.load_config().await.map_err(|_| internal())?;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(engine.pool().clone());
    let deleted = output
        .purge_old(config.alert_retention_days)
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("{deleted} alerts purged"),
    }))
}

// ============ Rulesets ============

pub async fn list_rulesets(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<IdsRuleset>>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
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

    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());

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

    // Recompile rules so the enabled/disabled change takes effect immediately
    let _ = mgr.compile_rules(engine.rule_db()).await;

    Ok(Json(ApiResponse { data: ruleset }))
}

pub async fn delete_ruleset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let row: Option<(String, String, Option<i64>, String, Option<String>, i64, bool, Option<String>, i64, Option<String>, String)> =
        sqlx::query_as(
            "SELECT id, ruleset_id, sid, rule_text, msg, severity, enabled, action_override, hit_count, last_hit, created_at FROM ids_rules WHERE id = ?"
        )
        .bind(&id)
        .fetch_optional(engine.pool())
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
        action_override: row.7.and_then(|s| aifw_common::ids::IdsAction::from_str(&s)),
        hit_count: row.8 as u64,
        last_hit: row.9.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
        created_at: chrono::DateTime::parse_from_rfc3339(&row.10).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());

    if let Some(enabled) = req.enabled {
        mgr.toggle_rule(uuid, enabled)
            .await
            .map_err(|_| internal())?;
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

pub async fn list_suppressions(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<IdsSuppression>>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let rows: Vec<(String, i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, sid, suppress_type, ip_cidr, created_at FROM ids_suppressions ORDER BY created_at DESC",
    )
    .fetch_all(engine.pool())
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
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
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
    .execute(engine.pool())
    .await
    .map_err(|_| internal())?;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            data: suppression,
        }),
    ))
}

pub async fn delete_suppression(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    sqlx::query("DELETE FROM ids_suppressions WHERE id = ?")
        .bind(&id)
        .execute(engine.pool())
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "suppression deleted".into(),
    }))
}

// ============ Stats ============

pub async fn get_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<IdsStatsResponse>>, StatusCode> {
    let engine = state.ids_engine.as_ref().ok_or(internal())?;
    let stats = engine.stats();
    let config = engine.load_config().await.map_err(|_| internal())?;
    let output = aifw_ids::output::sqlite::SqliteOutput::new(engine.pool().clone());

    let raw_counts = output.count_by_severity().await.unwrap_or_default();
    // Convert numeric severity to labeled counts for the UI
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

    let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
    let rulesets = mgr.list_rulesets().await.unwrap_or_default();
    let total_rulesets = rulesets.len() as u32;
    let enabled_rulesets = rulesets.iter().filter(|r| r.enabled).count() as u32;
    let loaded_rules = engine.rule_db().rule_count() as u32;
    let running = engine.is_running();

    Ok(Json(ApiResponse {
        data: IdsStatsResponse {
            stats,
            mode: config.mode.to_string(),
            severity_counts,
            top_signatures: top_sigs,
            top_sources,
            loaded_rules,
            enabled_rulesets,
            total_rulesets,
            running,
        },
    }))
}

#[derive(Debug, Serialize)]
pub struct IdsStatsResponse {
    pub stats: IdsStats,
    pub mode: String,
    pub severity_counts: Vec<(String, i64)>,
    pub top_signatures: Vec<(String, i64)>,
    pub top_sources: Vec<(String, i64)>,
    pub loaded_rules: u32,
    pub enabled_rulesets: u32,
    pub total_rulesets: u32,
    pub running: bool,
}

