//! `/api/v1/rules` handlers — firewall rules CRUD + reorder + block
//! logging toggle, plus the read-only `list_system_rules` that walks
//! `pfctl -sr` for the live kernel ruleset. Extracted from the legacy
//! 4000-line `routes.rs` God module (#187).

use super::*;

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub interface: Option<String>,
    /// "inet" | "inet6" | "both" (legacy UI alias "inet46" accepted).
    /// Absent = keep existing on update, default Both on create (#472).
    pub ip_version: Option<String>,
    pub priority: Option<i32>,
    pub log: Option<bool>,
    pub quick: Option<bool>,
    pub label: Option<String>,
    pub state_tracking: Option<String>,
    pub status: Option<String>,
    pub schedule_id: Option<String>,
    /// Multi-WAN gateway id for policy routing (#540). Empty string clears.
    pub gateway: Option<String>,
}

/// Resolve the request's `gateway` field to a validated gateway id (#540):
/// `None`/empty clears the association; anything else must parse as a UUID
/// and reference an existing multiwan gateway or the request is rejected —
/// unknown values must not be silently discarded again.
async fn validate_gateway_ref(
    state: &AppState,
    gateway: Option<String>,
) -> Result<Option<String>, StatusCode> {
    let Some(gw) = gateway
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
    else {
        return Ok(None);
    };
    let uuid = Uuid::parse_str(&gw).map_err(|_| bad_request())?;
    state
        .gateway_engine
        .get(uuid)
        .await
        .map_err(|_| bad_request())?;
    Ok(Some(uuid.to_string()))
}

#[derive(Debug, Deserialize)]
pub struct ReorderRequest {
    pub rule_ids: Vec<String>,
}

pub async fn list_system_rules() -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let mut all_rules = Vec::new();

    // Main ruleset
    if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["pfctl", "-sr"])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        all_rules.extend(stdout.lines().filter(|l| !l.is_empty()).map(String::from));
    }

    // AiFw anchor rules
    for anchor in [
        aifw_common::anchors::FILTER,
        aifw_common::anchors::NAT,
        aifw_common::anchors::VPN,
        aifw_common::anchors::GEOIP,
    ] {
        if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
            .args(["pfctl", "-a", anchor, "-sr"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let anchor_rules: Vec<String> = stdout
                .lines()
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            if !anchor_rules.is_empty() {
                all_rules.push(format!("# --- anchor \"{}\" ---", anchor));
                all_rules.extend(anchor_rules);
            }
        }
    }

    Ok(Json(ApiResponse { data: all_rules }))
}

pub async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Rule>>>, StatusCode> {
    let rules = state.rule_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Rule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let rule = state
        .rule_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Rule>>), StatusCode> {
    let action = match req.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        "block_drop" | "block-drop" => Action::BlockDrop,
        "block_return" | "block-return" => Action::BlockReturn,
        _ => return Err(bad_request()),
    };

    let direction = match req.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return Err(bad_request()),
    };

    let protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;

    let src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let rule_match = RuleMatch {
        src_addr,
        src_port: port_range(req.src_port_start, req.src_port_end),
        dst_addr,
        dst_port: port_range(req.dst_port_start, req.dst_port_end),
    };

    let mut rule = Rule::new(action, direction, protocol, rule_match);
    if let Some(ref v) = req.ip_version {
        rule.ip_version = aifw_common::IpVersion::parse(v).map_err(|_| bad_request())?;
    }
    if let Some(p) = req.priority {
        rule.priority = p;
    }
    if let Some(l) = req.log {
        rule.log = l;
    }
    if let Some(q) = req.quick {
        rule.quick = q;
    }
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);

    if let Some(ref st) = req.state_tracking {
        rule.state_options.tracking = match st.as_str() {
            "none" => StateTracking::None,
            "keep_state" => StateTracking::KeepState,
            "modulate_state" => StateTracking::ModulateState,
            "synproxy_state" => StateTracking::SynproxyState,
            _ => return Err(bad_request()),
        };
    }

    rule.schedule_id = req.schedule_id;
    rule.gateway = validate_gateway_ref(&state, req.gateway).await?;

    // Validate label and interface to prevent pf rule injection
    if let Some(ref iface) = rule.interface {
        aifw_core::validation::validate_interface_name(&iface.0).map_err(|_| bad_request())?;
    }
    if let Some(ref label) = rule.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    let rule = state
        .rule_engine
        .add(rule)
        .await
        .map_err(|_| bad_request())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<ApiResponse<Rule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state
        .rule_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    rule.action = match req.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        "block_drop" | "block-drop" => Action::BlockDrop,
        "block_return" | "block-return" => Action::BlockReturn,
        _ => return Err(bad_request()),
    };
    rule.direction = match req.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return Err(bad_request()),
    };
    rule.protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;
    if let Some(ref v) = req.ip_version {
        rule.ip_version = aifw_common::IpVersion::parse(v).map_err(|_| bad_request())?;
    }
    rule.rule_match.src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.rule_match.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.rule_match.dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.rule_match.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    if let Some(p) = req.priority {
        rule.priority = p;
    }
    if let Some(l) = req.log {
        rule.log = l;
    }
    if let Some(q) = req.quick {
        rule.quick = q;
    }
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);
    if let Some(ref st) = req.state_tracking {
        rule.state_options.tracking = match st.as_str() {
            "none" => StateTracking::None,
            "keep_state" => StateTracking::KeepState,
            "modulate_state" => StateTracking::ModulateState,
            "synproxy_state" => StateTracking::SynproxyState,
            _ => return Err(bad_request()),
        };
    }
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => RuleStatus::Active,
            "disabled" => RuleStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    rule.schedule_id = req.schedule_id;
    rule.gateway = validate_gateway_ref(&state, req.gateway).await?;
    rule.updated_at = chrono::Utc::now();

    // Validate label and interface to prevent pf rule injection
    if let Some(ref iface) = rule.interface {
        aifw_core::validation::validate_interface_name(&iface.0).map_err(|_| bad_request())?;
    }
    if let Some(ref label) = rule.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    state
        .rule_engine
        .update(rule.clone())
        .await
        .map_err(|_| internal())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .rule_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(MessageResponse {
        message: format!("Rule {id} deleted"),
    }))
}

pub async fn toggle_block_logging(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let enabled = payload
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let now = chrono::Utc::now().to_rfc3339();

    // Update all block rules' log flag
    sqlx::query("UPDATE rules SET log = ?1, updated_at = ?2 WHERE action IN ('block', 'blockdrop', 'block_return', 'blockreturn')")
        .bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| internal())?;

    // Reload pf rules
    let rules = state.rule_engine.list().await.map_err(|_| internal())?;
    let pf_rules: Vec<String> = rules.iter().map(|r| r.to_pf_rule("aifw")).collect();
    let _ = state.pf.load_rules("aifw", &pf_rules).await;

    let msg = if enabled {
        "Block logging enabled"
    } else {
        "Block logging disabled"
    };
    Ok(Json(MessageResponse {
        message: msg.to_string(),
    }))
}

pub async fn reorder_rules(
    State(state): State<AppState>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    for (i, id_str) in req.rule_ids.iter().enumerate() {
        let uuid = Uuid::parse_str(id_str).map_err(|_| bad_request())?;
        let mut rule = state
            .rule_engine
            .get(uuid)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        rule.priority = i as i32;
        rule.updated_at = chrono::Utc::now();
        state
            .rule_engine
            .update(rule)
            .await
            .map_err(|_| internal())?;
    }
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(MessageResponse {
        message: format!("{} rules reordered", req.rule_ids.len()),
    }))
}
