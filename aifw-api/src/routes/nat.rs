//! `/api/v1/nat` handlers — NAT rules CRUD + reorder + a pf-output
//! debug endpoint. Extracted from the legacy 4000-line `routes.rs`
//! God module (#187).

use super::*;
use super::rules::ReorderRequest;

#[derive(Debug, Deserialize)]
pub struct CreateNatRuleRequest {
    pub nat_type: String,
    pub interface: String,
    pub protocol: String,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub redirect_addr: String,
    pub redirect_port_start: Option<u16>,
    pub redirect_port_end: Option<u16>,
    pub label: Option<String>,
    pub status: Option<String>,
}

pub async fn list_nat_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<NatRule>>>, StatusCode> {
    let rules = state
        .nat_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn create_nat_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<NatRule>>), StatusCode> {
    let nat_type = NatType::parse(&req.nat_type).map_err(|_| bad_request())?;
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

    let redirect_addr = Address::parse(&req.redirect_addr).map_err(|_| bad_request())?;

    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface).map_err(|_| bad_request())?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    let mut rule = NatRule::new(
        nat_type,
        Interface(req.interface),
        protocol,
        src_addr,
        dst_addr,
        NatRedirect {
            address: redirect_addr,
            port: port_range(req.redirect_port_start, req.redirect_port_end),
        },
    );
    rule.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    rule.label = req.label;

    let rule = state
        .nat_engine
        .add_rule(rule)
        .await
        .map_err(|_| bad_request())?;
    state.set_pending(|p| p.nat = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<Json<ApiResponse<NatRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state
        .nat_engine
        .get_rule(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    rule.nat_type = NatType::parse(&req.nat_type).map_err(|_| bad_request())?;
    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface).map_err(|_| bad_request())?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    rule.interface = Interface(req.interface);
    rule.protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;
    rule.src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    rule.redirect = NatRedirect {
        address: Address::parse(&req.redirect_addr).map_err(|_| bad_request())?,
        port: port_range(req.redirect_port_start, req.redirect_port_end),
    };
    rule.label = req.label;
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => NatStatus::Active,
            "disabled" => NatStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    rule.updated_at = chrono::Utc::now();

    state
        .nat_engine
        .update_rule(&rule)
        .await
        .map_err(|_| internal())?;
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .nat_engine
        .delete_rule(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(MessageResponse {
        message: format!("NAT rule {id} deleted"),
    }))
}

pub async fn get_nat_pf_output(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let nat_rules = state.pf.get_nat_rules("aifw").await.unwrap_or_default();
    let filter_rules = state.pf.get_rules("aifw").await.unwrap_or_default();
    let mut output = Vec::new();
    if !nat_rules.is_empty() {
        output.push("# NAT Rules (anchor: aifw)".to_string());
        output.extend(nat_rules);
    }
    if !filter_rules.is_empty() {
        output.push("".to_string());
        output.push("# Filter Rules (anchor: aifw)".to_string());
        output.extend(filter_rules);
    }
    Ok(Json(ApiResponse { data: output }))
}

pub async fn reorder_nat_rules(
    State(state): State<AppState>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Update order by setting created_at timestamps in sequence
    for (i, id_str) in req.rule_ids.iter().enumerate() {
        let uuid = Uuid::parse_str(id_str).map_err(|_| bad_request())?;
        let _ = sqlx::query("UPDATE nat_rules SET created_at = datetime('2000-01-01', '+' || ?2 || ' seconds') WHERE id = ?1")
            .bind(uuid.to_string())
            .bind(i as i64)
            .execute(&state.pool)
            .await;
    }
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(MessageResponse {
        message: format!("{} NAT rules reordered", req.rule_ids.len()),
    }))
}
