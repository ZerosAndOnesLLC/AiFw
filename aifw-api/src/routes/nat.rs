//! `/api/v1/nat` handlers — NAT rules CRUD + reorder + a pf-output
//! debug endpoint. Extracted from the legacy 4000-line `routes.rs`
//! God module (#187).

use super::rules::ReorderRequest;
use super::*;

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
    /// Translation target. Optional: masquerade / nonat have none
    /// (defaults to `any`).
    pub redirect_addr: Option<String>,
    pub redirect_port_start: Option<u16>,
    pub redirect_port_end: Option<u16>,
    pub label: Option<String>,
    pub status: Option<String>,
    /// pf `static-port` — keep the original source port (SNAT/masquerade
    /// only; #253). Defaults false.
    #[serde(default)]
    pub static_port: bool,
    /// Explicit translated destination for nat46/nat64 (`af-to … to
    /// <dst>`, #596). Empty/omitted keeps RFC 6052 embedding.
    #[serde(default)]
    pub af_to_dst: Option<String>,
}

pub async fn list_nat_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<NatRule>>>, StatusCode> {
    let rules = state.nat_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

/// Error payload for NAT create/update: status + human-readable message so
/// engine/pf validation feedback (e.g. af-to family errors) reaches the UI
/// instead of a bare status code (#531).
type NatError = (StatusCode, Json<MessageResponse>);

fn nat_bad_request(msg: impl Into<String>) -> NatError {
    (
        StatusCode::BAD_REQUEST,
        Json(MessageResponse {
            message: msg.into(),
        }),
    )
}

fn nat_engine_error(e: aifw_common::AifwError) -> NatError {
    use aifw_common::AifwError;
    let code = match &e {
        AifwError::Validation(_) => StatusCode::BAD_REQUEST,
        AifwError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        code,
        Json(MessageResponse {
            message: e.to_string(),
        }),
    )
}

pub async fn create_nat_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<NatRule>>), NatError> {
    let nat_type = NatType::parse(&req.nat_type)
        .map_err(|_| nat_bad_request(format!("unknown NAT type '{}'", req.nat_type)))?;
    let protocol = Protocol::parse(&req.protocol)
        .map_err(|_| nat_bad_request(format!("unknown protocol '{}'", req.protocol)))?;

    let src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|e| nat_bad_request(format!("invalid source address: {e}")))?
        .unwrap_or(Address::Any);

    let dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|e| nat_bad_request(format!("invalid destination address: {e}")))?
        .unwrap_or(Address::Any);

    let redirect_addr = Address::parse(req.redirect_addr.as_deref().unwrap_or("any"))
        .map_err(|e| nat_bad_request(format!("invalid redirect address: {e}")))?;

    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface)
        .map_err(|e| nat_bad_request(e.to_string()))?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|e| nat_bad_request(e.to_string()))?;
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
    rule.static_port = req.static_port;
    rule.af_to_dst = match req.af_to_dst.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => Some(
            Address::parse(a)
                .map_err(|e| nat_bad_request(format!("invalid translated destination: {e}")))?,
        ),
        _ => None,
    };

    let rule = state.nat_engine.add(rule).await.map_err(nat_engine_error)?;
    state.set_pending(|p| p.nat = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<Json<ApiResponse<NatRule>>, NatError> {
    let uuid = Uuid::parse_str(&id).map_err(|_| nat_bad_request("invalid rule id"))?;
    let mut rule = state.nat_engine.get(uuid).await.map_err(nat_engine_error)?;

    rule.nat_type = NatType::parse(&req.nat_type)
        .map_err(|_| nat_bad_request(format!("unknown NAT type '{}'", req.nat_type)))?;
    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface)
        .map_err(|e| nat_bad_request(e.to_string()))?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|e| nat_bad_request(e.to_string()))?;
    }

    rule.interface = Interface(req.interface);
    rule.protocol = Protocol::parse(&req.protocol)
        .map_err(|_| nat_bad_request(format!("unknown protocol '{}'", req.protocol)))?;
    rule.src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|e| nat_bad_request(format!("invalid source address: {e}")))?
        .unwrap_or(Address::Any);
    rule.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|e| nat_bad_request(format!("invalid destination address: {e}")))?
        .unwrap_or(Address::Any);
    rule.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    rule.redirect = NatRedirect {
        address: Address::parse(req.redirect_addr.as_deref().unwrap_or("any"))
            .map_err(|e| nat_bad_request(format!("invalid redirect address: {e}")))?,
        port: port_range(req.redirect_port_start, req.redirect_port_end),
    };
    rule.label = req.label;
    rule.static_port = req.static_port;
    rule.af_to_dst = match req.af_to_dst.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => Some(
            Address::parse(a)
                .map_err(|e| nat_bad_request(format!("invalid translated destination: {e}")))?,
        ),
        _ => None,
    };
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => NatStatus::Active,
            "disabled" => NatStatus::Disabled,
            _ => return Err(nat_bad_request(format!("unknown status '{s}'"))),
        };
    }
    rule.updated_at = chrono::Utc::now();

    state
        .nat_engine
        .update(&rule)
        .await
        .map_err(nat_engine_error)?;
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
        .delete(uuid)
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
    // The NAT engine loads into "aifw-nat" (this endpoint used to read the
    // "aifw" filter anchor and always came back empty). Cross-family af-to
    // rules are filter-class, so both rulesets of the anchor are shown.
    let nat_rules = state
        .pf
        .get_nat_rules(aifw_common::anchors::NAT)
        .await
        .unwrap_or_default();
    let filter_rules = state
        .pf
        .get_rules(aifw_common::anchors::NAT)
        .await
        .unwrap_or_default();
    let mut output = Vec::new();
    if !nat_rules.is_empty() {
        output.push("# NAT rules (anchor: aifw-nat)".to_string());
        output.extend(nat_rules);
    }
    if !filter_rules.is_empty() {
        if !output.is_empty() {
            output.push("".to_string());
        }
        output.push("# Translation pass rules — af-to (anchor: aifw-nat)".to_string());
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
