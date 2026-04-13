use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::{Gateway, GatewayEvent, InstanceMember, InstanceStatus, RoutingInstance};

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

#[derive(Debug, Deserialize)]
pub struct CreateInstanceRequest {
    pub name: String,
    pub fib_number: u32,
    pub description: Option<String>,
    pub mgmt_reachable: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateInstanceRequest {
    pub name: String,
    pub fib_number: u32,
    pub description: Option<String>,
    pub mgmt_reachable: Option<bool>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub interface: String,
}

#[derive(Debug, Serialize)]
pub struct FibInfo {
    pub net_fibs: u32,
    pub used: Vec<u32>,
}

pub async fn list_instances(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<RoutingInstance>>>, StatusCode> {
    let list = state
        .multiwan_engine
        .list()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: list }))
}

pub async fn get_instance(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<RoutingInstance>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let inst = state
        .multiwan_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: inst }))
}

pub async fn create_instance(
    State(state): State<AppState>,
    Json(req): Json<CreateInstanceRequest>,
) -> Result<(StatusCode, Json<ApiResponse<RoutingInstance>>), StatusCode> {
    let now = Utc::now();
    let inst = RoutingInstance {
        id: Uuid::new_v4(),
        name: req.name,
        fib_number: req.fib_number,
        description: req.description,
        mgmt_reachable: req.mgmt_reachable.unwrap_or(false),
        status: InstanceStatus::Idle,
        created_at: now,
        updated_at: now,
    };
    let inst = state
        .multiwan_engine
        .add(inst)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: inst })))
}

pub async fn update_instance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateInstanceRequest>,
) -> Result<Json<ApiResponse<RoutingInstance>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let existing = state
        .multiwan_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let status = req
        .status
        .as_deref()
        .and_then(InstanceStatus::parse)
        .unwrap_or(existing.status);
    let updated = RoutingInstance {
        id: uuid,
        name: req.name,
        fib_number: req.fib_number,
        description: req.description,
        mgmt_reachable: req.mgmt_reachable.unwrap_or(existing.mgmt_reachable),
        status,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };
    let updated = state
        .multiwan_engine
        .update(updated)
        .await
        .map_err(|_| bad_request())?;
    Ok(Json(ApiResponse { data: updated }))
}

pub async fn delete_instance(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .multiwan_engine
        .delete(uuid)
        .await
        .map_err(|e| match e {
            aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::CONFLICT,
        })?;
    Ok(Json(MessageResponse {
        message: format!("instance {id} deleted"),
    }))
}

pub async fn list_members(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<InstanceMember>>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let members = state
        .multiwan_engine
        .list_members(uuid)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: members }))
}

pub async fn add_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<ApiResponse<InstanceMember>>), StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let member = state
        .multiwan_engine
        .add_member(uuid, &req.interface)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: member })))
}

pub async fn remove_member(
    State(state): State<AppState>,
    Path((id, iface)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .multiwan_engine
        .remove_member(uuid, &iface)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("interface {iface} detached from instance {id}"),
    }))
}

pub async fn list_fibs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<FibInfo>>, StatusCode> {
    let net_fibs = state
        .multiwan_engine
        .available_fibs()
        .await
        .map_err(|_| internal())?;
    let instances = state
        .multiwan_engine
        .list()
        .await
        .map_err(|_| internal())?;
    let used = instances.into_iter().map(|i| i.fib_number).collect();
    Ok(Json(ApiResponse {
        data: FibInfo { net_fibs, used },
    }))
}

// ============================================================
// Gateways (Phase 2)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreateGatewayRequest {
    pub name: String,
    pub instance_id: String,
    pub interface: String,
    pub next_hop: String,
    pub ip_version: Option<String>,
    pub monitor_kind: Option<String>,
    pub monitor_target: Option<String>,
    pub monitor_port: Option<u16>,
    pub monitor_expect: Option<String>,
    pub interval_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub loss_pct_down: Option<f64>,
    pub loss_pct_up: Option<f64>,
    pub consec_fail_down: Option<u32>,
    pub consec_ok_up: Option<u32>,
    pub weight: Option<u32>,
    pub dampening_secs: Option<u32>,
    pub dscp_tag: Option<u8>,
    pub enabled: Option<bool>,
}

fn req_to_gateway(req: CreateGatewayRequest, id: Option<Uuid>) -> Result<Gateway, StatusCode> {
    let instance_id = Uuid::parse_str(&req.instance_id).map_err(|_| bad_request())?;
    let now = Utc::now();
    Ok(Gateway {
        id: id.unwrap_or_else(Uuid::new_v4),
        name: req.name,
        instance_id,
        interface: req.interface,
        next_hop: req.next_hop,
        ip_version: req.ip_version.unwrap_or_else(|| "v4".into()),
        monitor_kind: req.monitor_kind.unwrap_or_else(|| "icmp".into()),
        monitor_target: req.monitor_target,
        monitor_port: req.monitor_port,
        monitor_expect: req.monitor_expect,
        interval_ms: req.interval_ms.unwrap_or(500),
        timeout_ms: req.timeout_ms.unwrap_or(1000),
        loss_pct_down: req.loss_pct_down.unwrap_or(20.0),
        loss_pct_up: req.loss_pct_up.unwrap_or(5.0),
        latency_ms_down: None,
        latency_ms_up: None,
        consec_fail_down: req.consec_fail_down.unwrap_or(3),
        consec_ok_up: req.consec_ok_up.unwrap_or(5),
        weight: req.weight.unwrap_or(1),
        dampening_secs: req.dampening_secs.unwrap_or(10),
        dscp_tag: req.dscp_tag,
        enabled: req.enabled.unwrap_or(true),
        state: aifw_common::GatewayState::Unknown,
        last_rtt_ms: None,
        last_jitter_ms: None,
        last_loss_pct: None,
        last_mos: None,
        last_probe_ts: None,
        created_at: now,
        updated_at: now,
    })
}

pub async fn list_gateways(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Gateway>>>, StatusCode> {
    let list = state
        .gateway_engine
        .list()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: list }))
}

pub async fn get_gateway(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Gateway>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let gw = state
        .gateway_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: gw }))
}

pub async fn create_gateway(
    State(state): State<AppState>,
    Json(req): Json<CreateGatewayRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Gateway>>), StatusCode> {
    let gw = req_to_gateway(req, None)?;
    let gw = state
        .gateway_engine
        .add(gw)
        .await
        .map_err(|_| bad_request())?;
    let _ = state.gateway_engine.start_monitor(gw.id).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: gw })))
}

pub async fn update_gateway(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateGatewayRequest>,
) -> Result<Json<ApiResponse<Gateway>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let existing = state
        .gateway_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let mut gw = req_to_gateway(req, Some(uuid))?;
    gw.created_at = existing.created_at;
    gw.state = existing.state;
    let gw = state
        .gateway_engine
        .update(gw)
        .await
        .map_err(|_| bad_request())?;
    state.gateway_engine.stop_monitor(gw.id).await;
    if gw.enabled {
        let _ = state.gateway_engine.start_monitor(gw.id).await;
    }
    Ok(Json(ApiResponse { data: gw }))
}

pub async fn delete_gateway(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .gateway_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("gateway {id} deleted"),
    }))
}

pub async fn list_gateway_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<GatewayEvent>>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let events = state
        .gateway_engine
        .list_events(uuid, 100)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: events }))
}

#[derive(Debug, Deserialize)]
pub struct InjectSampleRequest {
    pub success: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

pub async fn probe_now(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<InjectSampleRequest>,
) -> Result<Json<ApiResponse<Gateway>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let outcome = aifw_core::multiwan::ProbeOutcome {
        success: req.success,
        rtt_ms: req.rtt_ms,
        error: req.error,
    };
    state
        .gateway_engine
        .inject_sample(uuid, outcome)
        .await
        .map_err(|_| bad_request())?;
    let gw = state
        .gateway_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: gw }))
}


