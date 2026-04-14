use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::{
    Gateway, GatewayEvent, GatewayGroup, GroupMember, GroupPolicy, InstanceMember, InstanceStatus,
    RoutingInstance, StickyMode,
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



// ============================================================
// Gateway groups (Phase 3)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub policy: String,
    pub preempt: Option<bool>,
    pub sticky: Option<String>,
    pub hysteresis_ms: Option<u32>,
    pub kill_states_on_failover: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AddGroupMemberRequest {
    pub gateway_id: String,
    pub tier: Option<u32>,
    pub weight: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct GroupActiveResponse {
    pub selection: String,
    pub gateways: Vec<Uuid>,
}

pub async fn list_groups(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<GatewayGroup>>>, StatusCode> {
    let list = state.group_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: list }))
}

pub async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GatewayGroup>>), StatusCode> {
    let policy = GroupPolicy::parse(&req.policy).ok_or(bad_request())?;
    let sticky = req
        .sticky
        .as_deref()
        .and_then(StickyMode::parse)
        .unwrap_or(StickyMode::None);
    let now = Utc::now();
    let g = GatewayGroup {
        id: Uuid::new_v4(),
        name: req.name,
        policy,
        preempt: req.preempt.unwrap_or(true),
        sticky,
        hysteresis_ms: req.hysteresis_ms.unwrap_or(2000),
        kill_states_on_failover: req.kill_states_on_failover.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };
    let g = state.group_engine.add(g).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: g })))
}

pub async fn update_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<ApiResponse<GatewayGroup>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let existing = state
        .group_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let policy = GroupPolicy::parse(&req.policy).ok_or(bad_request())?;
    let sticky = req
        .sticky
        .as_deref()
        .and_then(StickyMode::parse)
        .unwrap_or(existing.sticky);
    let g = GatewayGroup {
        id: uuid,
        name: req.name,
        policy,
        preempt: req.preempt.unwrap_or(existing.preempt),
        sticky,
        hysteresis_ms: req.hysteresis_ms.unwrap_or(existing.hysteresis_ms),
        kill_states_on_failover: req
            .kill_states_on_failover
            .unwrap_or(existing.kill_states_on_failover),
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };
    let g = state.group_engine.update(g).await.map_err(|_| bad_request())?;
    Ok(Json(ApiResponse { data: g }))
}

pub async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .group_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("group {id} deleted"),
    }))
}

pub async fn list_group_members(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<GroupMember>>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let members = state
        .group_engine
        .list_members(uuid)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: members }))
}

pub async fn add_group_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AddGroupMemberRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GroupMember>>), StatusCode> {
    let group_id = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let gateway_id = Uuid::parse_str(&req.gateway_id).map_err(|_| bad_request())?;
    let m = GroupMember {
        group_id,
        gateway_id,
        tier: req.tier.unwrap_or(1),
        weight: req.weight.unwrap_or(1),
    };
    let m = state.group_engine.add_member(m).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: m })))
}

pub async fn remove_group_member(
    State(state): State<AppState>,
    Path((id, gw)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let group_id = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let gateway_id = Uuid::parse_str(&gw).map_err(|_| bad_request())?;
    state
        .group_engine
        .remove_member(group_id, gateway_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: "member removed".into(),
    }))
}

pub async fn group_active(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<GroupActiveResponse>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let group = state
        .group_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let members = state
        .group_engine
        .list_members(uuid)
        .await
        .map_err(|_| internal())?;
    let gateways = state.gateway_engine.list().await.map_err(|_| internal())?;
    let sel = aifw_core::multiwan::select(&group, &members, &gateways);
    let (kind, ids) = match sel {
        aifw_core::multiwan::Selection::Single(id) => ("single".to_string(), vec![id]),
        aifw_core::multiwan::Selection::WeightedList(l) => {
            ("weighted".to_string(), l.into_iter().map(|(id, _)| id).collect())
        }
        aifw_core::multiwan::Selection::None => ("none".to_string(), vec![]),
    };
    Ok(Json(ApiResponse {
        data: GroupActiveResponse {
            selection: kind,
            gateways: ids,
        },
    }))
}

// ============================================================
// Policy routing rules (Phase 4)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub priority: i64,
    pub name: String,
    pub status: Option<String>,
    pub ip_version: Option<String>,
    pub iface_in: Option<String>,
    pub src_addr: Option<String>,
    pub dst_addr: Option<String>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub protocol: Option<String>,
    pub dscp_in: Option<u8>,
    pub action_kind: String,
    pub target_id: String,
    pub sticky: Option<String>,
    pub fallback_target_id: Option<String>,
    pub description: Option<String>,
}

pub async fn list_policies(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_common::PolicyRule>>>, StatusCode> {
    let list = state.policy_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: list }))
}

fn req_to_policy(
    req: CreatePolicyRequest,
    id: Option<Uuid>,
    created_at: Option<chrono::DateTime<Utc>>,
) -> Result<aifw_common::PolicyRule, StatusCode> {
    let target = Uuid::parse_str(&req.target_id).map_err(|_| bad_request())?;
    let fallback = match req.fallback_target_id {
        Some(s) => Some(Uuid::parse_str(&s).map_err(|_| bad_request())?),
        None => None,
    };
    let sticky = req
        .sticky
        .as_deref()
        .and_then(aifw_common::StickyMode::parse)
        .unwrap_or(aifw_common::StickyMode::None);
    let now = Utc::now();
    Ok(aifw_common::PolicyRule {
        id: id.unwrap_or_else(Uuid::new_v4),
        priority: req.priority,
        name: req.name,
        status: req.status.unwrap_or_else(|| "active".into()),
        ip_version: req.ip_version.unwrap_or_else(|| "both".into()),
        iface_in: req.iface_in,
        src_addr: req.src_addr.unwrap_or_else(|| "any".into()),
        dst_addr: req.dst_addr.unwrap_or_else(|| "any".into()),
        src_port: req.src_port,
        dst_port: req.dst_port,
        protocol: req.protocol.unwrap_or_else(|| "any".into()),
        dscp_in: req.dscp_in,
        geoip_country: None,
        schedule_id: None,
        action_kind: req.action_kind,
        target_id: target,
        sticky,
        fallback_target_id: fallback,
        description: req.description,
        created_at: created_at.unwrap_or(now),
        updated_at: now,
    })
}

pub async fn create_policy(
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<ApiResponse<aifw_common::PolicyRule>>), StatusCode> {
    let p = req_to_policy(req, None, None)?;
    let p = state.policy_engine.add(p).await.map_err(|_| bad_request())?;
    let _ = apply_all(&state).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: p })))
}

pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<aifw_common::PolicyRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let existing = state
        .policy_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let p = req_to_policy(req, Some(uuid), Some(existing.created_at))?;
    let p = state.policy_engine.update(p).await.map_err(|_| bad_request())?;
    let _ = apply_all(&state).await;
    Ok(Json(ApiResponse { data: p }))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .policy_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let _ = apply_all(&state).await;
    Ok(Json(MessageResponse {
        message: format!("policy {id} deleted"),
    }))
}

pub async fn apply_policies(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    apply_all(&state).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "pf anchors reloaded".into(),
    }))
}

async fn apply_all(state: &AppState) -> aifw_common::Result<()> {
    let instances = state.multiwan_engine.list().await?;
    let gateways = state.gateway_engine.list().await?;
    let groups = state.group_engine.list().await?;
    let mut members = std::collections::HashMap::new();
    for g in &groups {
        members.insert(g.id, state.group_engine.list_members(g.id).await?);
    }
    state
        .policy_engine
        .apply(&instances, &gateways, &groups, &members)
        .await?;
    Ok(())
}

// ============================================================
// Route leaks (Phase 5)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreateLeakRequest {
    pub name: String,
    pub src_instance_id: String,
    pub dst_instance_id: String,
    pub prefix: String,
    pub protocol: Option<String>,
    pub ports: Option<String>,
    pub direction: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_leaks(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_common::RouteLeak>>>, StatusCode> {
    let list = state.leak_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: list }))
}

pub async fn create_leak(
    State(state): State<AppState>,
    Json(req): Json<CreateLeakRequest>,
) -> Result<(StatusCode, Json<ApiResponse<aifw_common::RouteLeak>>), StatusCode> {
    let src = Uuid::parse_str(&req.src_instance_id).map_err(|_| bad_request())?;
    let dst = Uuid::parse_str(&req.dst_instance_id).map_err(|_| bad_request())?;
    let now = Utc::now();
    let l = aifw_common::RouteLeak {
        id: Uuid::new_v4(),
        name: req.name,
        src_instance_id: src,
        dst_instance_id: dst,
        prefix: req.prefix,
        protocol: req.protocol.unwrap_or_else(|| "any".into()),
        ports: req.ports,
        direction: req.direction.unwrap_or_else(|| "bidirectional".into()),
        enabled: req.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };
    let l = state.leak_engine.add(l).await.map_err(|_| bad_request())?;
    let _ = apply_leaks(&state).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: l })))
}

pub async fn delete_leak(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.leak_engine.delete(uuid).await.map_err(|e| match e {
        aifw_common::AifwError::Validation(_) => StatusCode::CONFLICT,
        aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => internal(),
    })?;
    let _ = apply_leaks(&state).await;
    Ok(Json(MessageResponse {
        message: format!("leak {id} deleted"),
    }))
}

pub async fn seed_mgmt_escapes(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let instances = state.multiwan_engine.list().await.map_err(|_| internal())?;
    state
        .leak_engine
        .seed_mgmt_escapes(&instances)
        .await
        .map_err(|_| internal())?;
    let _ = apply_leaks(&state).await;
    Ok(Json(MessageResponse {
        message: "mgmt-escape leaks seeded".into(),
    }))
}

async fn apply_leaks(state: &AppState) -> aifw_common::Result<()> {
    let instances = state.multiwan_engine.list().await?;
    state.leak_engine.apply(&instances).await
}

// ============================================================
// Pre-flight / blast-radius (Phase 6)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    pub policies: Vec<CreatePolicyRequest>,
}

pub async fn preview_policies(
    State(state): State<AppState>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<ApiResponse<aifw_core::multiwan::BlastRadiusReport>>, StatusCode> {
    let current = state.policy_engine.list().await.map_err(|_| internal())?;
    let proposed: Vec<aifw_common::PolicyRule> = req
        .policies
        .into_iter()
        .map(|r| req_to_policy(r, None, None))
        .collect::<Result<Vec<_>, _>>()?;

    let instances = state.multiwan_engine.list().await.map_err(|_| internal())?;
    let gateways = state.gateway_engine.list().await.map_err(|_| internal())?;
    let groups = state.group_engine.list().await.map_err(|_| internal())?;
    let mut members = std::collections::HashMap::new();
    for g in &groups {
        members.insert(
            g.id,
            state.group_engine.list_members(g.id).await.map_err(|_| internal())?,
        );
    }

    let report = state
        .preflight_engine
        .preview(&current, &proposed, &instances, &gateways, &groups, &members)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: report }))
}

// ============================================================
// Flow migration (Phase 6/8)
// ============================================================

#[derive(Debug, Serialize)]
pub struct FlowMigrationResponse {
    pub killed: u64,
}

pub async fn migrate_flow(
    State(state): State<AppState>,
    Path(label): Path<String>,
) -> Result<Json<ApiResponse<FlowMigrationResponse>>, StatusCode> {
    let killed = state
        .pf
        .kill_states_for_label(&label)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse {
        data: FlowMigrationResponse { killed },
    }))
}

// ============================================================
// Per-flow visibility (Phase 8)
// ============================================================

#[derive(Debug, Serialize)]
pub struct FlowSummary {
    pub id: u64,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub iface: Option<String>,
    pub rtable: Option<u32>,
    pub bytes: u64,
    pub age_secs: u64,
}

pub async fn list_flows(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<FlowSummary>>>, StatusCode> {
    let states = state.pf.get_states().await.map_err(|_| internal())?;
    let flows: Vec<FlowSummary> = states
        .into_iter()
        .take(500)
        .map(|s| FlowSummary {
            id: s.id,
            protocol: s.protocol,
            src: format!("{}:{}", s.src_addr, s.src_port),
            dst: format!("{}:{}", s.dst_addr, s.dst_port),
            iface: s.iface,
            rtable: s.rtable,
            bytes: s.bytes_in + s.bytes_out,
            age_secs: s.age_secs,
        })
        .collect();
    Ok(Json(ApiResponse { data: flows }))
}

// ============================================================
// SLA reports (Phase 7)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct SlaQuery {
    pub window: Option<String>, // 24h | 7d | 30d
}

pub async fn get_sla(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SlaQuery>,
) -> Result<Json<ApiResponse<Vec<aifw_core::multiwan::SlaSample>>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let hours = match q.window.as_deref() {
        Some("7d") => 7 * 24,
        Some("30d") => 30 * 24,
        _ => 24,
    };
    let samples = state
        .sla_engine
        .window(uuid, hours)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: samples }))
}

// ============================================================
// YAML GitOps export/import (Phase 9)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigYaml {
    pub instances: Vec<RoutingInstance>,
    pub gateways: Vec<Gateway>,
    pub groups: Vec<GatewayGroup>,
    pub policies: Vec<aifw_common::PolicyRule>,
    pub leaks: Vec<aifw_common::RouteLeak>,
}

pub async fn export_config(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ConfigYaml>>, StatusCode> {
    let data = ConfigYaml {
        instances: state.multiwan_engine.list().await.map_err(|_| internal())?,
        gateways: state.gateway_engine.list().await.map_err(|_| internal())?,
        groups: state.group_engine.list().await.map_err(|_| internal())?,
        policies: state.policy_engine.list().await.map_err(|_| internal())?,
        leaks: state.leak_engine.list().await.map_err(|_| internal())?,
    };
    Ok(Json(ApiResponse { data }))
}

// ============================================================
// GitOps import (Phase 9b)
// ============================================================

pub async fn import_config(
    State(state): State<AppState>,
    Json(cfg): Json<ConfigYaml>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Instances: upsert by id (keeps FIB 0 default seed safe since its id is fixed)
    for inst in cfg.instances.iter().filter(|i| !i.mgmt_reachable) {
        // Only try to add; if already exists by id, update.
        if state.multiwan_engine.get(inst.id).await.is_ok() {
            let _ = state.multiwan_engine.update(inst.clone()).await;
        } else {
            let _ = state.multiwan_engine.add(inst.clone()).await;
        }
    }
    for gw in &cfg.gateways {
        if state.gateway_engine.get(gw.id).await.is_ok() {
            let _ = state.gateway_engine.update(gw.clone()).await;
        } else {
            let _ = state.gateway_engine.add(gw.clone()).await;
        }
    }
    for g in &cfg.groups {
        if state.group_engine.get(g.id).await.is_ok() {
            let _ = state.group_engine.update(g.clone()).await;
        } else {
            let _ = state.group_engine.add(g.clone()).await;
        }
    }
    for p in &cfg.policies {
        if state.policy_engine.get(p.id).await.is_ok() {
            let _ = state.policy_engine.update(p.clone()).await;
        } else {
            let _ = state.policy_engine.add(p.clone()).await;
        }
    }
    for l in &cfg.leaks {
        if state.leak_engine.get(l.id).await.is_ok() {
            let _ = state.leak_engine.update(l.clone()).await;
        } else {
            let _ = state.leak_engine.add(l.clone()).await;
        }
    }
    let _ = apply_all(&state).await;
    let _ = apply_leaks(&state).await;
    Ok(Json(MessageResponse {
        message: format!(
            "imported {} instances, {} gateways, {} groups, {} policies, {} leaks",
            cfg.instances.len(),
            cfg.gateways.len(),
            cfg.groups.len(),
            cfg.policies.len(),
            cfg.leaks.len(),
        ),
    }))
}

// ============================================================
// Policy reorder + duplicate (better UX)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct ReorderRequest {
    pub policy_ids: Vec<String>,
}

pub async fn reorder_policies(
    State(state): State<AppState>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    for (i, id_str) in req.policy_ids.iter().enumerate() {
        let uuid = Uuid::parse_str(id_str).map_err(|_| bad_request())?;
        let mut p = state
            .policy_engine
            .get(uuid)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
        p.priority = (i as i64) + 1;
        state
            .policy_engine
            .update(p)
            .await
            .map_err(|_| internal())?;
    }
    let _ = apply_all(&state).await;
    Ok(Json(MessageResponse {
        message: format!("{} policies reordered", req.policy_ids.len()),
    }))
}

pub async fn duplicate_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ApiResponse<aifw_common::PolicyRule>>), StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let src = state
        .policy_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let now = Utc::now();
    let dup = aifw_common::PolicyRule {
        id: Uuid::new_v4(),
        priority: src.priority + 1,
        name: format!("{}-copy", src.name),
        status: "disabled".into(), // duplicated rules start disabled for safety
        created_at: now,
        updated_at: now,
        ..src
    };
    let dup = state
        .policy_engine
        .add(dup)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: dup })))
}

#[derive(Debug, Deserialize)]
pub struct TogglePolicyRequest {
    pub enabled: bool,
}

pub async fn toggle_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TogglePolicyRequest>,
) -> Result<Json<ApiResponse<aifw_common::PolicyRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut p = state
        .policy_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    p.status = if req.enabled { "active".into() } else { "disabled".into() };
    let p = state.policy_engine.update(p).await.map_err(|_| internal())?;
    let _ = apply_all(&state).await;
    Ok(Json(ApiResponse { data: p }))
}
