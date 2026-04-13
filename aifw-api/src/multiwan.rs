use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::{InstanceMember, InstanceStatus, RoutingInstance};

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
