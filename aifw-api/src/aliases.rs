use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use aifw_common::{Alias, AliasType};

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
pub struct CreateAliasRequest {
    pub name: String,
    pub alias_type: String,
    pub entries: Vec<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_aliases(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Alias>>>, StatusCode> {
    let aliases = state.alias_engine.list().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: aliases }))
}

pub async fn get_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Alias>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let alias = state
        .alias_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: alias }))
}

fn validate_alias_name(name: &str) -> Result<(), StatusCode> {
    if name.is_empty() || name.len() > 31 {
        return Err(bad_request());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(bad_request());
    }
    Ok(())
}

pub async fn create_alias(
    State(state): State<AppState>,
    Json(req): Json<CreateAliasRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Alias>>), StatusCode> {
    validate_alias_name(&req.name)?;
    let alias_type = AliasType::parse(&req.alias_type).ok_or(bad_request())?;
    let now = Utc::now();
    let alias = Alias {
        id: Uuid::new_v4(),
        name: req.name,
        alias_type,
        entries: req.entries,
        description: req.description,
        enabled: req.enabled.unwrap_or(true),
        created_at: now,
        updated_at: now,
    };
    let alias = state
        .alias_engine
        .add(alias)
        .await
        .map_err(|_| bad_request())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: alias })))
}

pub async fn update_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateAliasRequest>,
) -> Result<Json<ApiResponse<Alias>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    validate_alias_name(&req.name)?;
    let alias_type = AliasType::parse(&req.alias_type).ok_or(bad_request())?;
    let existing = state
        .alias_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let alias = Alias {
        id: uuid,
        name: req.name,
        alias_type,
        entries: req.entries,
        description: req.description,
        enabled: req.enabled.unwrap_or(true),
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };
    let alias = state
        .alias_engine
        .update(alias)
        .await
        .map_err(|_| bad_request())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(ApiResponse { data: alias }))
}

pub async fn delete_alias(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .alias_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(MessageResponse {
        message: "Alias deleted".to_string(),
    }))
}
