//! `/api/v1/auth/users` handlers — user CRUD and the per-user audit log.

use super::auth::extract_user_id;
use super::*;
use crate::auth;

/// Protected user creation — requires authentication (admin only via RBAC middleware)
pub async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<auth::CreateUserRequest>,
) -> Result<(StatusCode, Json<ApiResponse<auth::User>>), StatusCode> {
    let user =
        auth::create_user(&state.pool, &req, state.auth_settings.password_min_length).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: user })))
}

pub async fn list_users(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::User>>>, StatusCode> {
    let users = auth::list_users(&state.pool).await?;
    Ok(Json(ApiResponse { data: users }))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<auth::User>>, StatusCode> {
    let user = auth::get_user_by_id(&state.pool, &id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: user }))
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<auth::UpdateUserRequest>,
) -> Result<Json<ApiResponse<auth::User>>, StatusCode> {
    let actor_id = extract_user_id(&headers, &state)?;
    let user = auth::update_user(
        &state.pool,
        &id,
        &req,
        state.auth_settings.password_min_length,
    )
    .await?;
    // PERF-C12: invalidate the user cache so disable / role change takes
    // effect immediately instead of waiting out the TTL.
    state.auth_user_cache.remove(&id);
    let details = format!("updated user {}", user.username);
    auth::log_user_audit(
        &state.pool,
        &actor_id,
        Some(&id),
        "user_updated",
        Some(&details),
    )
    .await;
    Ok(Json(ApiResponse { data: user }))
}

pub async fn delete_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let actor_id = extract_user_id(&headers, &state)?;
    // Prevent self-deletion
    if actor_id == id {
        return Err(StatusCode::BAD_REQUEST);
    }
    let user = auth::get_user_by_id(&state.pool, &id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    auth::delete_user(&state.pool, &id).await?;
    // PERF-C12: invalidate the user cache so the deleted user can't
    // continue authenticating with a still-valid token for AUTH_USER_CACHE_TTL.
    state.auth_user_cache.remove(&id);
    auth::log_user_audit(
        &state.pool,
        &actor_id,
        Some(&id),
        "user_deleted",
        Some(&format!("deleted user {}", user.username)),
    )
    .await;
    Ok(Json(MessageResponse {
        message: format!("User {} deleted", user.username),
    }))
}

pub async fn list_user_audit(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::UserAuditEntry>>>, StatusCode> {
    let entries = auth::list_user_audit_log(&state.pool, 200).await?;
    Ok(Json(ApiResponse { data: entries }))
}
