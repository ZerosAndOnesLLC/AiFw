//! `/api/v1/auth/api-keys` handlers — self-service API key minting,
//! listing and revocation.
//!
//! Any authenticated user may manage their own keys. Minting or revoking a
//! key for someone else needs `users:write`; listing everyone's keys needs
//! `users:read`. A request authenticated *with* an API key may not mint
//! keys (a narrowed key must not be able to mint an un-narrowed one).

use super::*;
use crate::auth::{self, AuthUser};
use aifw_common::{Permission, PermissionSet};
use axum::{Extension, extract::Query};

/// True when every permission in `inner` is also in `outer`.
fn is_subset(inner: u64, outer: PermissionSet) -> bool {
    inner & !outer.to_bits() == 0
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthUser>,
    Json(req): Json<auth::CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<auth::CreateApiKeyResponse>), StatusCode> {
    if caller.api_key_id.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }

    let owner_id = req
        .user_id
        .clone()
        .unwrap_or_else(|| caller.user_id.clone());
    if owner_id != caller.user_id && !caller.permissions.has(Permission::UsersWrite) {
        return Err(StatusCode::FORBIDDEN);
    }

    let owner = auth::get_user_by_id(&state.pool, &owner_id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    // Service accounts get their keys from dedicated code paths only.
    if !owner.enabled || owner.auth_provider == "system" {
        return Err(bad_request());
    }

    if let Some(role_id) = req.role_id.as_deref() {
        let (role_bits, _) = auth::role_permission_bits(&state.pool, role_id)
            .await?
            .ok_or_else(bad_request)?;
        let (owner_bits, _) = auth::tokens::resolve_token_permissions(
            &state.pool,
            &owner.role,
            owner.role_id.as_deref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "api keys: failed to resolve owner permissions");
            internal()
        })?;
        if !is_subset(role_bits, PermissionSet::from_bits(owner_bits))
            || !is_subset(role_bits, caller.permissions)
        {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let expires_at = auth::expiry_from_days(req.expires_in_days, chrono::Utc::now())?;
    let response = auth::create_api_key(
        &state.pool,
        owner.id,
        &req.name,
        req.role_id.as_deref(),
        expires_at,
    )
    .await?;

    auth::log_user_audit(
        &state.pool,
        &caller.user_id,
        Some(&owner_id),
        "api_key_created",
        Some(&format!("{} ({})", response.name, response.prefix)),
    )
    .await;

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthUser>,
    Query(q): Query<auth::ListApiKeysQuery>,
) -> Result<Json<ApiResponse<Vec<auth::ApiKeyInfo>>>, StatusCode> {
    let owner = if q.all {
        if !caller.permissions.has(Permission::UsersRead) {
            return Err(StatusCode::FORBIDDEN);
        }
        None
    } else {
        Some(caller.user_id.as_str())
    };
    let keys = auth::list_api_keys(&state.pool, owner).await?;
    Ok(Json(ApiResponse { data: keys }))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let (owner_id, name) = auth::api_key_owner(&state.pool, &id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;
    if auth::RESERVED_API_KEY_NAMES.contains(&name.as_str()) {
        return Err(StatusCode::NOT_FOUND);
    }
    if owner_id != caller.user_id && !caller.permissions.has(Permission::UsersWrite) {
        return Err(StatusCode::FORBIDDEN);
    }
    if !auth::revoke_api_key(&state.pool, &id).await? {
        return Err(StatusCode::NOT_FOUND);
    }
    auth::log_user_audit(
        &state.pool,
        &caller.user_id,
        Some(&owner_id),
        "api_key_revoked",
        Some(&name),
    )
    .await;
    Ok(Json(MessageResponse {
        message: format!("API key '{name}' revoked"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_check() {
        let outer = PermissionSet::from_permissions(&[Permission::RulesRead, Permission::NatRead]);
        let inner = PermissionSet::from_permissions(&[Permission::RulesRead]).to_bits();
        assert!(is_subset(inner, outer));
        let wider =
            PermissionSet::from_permissions(&[Permission::RulesRead, Permission::UsersWrite])
                .to_bits();
        assert!(!is_subset(wider, outer));
        assert!(is_subset(0, outer));
    }
}
