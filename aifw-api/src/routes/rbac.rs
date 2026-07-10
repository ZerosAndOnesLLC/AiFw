//! Role management and `/api/v1/auth/me` — the permission catalogue and
//! CRUD over custom (non-builtin) roles.

use super::*;
use crate::auth;

pub async fn get_current_user(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_user = request
        .extensions()
        .get::<auth::AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user = auth::get_user_by_id(&state.pool, &auth_user.user_id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;

    let perms = auth_user.permissions.to_strings();

    Ok(Json(serde_json::json!({
        "id": user.id,
        "username": user.username,
        "role": auth_user.role,
        "role_id": user.role_id,
        "permissions": perms,
        "totp_enabled": user.totp_enabled,
        "auth_provider": user.auth_provider,
    })))
}

pub async fn list_permissions() -> Json<serde_json::Value> {
    use aifw_common::permission::ALL_PERMISSIONS;
    let perms: Vec<serde_json::Value> = ALL_PERMISSIONS
        .iter()
        .map(|p| {
            let s = p.as_str();
            let parts: Vec<&str> = s.split(':').collect();
            serde_json::json!({
                "key": s,
                "category": parts.first().unwrap_or(&""),
                "action": parts.get(1).unwrap_or(&""),
            })
        })
        .collect();
    Json(serde_json::json!({ "permissions": perms }))
}

pub async fn list_roles(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, i64, bool, Option<String>, String)>(
        "SELECT id, name, permissions, builtin, description, created_at FROM roles ORDER BY builtin DESC, name ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let roles: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, name, perms, builtin, desc, created)| {
            let perm_set = aifw_common::PermissionSet::from_bits(perms as u64);
            serde_json::json!({
                "id": id,
                "name": name,
                "permissions": perm_set.to_strings(),
                "permission_bits": perms,
                "builtin": builtin,
                "description": desc,
                "created_at": created,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({ "roles": roles })))
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: Option<String>,
}

pub async fn create_role(
    State(state): State<AppState>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    if req.name.trim().is_empty() {
        return Err(bad_request());
    }
    let str_refs: Vec<&str> = req.permissions.iter().map(|s| s.as_str()).collect();
    let perm_set = aifw_common::PermissionSet::from_strings(&str_refs);
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 0, ?4)"
    )
    .bind(&id)
    .bind(req.name.trim())
    .bind(perm_set.to_bits() as i64)
    .bind(req.description.as_deref())
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "name": req.name.trim(),
            "permissions": perm_set.to_strings(),
            "builtin": false,
        })),
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub description: Option<String>,
}

pub async fn update_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Prevent editing built-in roles' permissions
    let row = sqlx::query_as::<_, (bool,)>("SELECT builtin FROM roles WHERE id = ?1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;

    if row.0 {
        // Built-in: only allow description update
        if req.permissions.is_some() || req.name.is_some() {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(ref desc) = req.description {
            sqlx::query("UPDATE roles SET description = ?2 WHERE id = ?1")
                .bind(&id)
                .bind(desc)
                .execute(&state.pool)
                .await
                .map_err(|_| internal())?;
        }
    } else {
        if let Some(ref name) = req.name {
            sqlx::query("UPDATE roles SET name = ?2 WHERE id = ?1")
                .bind(&id)
                .bind(name.trim())
                .execute(&state.pool)
                .await
                .map_err(|_| internal())?;
        }
        if let Some(ref perms) = req.permissions {
            let str_refs: Vec<&str> = perms.iter().map(|s| s.as_str()).collect();
            let perm_set = aifw_common::PermissionSet::from_strings(&str_refs);
            sqlx::query("UPDATE roles SET permissions = ?2 WHERE id = ?1")
                .bind(&id)
                .bind(perm_set.to_bits() as i64)
                .execute(&state.pool)
                .await
                .map_err(|_| internal())?;
        }
        if let Some(ref desc) = req.description {
            sqlx::query("UPDATE roles SET description = ?2 WHERE id = ?1")
                .bind(&id)
                .bind(desc)
                .execute(&state.pool)
                .await
                .map_err(|_| internal())?;
        }
    }

    Ok(Json(serde_json::json!({ "message": "Role updated" })))
}

pub async fn delete_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Prevent deleting built-in roles
    let row = sqlx::query_as::<_, (bool,)>("SELECT builtin FROM roles WHERE id = ?1")
        .bind(&id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;

    if row.0 {
        return Err(StatusCode::FORBIDDEN);
    }

    // Check no users reference this role
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role_id = ?1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await
        .map_err(|_| internal())?;
    if count.0 > 0 {
        return Err(StatusCode::CONFLICT);
    }

    sqlx::query("DELETE FROM roles WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    Ok(Json(MessageResponse {
        message: "Role deleted".to_string(),
    }))
}
