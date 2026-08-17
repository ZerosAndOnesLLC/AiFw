//! User CRUD, password-policy validation, the user audit log, and the
//! by-username / by-id lookups the login flow depends on.

use axum::http::StatusCode;
use chrono::Utc;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::password::hash_password;
use super::types::{CreateUserRequest, UpdateUserRequest, User, UserAuditEntry};

/// Validate password meets minimum security requirements.
///
/// `min_length` is the operator-configured `password_min_length`
/// (`AuthSettings`). We floor it at 8 so a misconfigured-low setting can
/// never weaken the baseline below the historical hardcoded minimum.
pub fn validate_password(password: &str, min_length: u32) -> Result<(), StatusCode> {
    let min = (min_length as usize).max(8);
    if password.len() < min {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

pub async fn create_user(
    pool: &SqlitePool,
    req: &CreateUserRequest,
    min_length: u32,
) -> Result<User, StatusCode> {
    validate_password(&req.password, min_length)?;
    let pw_hash = hash_password(&req.password)?;
    let role = req.role.as_deref().unwrap_or("viewer").to_string();
    // #318: the system role belongs to AiFw's own service identities only.
    if role == "system" || role == super::migrate::SYSTEM_ROLE_ID {
        return Err(StatusCode::BAD_REQUEST);
    }
    let role_id = match role.as_str() {
        "admin" => Some("builtin-admin".to_string()),
        "operator" => Some("builtin-operator".to_string()),
        "viewer" => Some("builtin-viewer".to_string()),
        _ => None,
    };
    let user = User {
        id: Uuid::new_v4(),
        username: req.username.clone(),
        password_hash: pw_hash,
        totp_enabled: false,
        totp_secret: None,
        auth_provider: "local".to_string(),
        role,
        role_id: role_id.clone(),
        enabled: true,
        created_at: Utc::now().to_rfc3339(),
    };

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(user.id.to_string())
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(user.totp_enabled)
    .bind(user.totp_secret.as_deref())
    .bind(&user.auth_provider)
    .bind(&user.role)
    .bind(user.role_id.as_deref())
    .bind(user.enabled)
    .bind(&user.created_at)
    .execute(pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    Ok(user)
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<User>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| { tracing::error!(error = %e, "auth: failed to list users"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(rows
        .into_iter()
        .map(
            |(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
                id: Uuid::parse_str(&id).unwrap_or_default(),
                username,
                password_hash: pw,
                totp_enabled: totp_on,
                totp_secret: totp_sec,
                auth_provider: provider,
                role,
                role_id,
                enabled,
                created_at: ca,
            },
        )
        .collect())
}

pub async fn update_user(
    pool: &SqlitePool,
    user_id: &str,
    req: &UpdateUserRequest,
    min_length: u32,
) -> Result<User, StatusCode> {
    let mut user = get_user_by_id(pool, user_id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;

    if let Some(ref username) = req.username {
        user.username = username.clone();
    }
    if let Some(ref password) = req.password {
        validate_password(password, min_length)?;
        user.password_hash = hash_password(password)?;
    }
    if let Some(ref role) = req.role {
        // #318: the system role belongs to AiFw's own service identities only.
        if role == "system" || role == super::migrate::SYSTEM_ROLE_ID {
            return Err(StatusCode::BAD_REQUEST);
        }
        user.role = role.clone();
        // Map built-in role names to role_id; custom role_id can be set directly
        user.role_id = match role.as_str() {
            "admin" => Some("builtin-admin".to_string()),
            "operator" => Some("builtin-operator".to_string()),
            "viewer" => Some("builtin-viewer".to_string()),
            _ => {
                // Check if it's a custom role_id
                let exists = sqlx::query_as::<_, (String,)>(
                    "SELECT id FROM roles WHERE id = ?1 OR name = ?1",
                )
                .bind(role)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
                exists.map(|(id,)| id)
            }
        };
    }
    if let Some(enabled) = req.enabled {
        user.enabled = enabled;
    }

    sqlx::query(
        "UPDATE users SET username = ?2, password_hash = ?3, role = ?4, role_id = ?5, enabled = ?6 WHERE id = ?1",
    )
    .bind(user_id)
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(&user.role)
    .bind(user.role_id.as_deref())
    .bind(user.enabled)
    .execute(pool)
    .await
    .map_err(|e| { tracing::error!(error = %e, "auth: failed to update user"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(user)
}

pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    let result = sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to delete user");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    // Clean up related data
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await;
    Ok(())
}

pub async fn log_user_audit(
    pool: &SqlitePool,
    actor_id: &str,
    user_id: Option<&str>,
    action: &str,
    details: Option<&str>,
) {
    let _ = sqlx::query(
        "INSERT INTO user_audit_log (id, user_id, actor_id, action, details, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(actor_id)
    .bind(action)
    .bind(details)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await;
}

pub async fn list_user_audit_log(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<UserAuditEntry>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, Option<String>, String, String, Option<String>, Option<String>, String)>(
        "SELECT id, user_id, actor_id, action, details, ip_addr, created_at FROM user_audit_log ORDER BY created_at DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|e| { tracing::error!(error = %e, "auth: failed to query user audit log"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(rows
        .into_iter()
        .map(
            |(id, user_id, actor_id, action, details, ip_addr, created_at)| UserAuditEntry {
                id,
                user_id,
                actor_id,
                action,
                details,
                ip_addr,
                created_at,
            },
        )
        .collect())
}

pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| { tracing::error!(error = %e, "auth: failed to query user by username"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(row.map(
        |(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            username,
            password_hash: pw,
            totp_enabled: totp_on,
            totp_secret: totp_sec,
            auth_provider: provider,
            role,
            role_id,
            enabled,
            created_at: ca,
        },
    ))
}

pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users WHERE id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| { tracing::error!(error = %e, "auth: failed to query user by id"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(row.map(
        |(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            username,
            password_hash: pw,
            totp_enabled: totp_on,
            totp_secret: totp_sec,
            auth_provider: provider,
            role,
            role_id,
            enabled,
            created_at: ca,
        },
    ))
}
