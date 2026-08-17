//! Persistence for TOTP secrets and single-use recovery codes. The TOTP
//! algorithm itself lives in the sibling `totp` module.

use axum::http::StatusCode;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::password::{hash_password, verify_password};

pub async fn save_totp_secret(
    pool: &SqlitePool,
    user_id: &str,
    secret: &str,
) -> Result<(), StatusCode> {
    // #298: TOTP seeds are sealed at rest.
    let sealed = aifw_core::secrets::seal(secret).map_err(|e| {
        tracing::error!(error = %e, "auth: failed to seal TOTP secret");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    sqlx::query("UPDATE users SET totp_secret = ?1 WHERE id = ?2")
        .bind(sealed)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to save TOTP secret");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

pub async fn enable_totp(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET totp_enabled = 1 WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to enable TOTP");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

pub async fn disable_totp(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to disable TOTP");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    // Also delete recovery codes
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to delete recovery codes on TOTP disable");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

pub async fn save_recovery_codes(
    pool: &SqlitePool,
    user_id: &str,
    codes: &[String],
) -> Result<(), StatusCode> {
    // Delete old codes
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to delete existing recovery codes");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    for code in codes {
        let code_hash = hash_password(code)?;
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?1, ?2, ?3, 0)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(&code_hash)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to insert recovery code");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    }
    Ok(())
}

/// Try to use a recovery code. Returns true if valid and unused.
pub async fn use_recovery_code(pool: &SqlitePool, user_id: &str, code: &str) -> bool {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ?1 AND used = 0",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (id, code_hash) in rows {
        if verify_password(code, &code_hash) {
            let _ = sqlx::query("UPDATE recovery_codes SET used = 1 WHERE id = ?1")
                .bind(&id)
                .execute(pool)
                .await;
            return true;
        }
    }
    false
}
