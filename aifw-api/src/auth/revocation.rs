//! Access-token revocation blacklist (JTI-keyed) and its periodic cleanup.

use axum::http::StatusCode;
use sqlx::sqlite::SqlitePool;

/// Revoke an access token by its JTI (unique token ID).
pub async fn revoke_access_token(
    pool: &SqlitePool,
    jti: &str,
    expires_at: &str,
) -> Result<(), StatusCode> {
    sqlx::query("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)")
        .bind(jti)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth: failed to insert token revocation");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

/// Check if an access token has been revoked.
pub async fn is_token_revoked(pool: &SqlitePool, jti: &str) -> bool {
    sqlx::query_as::<_, (String,)>("SELECT jti FROM revoked_tokens WHERE jti = ?1")
        .bind(jti)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Clean up expired entries from the blacklist. Spawned on an hourly timer in
/// `main.rs` so the `revoked_tokens` table doesn't grow without bound.
pub async fn cleanup_revoked_tokens(pool: &SqlitePool) {
    let now = chrono::Utc::now().to_rfc3339();
    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await;
}
