//! API-key minting and verification, including the reserved cluster/daemon
//! key names that operators may not self-assign (SEC-H12).

use axum::http::StatusCode;
use chrono::Utc;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::password::{hash_password, verify_password};
use super::types::CreateApiKeyResponse;

/// API key names reserved for internal cluster identities (the daemon loopback
/// key and the inbound peer key). `create_api_key` refuses to mint these via
/// the normal Users → API Keys path so an operator can't self-grant peer /
/// daemon privilege by naming a regular key one of them (SEC-H12).
pub const RESERVED_API_KEY_NAMES: &[&str] = &["aifw-daemon-loopback", "aifw-cluster-peer"];

pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: Uuid,
    name: &str,
) -> Result<CreateApiKeyResponse, StatusCode> {
    if RESERVED_API_KEY_NAMES.contains(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let raw_key = format!("aifw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let prefix = raw_key[..12].to_string();
    let key_hash = hash_password(&raw_key)?;
    let id = Uuid::new_v4();

    sqlx::query("INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(id.to_string())
        .bind(name)
        .bind(&key_hash)
        .bind(&prefix)
        .bind(user_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(CreateApiKeyResponse {
        id,
        name: name.to_string(),
        key: raw_key,
        prefix,
    })
}

/// Verify an API key and return (user_id, key_name) on success.
pub async fn verify_api_key(pool: &SqlitePool, key: &str) -> Result<(String, String), StatusCode> {
    // Use prefix for fast lookup, then verify hash only on prefix-matched keys
    let prefix = if key.len() >= 12 { &key[..12] } else { key };
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT ak.key_hash, u.id, ak.name FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.prefix = ?1",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for (key_hash, user_id, key_name) in rows {
        if verify_password(key, &key_hash) {
            return Ok((user_id, key_name));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}
