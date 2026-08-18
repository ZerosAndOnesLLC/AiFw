//! `aifw users …`.

use aifw_core::Database;
use std::path::Path;
use uuid::Uuid;

// ============================================================
// Users
// ============================================================

pub async fn users_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, String, bool, bool)>(
        "SELECT id, username, role, totp_enabled, enabled FROM users ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    if json {
        let users: Vec<serde_json::Value> = rows.iter().map(|(id, u, r, mfa, e)| {
            serde_json::json!({"id": id, "username": u, "role": r, "mfa": mfa, "enabled": e})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&users)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No users.");
        return Ok(());
    }

    println!(
        "{:<36} {:<16} {:<10} {:<6} Status",
        "ID", "Username", "Role", "MFA"
    );
    println!("{}", "-".repeat(80));
    for (id, username, role, mfa, enabled) in &rows {
        let status = if *enabled { "active" } else { "disabled" };
        let mfa_str = if *mfa { "yes" } else { "no" };
        println!(
            "{:<36} {:<16} {:<10} {:<6} {}",
            id, username, role, mfa_str, status
        );
    }
    Ok(())
}

pub async fn users_add(
    db_path: &Path,
    username: &str,
    password: &str,
    role: &str,
) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Same pinned Argon2id parameters as the API and setup wizard (SEC-M4 #301).
    let pw_hash = aifw_common::password::hash_password(password)
        .map_err(|e| anyhow::anyhow!("hash error: {e}"))?;

    sqlx::query("INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, role, enabled, created_at) VALUES (?1, ?2, ?3, 0, 'local', ?4, 1, ?5)")
        .bind(&id).bind(username).bind(&pw_hash).bind(role).bind(&now)
        .execute(pool).await?;

    println!(
        "Created user: {} (role: {}, id: {})",
        username,
        role,
        &id[..8]
    );
    Ok(())
}

pub async fn users_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    println!("Deleted user {}", id);
    Ok(())
}

pub async fn users_set_enabled(db_path: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("UPDATE users SET enabled = ?2 WHERE id = ?1")
        .bind(id)
        .bind(enabled)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    println!(
        "User {} {}",
        id,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}
