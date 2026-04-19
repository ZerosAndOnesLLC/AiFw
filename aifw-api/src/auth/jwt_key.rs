//! JWT signing secret storage.
//!
//! The secret used to be kept in the `auth_config` SQLite table, which
//! made a stolen DB (backup leak, image snapshot, another SQL-read bug)
//! equivalent to total auth compromise. This module moves the secret to
//! its own file at `/var/db/aifw/jwt.key` with `0600` permissions.
//!
//! On startup [`load_or_create`]:
//!   1. If the key file exists, read and return it.
//!   2. Otherwise, migrate an existing DB-stored secret into the file
//!      (preserving currently-issued tokens across the upgrade), or
//!      generate a fresh 256-bit secret.
//!   3. Either way, delete the legacy `auth_config.jwt_secret` row so
//!      it can't regress.

use std::path::Path;
use tokio::fs;

/// Resolve the JWT signing secret, creating the key file on first run.
pub async fn load_or_create(
    path: &Path,
    pool: &sqlx::SqlitePool,
) -> Result<String, String> {
    if let Ok(contents) = fs::read_to_string(path).await {
        let secret = contents.trim().to_string();
        if !secret.is_empty() {
            // Best-effort cleanup of the legacy row on subsequent boots.
            let _ = sqlx::query("DELETE FROM auth_config WHERE key = 'jwt_secret'")
                .execute(pool)
                .await;
            return Ok(secret);
        }
    }

    // Migration path: adopt the DB-stored secret if present so existing
    // JWTs remain valid after the upgrade.
    let legacy: Option<(String,)> = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'jwt_secret'",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("read legacy jwt_secret: {e}"))?;

    let secret = match legacy {
        Some((s,)) if !s.is_empty() => s,
        _ => generate(),
    };

    write_restricted(path, &secret).await?;

    let _ = sqlx::query("DELETE FROM auth_config WHERE key = 'jwt_secret'")
        .execute(pool)
        .await;

    Ok(secret)
}

fn generate() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple(),
    )
}

async fn write_restricted(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        f.write_all(contents.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
            .await
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fresh_pool() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE auth_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn creates_file_on_first_run() {
        let dir = tempfile_dir();
        let path = dir.join("jwt.key");
        let pool = fresh_pool().await;
        let secret = load_or_create(&path, &pool).await.unwrap();
        assert!(!secret.is_empty());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.trim(), secret);
    }

    #[tokio::test]
    async fn second_call_returns_same_secret() {
        let dir = tempfile_dir();
        let path = dir.join("jwt.key");
        let pool = fresh_pool().await;
        let first = load_or_create(&path, &pool).await.unwrap();
        let second = load_or_create(&path, &pool).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn migrates_legacy_db_secret() {
        let dir = tempfile_dir();
        let path = dir.join("jwt.key");
        let pool = fresh_pool().await;
        sqlx::query(
            "INSERT INTO auth_config (key, value) VALUES ('jwt_secret', 'legacy-deadbeef')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let secret = load_or_create(&path, &pool).await.unwrap();
        assert_eq!(secret, "legacy-deadbeef");

        // Legacy row is scrubbed.
        let legacy: Option<(String,)> = sqlx::query_as::<_, (String,)>(
            "SELECT value FROM auth_config WHERE key = 'jwt_secret'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(legacy.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_file_has_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile_dir();
        let path = dir.join("jwt.key");
        let pool = fresh_pool().await;
        load_or_create(&path, &pool).await.unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aifw_jwt_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
