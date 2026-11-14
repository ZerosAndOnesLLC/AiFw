//! The root-only on-box CLI key.
//!
//! When `aifw` runs as root on the appliance with no other credential, it
//! mints an admin API key for itself straight into the database (root owns
//! the box already, so this grants nothing new) and keeps it in
//! `/usr/local/etc/aifw/cli.key` (0600 root). That is what lets the
//! maintenance cron and the console menu run `aifw update …` against the
//! API without anyone logging in.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::Context as _;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use crate::cli::onbox::OnBox;

/// Must match `aifw_api::auth::CLI_LOCAL_KEY_NAME` (reserved there, so it
/// can't be minted, listed or revoked through the normal key endpoints).
pub const CLI_KEY_NAME: &str = "aifw-cli-local";
/// Locked service account that owns the key (no password login).
pub const CLI_USERNAME: &str = "aifw-cli";

/// Mint the on-box CLI key: write the DB rows, then the key file (0600).
/// Returns the key. Serialized with a lock file: when `rotate` is false and
/// another process minted a key while we waited, that key is returned
/// instead of minting a second one.
pub fn provision_cli_key(onbox: &OnBox, rotate: bool) -> anyhow::Result<String> {
    // Called from sync resolution code; run the async DB work on a scoped
    // runtime-independent thread so it works inside or outside tokio.
    let onbox = onbox.clone();
    std::thread::spawn(move || {
        let _lock = lock_file(&onbox)?;
        if !rotate && let Some(k) = crate::cli::onbox::read_key(&onbox.cli_key) {
            return Ok(k);
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(provision_async(&onbox))
    })
    .join()
    .map_err(|_| anyhow::anyhow!("CLI key provisioning panicked"))?
}

async fn provision_async(onbox: &OnBox) -> anyhow::Result<String> {
    let key = format!(
        "aifw_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let prefix = key[..12].to_string();
    let hash = aifw_common::password::hash_password(&key)
        .map_err(|e| anyhow::anyhow!("hashing CLI key: {e}"))?;

    precreate_sidecars(&onbox.db);
    let opts = SqliteConnectOptions::new()
        .filename(&onbox.db)
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_secs(10));
    let pool = SqlitePool::connect_with(opts)
        .await
        .with_context(|| format!("opening {}", onbox.db.display()))?;

    let now = chrono::Utc::now().to_rfc3339();
    // IMMEDIATE takes the write lock up front, so a concurrent minter (or
    // the API) can't interleave between our read of the user and the write.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let user_id: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?1")
        .bind(CLI_USERNAME)
        .fetch_optional(&mut *tx)
        .await?;
    let user_id = match user_id {
        Some(id) => id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            // Random password nobody knows; 'system' provider keeps the
            // account out of the first-admin registration check.
            let dummy = aifw_common::password::hash_password(&format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            ))
            .map_err(|e| anyhow::anyhow!("hashing: {e}"))?;
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, role, role_id, created_at) \
                 VALUES (?1, ?2, ?3, 0, 'system', 'admin', 'builtin-admin', ?4)",
            )
            .bind(&id)
            .bind(CLI_USERNAME)
            .bind(&dummy)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            id
        }
    };
    sqlx::query("DELETE FROM api_keys WHERE name = ?1")
        .bind(CLI_KEY_NAME)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(CLI_KEY_NAME)
    .bind(&hash)
    .bind(&prefix)
    .bind(&user_id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    pool.close().await;
    restore_db_sidecar_owner(&onbox.db);

    crate::cli::config::write_atomic(&onbox.cli_key, format!("{key}\n").as_bytes(), 0o600)
        .with_context(|| format!("writing {}", onbox.cli_key.display()))?;
    Ok(key)
}

/// Exclusive lock beside the key file, held for the whole mint.
fn lock_file(onbox: &OnBox) -> anyhow::Result<nix::fcntl::Flock<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = onbox
        .cli_key
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent", onbox.cli_key.display()))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(".cli.key.lock"))
        .context("opening the CLI key lock")?;
    nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, e)| anyhow::anyhow!("locking the CLI key: {e}"))
}

/// Create missing `-wal`/`-shm` sidecars up front with the database
/// file's owner, so opening the database as root never leaves root-owned
/// sidecars (even briefly) that would lock the `aifw` service user out.
fn precreate_sidecars(db: &Path) {
    let Ok(meta) = std::fs::metadata(db) else {
        return;
    };
    for suffix in ["-wal", "-shm"] {
        let side = db.with_file_name(format!(
            "{}{suffix}",
            db.file_name().and_then(|n| n.to_str()).unwrap_or("aifw.db")
        ));
        if side.exists() {
            continue;
        }
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&side);
        if created.is_ok()
            && let Err(e) = std::os::unix::fs::chown(&side, Some(meta.uid()), Some(meta.gid()))
        {
            tracing::warn!(path = %side.display(), error = %e, "could not set database sidecar owner");
        }
    }
}

/// Opening the database as root can create `-wal`/`-shm` sidecars owned by
/// root, which would lock the `aifw` service user out. Give them the main
/// database file's owner.
fn restore_db_sidecar_owner(db: &Path) {
    let Ok(meta) = std::fs::metadata(db) else {
        return;
    };
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = db.with_file_name(format!(
            "{}{suffix}",
            db.file_name().and_then(|n| n.to_str()).unwrap_or("aifw.db")
        ));
        if let Ok(m) = std::fs::metadata(&side)
            && (m.uid() != meta.uid() || m.gid() != meta.gid())
            && let Err(e) = std::os::unix::fs::chown(&side, Some(meta.uid()), Some(meta.gid()))
        {
            tracing::warn!(path = %side.display(), error = %e, "could not restore database sidecar owner");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    async fn scratch_db(path: &Path) {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        sqlx::query(aifw_common::schemas::USERS_CREATE)
            .execute(&pool)
            .await
            .unwrap();
        // USERS_CREATE predates RBAC; the API's migration adds these.
        for (col, def) in [
            ("role", "TEXT NOT NULL DEFAULT 'admin'"),
            ("role_id", "TEXT"),
            ("enabled", "INTEGER NOT NULL DEFAULT 1"),
        ] {
            aifw_core::schema::add_column_if_missing(&pool, "users", col, def)
                .await
                .unwrap();
        }
        sqlx::query(aifw_common::schemas::API_KEYS_CREATE)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    async fn mints_and_rotates() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-key-prov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let onbox = OnBox {
            cert: dir.join("cert.pem"),
            cli_key: dir.join("etc").join("cli.key"),
            daemon_key: dir.join("daemon.key"),
            db: dir.join("aifw.db"),
        };
        scratch_db(&onbox.db).await;

        let k1 = provision_cli_key(&onbox, false).unwrap();
        assert!(k1.starts_with("aifw_") && k1.len() == 69);
        assert_eq!(std::fs::read_to_string(&onbox.cli_key).unwrap().trim(), k1);
        let mode = std::fs::metadata(&onbox.cli_key)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        // Without rotate, an existing key is reused (another process won).
        assert_eq!(provision_cli_key(&onbox, false).unwrap(), k1);
        let k2 = provision_cli_key(&onbox, true).unwrap();
        assert_ne!(k1, k2, "rotates");

        let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&onbox.db))
            .await
            .unwrap();
        let (keys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM api_keys WHERE name = ?1")
            .bind(CLI_KEY_NAME)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(keys, 1, "old key replaced");
        let (users, provider, role): (i64, String, String) =
            sqlx::query_as("SELECT COUNT(*), auth_provider, role FROM users WHERE username = ?1")
                .bind(CLI_USERNAME)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (users, provider.as_str(), role.as_str()),
            (1, "system", "admin")
        );
        let (hash,): (String,) = sqlx::query_as("SELECT key_hash FROM api_keys WHERE name = ?1")
            .bind(CLI_KEY_NAME)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(aifw_common::password::verify_password(&k2, &hash));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_db_is_an_error() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-key-missing-{}", std::process::id()));
        let onbox = OnBox {
            cert: dir.join("c"),
            cli_key: dir.join("k"),
            daemon_key: dir.join("d"),
            db: dir.join("nope.db"),
        };
        assert!(provision_cli_key(&onbox, false).is_err());
        assert!(!onbox.cli_key.exists());
    }
}
