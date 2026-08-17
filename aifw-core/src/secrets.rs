//! Column-level encryption for secrets stored in SQLite (#298 / SEC-M1).
//!
//! Integration secrets (OAuth client secrets, S3/SMTP credentials, TSIG,
//! WireGuard private/preshared keys, CARP + IPsec PSKs, cluster peer API
//! keys, ACME DNS tokens, AI provider keys, TOTP seeds) used to sit in the
//! database in cleartext, so any DB snapshot leak — backup, disk image, an
//! SQL-read bug elsewhere — handed over every credential the appliance
//! holds. They are now sealed with AES-256-GCM under a master key that
//! lives outside the database.
//!
//! # Wire format
//! `enc:v1:<base64(nonce(12) ‖ ciphertext ‖ tag(16))>` — a random 96-bit
//! nonce per value. Anything without the `enc:v1:` prefix is treated as a
//! legacy plaintext value by [`open`], so an upgraded appliance keeps
//! working immediately and every value becomes sealed the next time it is
//! written (each call site seals on write, opens on read).
//!
//! # Master key
//! 32 random bytes, hex-encoded, in `/var/db/aifw/secrets.key` (0600, next
//! to `jwt.key`). Loaded lazily on first use by whichever AiFw process
//! needs it and created — atomically, so two processes racing on first
//! boot can't end up with two keys — by the first process that has to
//! *seal* something. Override the path with `AIFW_SECRETS_KEY_FILE`
//! (tests, dev hosts). #108 (TPM-sealed key) swaps the source of these
//! 32 bytes; nothing above this module needs to change for that.
//!
//! When no key file exists and one cannot be created (read-only dev host,
//! unit tests), the process falls back to an ephemeral in-memory key and
//! logs a warning: values round-trip within the process but will not
//! survive a restart. Production appliances always have a writable
//! `/var/db/aifw`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tracing::{info, warn};

use crate::{CoreError, Result};

/// Prefix identifying a sealed value.
pub const PREFIX: &str = "enc:v1:";
/// Default location of the master key.
pub const DEFAULT_KEY_PATH: &str = "/var/db/aifw/secrets.key";
/// Environment override for the key path (tests / dev hosts).
pub const KEY_PATH_ENV: &str = "AIFW_SECRETS_KEY_FILE";

const KEY_LEN: usize = 32;

static KEY: OnceLock<LessSafeKey> = OnceLock::new();
static CONFIGURED_PATH: OnceLock<PathBuf> = OnceLock::new();
/// Set when the process fell back to an in-memory key (no readable or
/// creatable key file). Nothing sealed under it survives a restart, so the
/// legacy-row migration refuses to run in that state.
static EPHEMERAL: AtomicBool = AtomicBool::new(false);

/// Point this process at a specific key file. Binaries call it once at
/// startup with `<db dir>/secrets.key` so a dev run with `--db
/// ./scratch/aifw.db` gets a persistent key beside its database instead of
/// falling back to an ephemeral one. No effect after the key is loaded or
/// if `AIFW_SECRETS_KEY_FILE` is set.
pub fn set_key_path(path: PathBuf) {
    let _ = CONFIGURED_PATH.set(path);
}

/// Derive the key path from a database path (`<db dir>/secrets.key`) and
/// configure it. In-memory / relative-less DB paths leave the default.
pub fn configure_from_db_path(db_path: &Path) {
    if let Some(dir) = db_path.parent()
        && !dir.as_os_str().is_empty()
    {
        set_key_path(dir.join("secrets.key"));
    }
}

/// Path the master key is read from / written to: env override, then the
/// path set by [`set_key_path`], then [`DEFAULT_KEY_PATH`].
pub fn key_path() -> PathBuf {
    if let Some(p) = std::env::var_os(KEY_PATH_ENV) {
        return PathBuf::from(p);
    }
    CONFIGURED_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KEY_PATH))
}

/// True when this process is using an ephemeral (non-persistent) key.
pub fn is_ephemeral() -> bool {
    EPHEMERAL.load(Ordering::Relaxed)
}

/// True for values written by [`seal`].
pub fn is_sealed(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// Encrypt `plaintext` for storage. Empty input stays empty (an unset
/// secret is not a secret, and callers test for emptiness).
pub fn seal(plaintext: &str) -> Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let key = load_key(true)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| CoreError::Other(format!("secrets: nonce generation failed: {e}")))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| CoreError::Other("secrets: encryption failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(format!("{PREFIX}{}", B64.encode(out)))
}

/// Decrypt a stored value. Values without the [`PREFIX`] are returned as-is
/// (legacy plaintext from before #298).
pub fn open(stored: &str) -> Result<String> {
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        return Ok(stored.to_string());
    };
    let raw = B64
        .decode(b64)
        .map_err(|e| CoreError::Other(format!("secrets: malformed sealed value: {e}")))?;
    if raw.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(CoreError::Other("secrets: sealed value too short".into()));
    }
    let key = load_key(false)?;
    let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| CoreError::Other("secrets: bad nonce".into()))?;
    let mut buf = ct.to_vec();
    let pt = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| {
            CoreError::Other(
                "secrets: decryption failed — the master key does not match this value \
                 (was /var/db/aifw/secrets.key replaced or restored from another box?)"
                    .into(),
            )
        })?;
    String::from_utf8(pt.to_vec())
        .map_err(|_| CoreError::Other("secrets: decrypted value is not UTF-8".into()))
}

/// [`open`] for `Option<String>` columns.
pub fn open_opt(stored: Option<String>) -> Result<Option<String>> {
    stored.map(|s| open(&s)).transpose()
}

/// [`open`] that never fails the caller: on a decryption error it logs and
/// returns an empty string, so a list/status page still renders and the
/// operator sees a blank credential rather than a 500. Use for read paths
/// where the secret is display-masked anyway; use [`open`] where the value
/// is about to be *used*.
pub fn open_lossy(stored: &str) -> String {
    match open(stored) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "secrets: could not open a stored secret; treating as unset");
            String::new()
        }
    }
}

/// [`open_lossy`] for `Option<String>` columns.
pub fn open_opt_lossy(stored: Option<String>) -> Option<String> {
    stored.map(|s| open_lossy(&s))
}

/// Error adapter for engines that still use `aifw_common::AifwError`
/// (`ha.rs`, `vpn.rs`): `secrets::seal(v).map_err(secrets::to_common)?`.
pub fn to_common(e: CoreError) -> aifw_common::AifwError {
    aifw_common::AifwError::Crypto(e.to_string())
}

/// Re-seal a value that may still be legacy plaintext, for one-shot
/// migrations. Returns `None` when the value is already sealed or empty
/// (nothing to write back).
pub fn reseal_if_plain(stored: &str) -> Result<Option<String>> {
    if stored.is_empty() || is_sealed(stored) {
        return Ok(None);
    }
    seal(stored).map(Some)
}

fn load_key(create: bool) -> Result<&'static LessSafeKey> {
    if let Some(k) = KEY.get() {
        return Ok(k);
    }
    let path = key_path();
    let bytes = match read_key_file(&path) {
        Ok(Some(b)) => b,
        Ok(None) if create => match create_key_file(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "secrets: cannot create master key file — using an ephemeral key; \
                     sealed values will NOT survive a restart"
                );
                EPHEMERAL.store(true, Ordering::Relaxed);
                random_key()?
            }
        },
        Ok(None) => {
            return Err(CoreError::Config(format!(
                "secrets: master key {} does not exist yet — a sealed value cannot be \
                 opened before aifw-api has created the key",
                path.display()
            )));
        }
        Err(e) => return Err(e),
    };
    let unbound = UnboundKey::new(&AES_256_GCM, &bytes)
        .map_err(|_| CoreError::Config("secrets: master key has the wrong length".into()))?;
    let _ = KEY.set(LessSafeKey::new(unbound));
    // Another thread may have won the race; both loaded the same file.
    Ok(KEY
        .get()
        .expect("KEY set just above or by a concurrent loader"))
}

fn random_key() -> Result<[u8; KEY_LEN]> {
    let mut k = [0u8; KEY_LEN];
    getrandom::fill(&mut k)
        .map_err(|e| CoreError::Other(format!("secrets: key generation failed: {e}")))?;
    Ok(k)
}

fn read_key_file(path: &Path) -> Result<Option<[u8; KEY_LEN]>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let raw = hex::decode(s.trim()).map_err(|_| {
                CoreError::Config(format!("secrets: {} is not hex", path.display()))
            })?;
            let arr: [u8; KEY_LEN] = raw.try_into().map_err(|_| {
                CoreError::Config(format!(
                    "secrets: {} must hold exactly {KEY_LEN} bytes",
                    path.display()
                ))
            })?;
            Ok(Some(arr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CoreError::Io(e)),
    }
}

/// Create the key file atomically (create-new semantics). If another
/// process created it first, adopt that key instead of ours.
fn create_key_file(path: &Path) -> Result<[u8; KEY_LEN]> {
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let key = random_key()?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(hex::encode(key).as_bytes())?;
            f.sync_all()?;
            drop(f);
            fix_owner(path);
            info!(path = %path.display(), "secrets: master key created");
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race — read what the winner wrote (it may still be
            // mid-write for a moment; the file is tiny and fsync'd, retry
            // briefly).
            for _ in 0..20 {
                if let Ok(Some(k)) = read_key_file(path) {
                    return Ok(k);
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(CoreError::Config(format!(
                "secrets: {} exists but could not be read",
                path.display()
            )))
        }
        Err(e) => Err(CoreError::Io(e)),
    }
}

/// When a root-run process (aifw CLI, aifw-setup) creates the key, hand it
/// to the `aifw` service user so aifw-api / aifw-daemon can read it.
/// Best-effort: as a non-root user, or on hosts without an `aifw` user
/// (dev), chown simply fails and the file keeps its creator's ownership.
fn fix_owner(path: &Path) {
    let out = std::process::Command::new("chown")
        .arg("aifw:aifw")
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if let Ok(st) = out
        && st.success()
    {
        info!(path = %path.display(), "secrets: master key handed to the aifw user");
    }
}

/// (table, secret column, primary-key column) for every secret the code
/// seals. [`seal_legacy_rows`] walks this list; keep it in sync when a new
/// call site starts sealing a column.
pub const SEALED_COLUMNS: &[(&str, &str, &str)] = &[
    ("oauth_providers", "client_secret", "id"),
    ("s3_backup_config", "secret_access_key", "id"),
    ("smtp_notify_config", "password", "id"),
    ("cluster_nodes", "peer_api_key", "id"),
    ("carp_vips", "password", "id"),
    ("wg_tunnels", "private_key", "id"),
    ("wg_peers", "preshared_key", "id"),
    ("wg_peers", "client_private_key", "id"),
    ("ipsec_tunnels", "psk", "id"),
    ("ipsec_tunnels", "local_key_pem", "id"),
    ("acme_dns_provider", "api_token", "id"),
    ("acme_dns_provider", "aws_secret_key", "id"),
    ("users", "totp_secret", "id"),
    // Config-history snapshots embed every secret above in one JSON blob.
    ("config_versions", "config_json", "version"),
];

/// Key/value tables whose *value* is a secret for the listed keys.
/// (table, key column, value column, key match — `=` literal or `LIKE`).
pub const SEALED_KV: &[(&str, &str, &str, &str)] = &[
    ("dhcp_ddns_config", "key", "value", "tsig_secret"),
    ("auth_config", "key", "value", "ai_%_api_key"),
];

/// One-shot upgrade pass: seal every legacy plaintext secret still in the
/// database. Runs at aifw-api startup after the schema migrations; each
/// later start finds nothing to do. Skipped (with a warning) when the
/// process only has an ephemeral key — sealing rows under a key that dies
/// with the process would lock the operator out of their own secrets.
/// Missing tables/columns (older DBs, other crates' engines not yet
/// migrated) are ignored. Returns the number of values sealed.
pub async fn seal_legacy_rows(pool: &sqlx::SqlitePool) -> usize {
    // Force key load (creating the file if needed) so we know whether we
    // are persistent before touching a single row.
    if load_key(true).is_err() || is_ephemeral() {
        warn!("secrets: no persistent master key — leaving legacy plaintext rows untouched");
        return 0;
    }
    seal_legacy_rows_unchecked(pool).await
}

/// [`seal_legacy_rows`] without the persistence guard. Exposed for tests
/// (which run under an ephemeral key); production code must call
/// [`seal_legacy_rows`].
#[doc(hidden)]
pub async fn seal_legacy_rows_unchecked(pool: &sqlx::SqlitePool) -> usize {
    let mut sealed = 0usize;
    for (table, col, pk) in SEALED_COLUMNS {
        // CAST: some PKs are INTEGER (s3/smtp singleton rows, acme
        // providers), others TEXT uuids; the UPDATE below relies on SQLite
        // column affinity to match the text back to an integer id.
        let select = format!(
            "SELECT CAST({pk} AS TEXT), {col} FROM {table} WHERE {col} IS NOT NULL AND {col} != '' AND {col} NOT LIKE '{PREFIX}%'"
        );
        let rows: Vec<(String, String)> = match sqlx::query_as(sqlx::AssertSqlSafe(select))
            .fetch_all(pool)
            .await
        {
            Ok(r) => r,
            Err(_) => continue, // table/column absent on this DB
        };
        for (id, plain) in rows {
            let Ok(Some(enc)) = reseal_if_plain(&plain) else {
                continue;
            };
            let update = format!("UPDATE {table} SET {col} = ?1 WHERE {pk} = ?2");
            match sqlx::query(sqlx::AssertSqlSafe(update))
                .bind(&enc)
                .bind(&id)
                .execute(pool)
                .await
            {
                Ok(_) => sealed += 1,
                Err(e) => warn!(table, col, error = %e, "secrets: legacy row re-seal failed"),
            }
        }
    }
    for (table, kcol, vcol, pat) in SEALED_KV {
        let op = if pat.contains('%') { "LIKE" } else { "=" };
        let select = format!(
            "SELECT {kcol}, {vcol} FROM {table} WHERE {kcol} {op} ?1 AND {vcol} != '' AND {vcol} NOT LIKE '{PREFIX}%'"
        );
        let rows: Vec<(String, String)> = match sqlx::query_as(sqlx::AssertSqlSafe(select))
            .bind(pat)
            .fetch_all(pool)
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        for (k, plain) in rows {
            let Ok(Some(enc)) = reseal_if_plain(&plain) else {
                continue;
            };
            let update = format!("UPDATE {table} SET {vcol} = ?1 WHERE {kcol} = ?2");
            match sqlx::query(sqlx::AssertSqlSafe(update))
                .bind(&enc)
                .bind(&k)
                .execute(pool)
                .await
            {
                Ok(_) => sealed += 1,
                Err(e) => warn!(table, key = %k, error = %e, "secrets: legacy row re-seal failed"),
            }
        }
    }
    if sealed > 0 {
        info!(
            sealed,
            "secrets: legacy plaintext secrets sealed at rest (#298)"
        );
    }
    sealed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_legacy_passthrough() {
        let sealed = seal("hunter2").unwrap();
        assert!(is_sealed(&sealed));
        assert_ne!(sealed, "hunter2");
        assert_eq!(open(&sealed).unwrap(), "hunter2");
        // Fresh nonce each time
        assert_ne!(seal("hunter2").unwrap(), sealed);
        // Legacy plaintext passes through
        assert_eq!(open("plain-old-secret").unwrap(), "plain-old-secret");
        assert!(!is_sealed("plain-old-secret"));
        // Empty stays empty
        assert_eq!(seal("").unwrap(), "");
        assert_eq!(open("").unwrap(), "");
        assert_eq!(open_opt(None).unwrap(), None);
    }

    #[test]
    fn tampering_is_detected() {
        let sealed = seal("payload").unwrap();
        let mut bytes = B64.decode(&sealed[PREFIX.len()..]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{PREFIX}{}", B64.encode(bytes));
        assert!(open(&tampered).is_err());
        assert_eq!(open_lossy(&tampered), "");
        assert!(open("enc:v1:not-base64!!").is_err());
        assert!(open("enc:v1:AAAA").is_err());
    }

    #[tokio::test]
    async fn legacy_rows_get_sealed_once() {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        // Plaintext rows in a mix of TEXT-pk and INTEGER-pk tables plus a KV table.
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, created_at)
             VALUES ('u1', 'alice', 'x', 1, 'JBSWY3DPEHPK3PXP', 'local', 'now')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO auth_config (key, value) VALUES ('ai_openai_api_key', 'sk-plain')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO auth_config (key, value) VALUES ('ai_openai_model', 'gpt')")
            .execute(pool)
            .await
            .unwrap();
        crate::acme::migrate(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO acme_dns_provider (name, kind, api_token, aws_secret_key, zone, extra)
             VALUES ('cf', 'cloudflare', 'tok-plain', NULL, 'example.com', '{}')",
        )
        .execute(pool)
        .await
        .unwrap();

        let n = seal_legacy_rows_unchecked(pool).await;
        assert_eq!(n, 3, "totp_secret + ai api key + acme token");

        let (totp,): (String,) = sqlx::query_as("SELECT totp_secret FROM users WHERE id = 'u1'")
            .fetch_one(pool)
            .await
            .unwrap();
        assert!(is_sealed(&totp));
        assert_eq!(open(&totp).unwrap(), "JBSWY3DPEHPK3PXP");
        let (ai,): (String,) =
            sqlx::query_as("SELECT value FROM auth_config WHERE key = 'ai_openai_api_key'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(is_sealed(&ai));
        let (model,): (String,) =
            sqlx::query_as("SELECT value FROM auth_config WHERE key = 'ai_openai_model'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(model, "gpt", "non-secret KV rows untouched");
        let (tok,): (String,) =
            sqlx::query_as("SELECT api_token FROM acme_dns_provider WHERE name = 'cf'")
                .fetch_one(pool)
                .await
                .unwrap();
        assert!(is_sealed(&tok), "INTEGER-pk table row sealed");
        assert_eq!(open(&tok).unwrap(), "tok-plain");

        // Idempotent
        assert_eq!(seal_legacy_rows_unchecked(pool).await, 0);
    }

    #[test]
    fn reseal_only_touches_plaintext() {
        assert!(reseal_if_plain("").unwrap().is_none());
        let sealed = seal("x").unwrap();
        assert!(reseal_if_plain(&sealed).unwrap().is_none());
        let re = reseal_if_plain("x").unwrap().unwrap();
        assert!(is_sealed(&re));
        assert_eq!(open(&re).unwrap(), "x");
    }
}
