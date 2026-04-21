//! S3 (or S3-compatible) backup sync for config versions.
//!
//! When enabled, every new auto-snapshot is uploaded to the configured
//! bucket under a per-host prefix. The UI can list, diff, and import
//! (restore) archived versions from any date — no time-based pruning
//! applies on the S3 side; bucket lifecycle is the operator's job.
//!
//! Credentials: empty access_key/secret means "use the AWS default
//! credential provider chain" — environment, `~/.aws/credentials`, or
//! the EC2/ECS instance role. Otherwise the explicit key+secret pair
//! is used. Stored-in-DB secrets are returned masked via the API.

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Object;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

const TEST_KEY_SUFFIX: &str = ".aifw-connectivity-test";
const APP_TAG: &str = "aifw-backup";

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub enabled: bool,
    pub bucket: String,
    pub region: String,
    /// Optional custom endpoint for S3-compatible providers (MinIO, Backblaze,
    /// Wasabi, etc). When empty, the default AWS endpoint for `region` is used.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Optional key prefix (e.g. "aifw/production/").
    #[serde(default)]
    pub prefix: String,
    /// When `true`, use path-style URLs (bucket in the path) instead of
    /// virtual-hosted. Required for most S3-compatible providers.
    #[serde(default)]
    pub path_style: bool,
    /// Leave empty to use the default AWS credential chain (env, profile,
    /// instance role). Fill in both to use explicit creds.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// Secret is write-only from the API. GET returns `""` if set, `null`
    /// otherwise — never the real value.
    #[serde(default)]
    pub secret_access_key: Option<String>,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bucket: String::new(),
            region: "us-east-1".into(),
            endpoint: None,
            prefix: String::new(),
            path_style: false,
            access_key_id: None,
            secret_access_key: None,
        }
    }
}

// ============================================================================
// Schema
// ============================================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS s3_backup_config (
            id                INTEGER PRIMARY KEY CHECK (id = 1),
            enabled           INTEGER NOT NULL DEFAULT 0,
            bucket            TEXT    NOT NULL DEFAULT '',
            region            TEXT    NOT NULL DEFAULT 'us-east-1',
            endpoint          TEXT,
            prefix            TEXT    NOT NULL DEFAULT '',
            path_style        INTEGER NOT NULL DEFAULT 0,
            access_key_id     TEXT,
            secret_access_key TEXT
        )"#,
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT OR IGNORE INTO s3_backup_config (id) VALUES (1)")
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load(pool: &SqlitePool) -> S3Config {
    sqlx::query_as::<_, (i64, String, String, Option<String>, String, i64, Option<String>, Option<String>)>(
        r#"SELECT enabled, bucket, region, endpoint, prefix, path_style, access_key_id, secret_access_key
             FROM s3_backup_config WHERE id = 1"#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(enabled, bucket, region, endpoint, prefix, path_style, ak, sk)| S3Config {
        enabled: enabled != 0,
        bucket,
        region,
        endpoint,
        prefix,
        path_style: path_style != 0,
        access_key_id: ak,
        secret_access_key: sk,
    })
    .unwrap_or_default()
}

/// Persist config. `secret_access_key = None` means "don't touch" —
/// `Some("")` means "clear". Any other value is stored verbatim.
pub async fn save(pool: &SqlitePool, cfg: &S3Config) -> Result<(), String> {
    let existing = load(pool).await;
    let final_secret = match cfg.secret_access_key.as_deref() {
        None => existing.secret_access_key,
        Some("") => None,
        Some(v) => Some(v.to_string()),
    };
    sqlx::query(
        r#"UPDATE s3_backup_config
              SET enabled=?, bucket=?, region=?, endpoint=?, prefix=?,
                  path_style=?, access_key_id=?, secret_access_key=?
            WHERE id=1"#,
    )
    .bind(cfg.enabled as i64)
    .bind(&cfg.bucket)
    .bind(&cfg.region)
    .bind(&cfg.endpoint)
    .bind(&cfg.prefix)
    .bind(cfg.path_style as i64)
    .bind(&cfg.access_key_id)
    .bind(&final_secret)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// Client
// ============================================================================

async fn client(cfg: &S3Config) -> Result<Client, String> {
    if cfg.bucket.trim().is_empty() {
        return Err("bucket is required".into());
    }
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new(cfg.region.clone()));

    // Explicit creds override the default chain. Otherwise AWS SDK walks
    // env -> profile -> instance role / container role -> SSO etc.
    if let (Some(ak), Some(sk)) = (
        cfg.access_key_id
            .as_deref()
            .filter(|s| !s.trim().is_empty()),
        cfg.secret_access_key
            .as_deref()
            .filter(|s| !s.trim().is_empty()),
    ) {
        let creds = Credentials::new(ak, sk, None, None, APP_TAG);
        loader = loader.credentials_provider(SharedCredentialsProvider::new(creds));
    }

    if let Some(ep) = cfg.endpoint.as_deref().filter(|s| !s.trim().is_empty()) {
        loader = loader.endpoint_url(ep);
    }

    let sdk_cfg = loader.load().await;
    let mut builder = aws_sdk_s3::config::Builder::from(&sdk_cfg);
    if cfg.path_style {
        builder = builder.force_path_style(true);
    }
    Ok(Client::from_conf(builder.build()))
}

// ============================================================================
// Keys / naming
// ============================================================================

fn hostname() -> String {
    hostname_fallback::gethostname().unwrap_or_else(|| "aifw".to_string())
}

fn normalize_prefix(p: &str) -> String {
    let p = p.trim().trim_matches('/');
    if p.is_empty() {
        String::new()
    } else {
        format!("{p}/")
    }
}

pub fn object_key(prefix: &str, version: i64, created_at: &str) -> String {
    // Sortable, collision-free, timestamp-first so lexicographic listing
    // returns newest-last (or reverse via `start-after`).
    let safe_ts: String = created_at
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else if c == ':' {
                '-'
            } else if c == 'T' {
                'T'
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "{}{}/{}-v{:06}.json",
        normalize_prefix(prefix),
        hostname(),
        safe_ts,
        version
    )
}

// ============================================================================
// Operations
// ============================================================================

#[derive(Debug, Serialize)]
pub struct TestResult {
    pub ok: bool,
    pub message: String,
    /// Whether each subtest succeeded. Useful in the UI for showing exactly
    /// which permission is missing (e.g. "write ok, read failed").
    pub write: bool,
    pub read: bool,
    pub delete: bool,
}

/// Write → read → delete a small test object. Proves that the credentials
/// have s3:PutObject, s3:GetObject, and s3:DeleteObject on the target
/// prefix. Each step is reported independently so the UI can explain which
/// IAM permission is missing.
pub async fn test_connection(cfg: &S3Config) -> TestResult {
    let mut r = TestResult {
        ok: false,
        message: String::new(),
        write: false,
        read: false,
        delete: false,
    };
    let c = match client(cfg).await {
        Ok(c) => c,
        Err(e) => {
            r.message = format!("config error: {e}");
            return r;
        }
    };
    let key = format!(
        "{}{}{}",
        normalize_prefix(&cfg.prefix),
        hostname(),
        TEST_KEY_SUFFIX
    );
    let payload = format!(
        "aifw-connectivity-test host={} ts={}\n",
        hostname(),
        chrono::Utc::now().to_rfc3339(),
    );

    match c
        .put_object()
        .bucket(&cfg.bucket)
        .key(&key)
        .body(ByteStream::from(payload.as_bytes().to_vec()))
        .content_type("text/plain")
        .send()
        .await
    {
        Ok(_) => r.write = true,
        Err(e) => {
            r.message = format!("write failed: {}", summarize_sdk_error(&e));
            return r;
        }
    }

    match c.get_object().bucket(&cfg.bucket).key(&key).send().await {
        Ok(obj) => match obj.body.collect().await {
            Ok(_) => r.read = true,
            Err(e) => {
                r.message = format!("read drain failed: {e}");
                return r;
            }
        },
        Err(e) => {
            r.message = format!("read failed: {}", summarize_sdk_error(&e));
            return r;
        }
    }

    match c.delete_object().bucket(&cfg.bucket).key(&key).send().await {
        Ok(_) => r.delete = true,
        Err(e) => {
            r.message = format!("delete failed: {}", summarize_sdk_error(&e));
            return r;
        }
    }

    r.ok = true;
    r.message = format!(
        "S3 connectivity OK (wrote, read, and deleted s3://{}/{})",
        cfg.bucket, key
    );
    r
}

fn summarize_sdk_error<E: std::fmt::Display, R>(err: &aws_sdk_s3::error::SdkError<E, R>) -> String {
    format!("{err}")
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteObject {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<String>,
}

/// List all config backups under the configured prefix (scoped to this host).
/// Returns up to `max` objects, newest-first.
pub async fn list(cfg: &S3Config, max: usize) -> Result<Vec<RemoteObject>, String> {
    let c = client(cfg).await?;
    let prefix = format!("{}{}/", normalize_prefix(&cfg.prefix), hostname());
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = c.list_objects_v2().bucket(&cfg.bucket).prefix(&prefix);
        if let Some(t) = token.as_ref() {
            req = req.continuation_token(t);
        }
        let resp = req.send().await.map_err(|e| summarize_sdk_error(&e))?;
        for Object {
            key: k,
            size,
            last_modified,
            ..
        } in resp.contents.unwrap_or_default()
        {
            if let Some(k) = k {
                if k.ends_with(TEST_KEY_SUFFIX) {
                    continue;
                }
                out.push(RemoteObject {
                    key: k,
                    size: size.unwrap_or(0),
                    last_modified: last_modified.map(|d| d.to_string()),
                });
            }
        }
        if out.len() >= max {
            break;
        }
        if resp.is_truncated.unwrap_or(false) {
            token = resp.next_continuation_token;
        } else {
            break;
        }
    }
    // Sort newest-first (keys embed timestamps).
    out.sort_by(|a, b| b.key.cmp(&a.key));
    out.truncate(max);
    Ok(out)
}

/// Fetch one archived config JSON by its S3 key. Caller is responsible for
/// de-serializing into `FirewallConfig`.
pub async fn fetch(cfg: &S3Config, key: &str) -> Result<String, String> {
    let c = client(cfg).await?;
    let obj = c
        .get_object()
        .bucket(&cfg.bucket)
        .key(key)
        .send()
        .await
        .map_err(|e| summarize_sdk_error(&e))?;
    let body = obj.body.collect().await.map_err(|e| e.to_string())?;
    String::from_utf8(body.into_bytes().to_vec()).map_err(|e| e.to_string())
}

/// Upload one config version. Idempotent (PUT always succeeds).
pub async fn upload_version(
    cfg: &S3Config,
    version: i64,
    created_at: &str,
    config_json: &str,
) -> Result<String, String> {
    let c = client(cfg).await?;
    let key = object_key(&cfg.prefix, version, created_at);
    c.put_object()
        .bucket(&cfg.bucket)
        .key(&key)
        .body(ByteStream::from(config_json.as_bytes().to_vec()))
        .content_type("application/json")
        .send()
        .await
        .map_err(|e| summarize_sdk_error(&e))?;
    Ok(key)
}

// ============================================================================
// Tiny hostname helper — avoids pulling `hostname` crate globally.
// ============================================================================

mod hostname_fallback {
    pub fn gethostname() -> Option<String> {
        std::env::var("HOSTNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| {
                        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if s.is_empty() { None } else { Some(s) }
                    })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_prefix_handles_edges() {
        assert_eq!(normalize_prefix(""), "");
        assert_eq!(normalize_prefix("/"), "");
        assert_eq!(normalize_prefix("aifw"), "aifw/");
        assert_eq!(normalize_prefix("/aifw/prod/"), "aifw/prod/");
    }

    #[test]
    fn object_key_is_sortable() {
        let a = object_key("p", 1, "2026-04-15T10:00:00Z");
        let b = object_key("p", 2, "2026-04-15T11:00:00Z");
        assert!(a < b, "{a} should sort before {b}");
    }
}
