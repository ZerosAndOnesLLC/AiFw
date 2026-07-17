//! S3 (or S3-compatible) backup sync for config versions.
//!
//! When enabled, every new auto-snapshot is uploaded to the configured
//! bucket under a per-host prefix. The UI can list, diff, and import
//! (restore) archived versions from any date — no time-based pruning
//! applies on the S3 side; bucket lifecycle is the operator's job.
//!
//! Credentials: empty access_key/secret means "use the AWS environment
//! variables" (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, plus
//! `AWS_SESSION_TOKEN` when set). Otherwise the explicit key+secret
//! pair is used. Stored-in-DB secrets are returned masked via the API.
//!
//! PERF-I2 (#410): implemented with `rusty-s3` (a small sans-IO SigV4
//! signer) + the `reqwest` client we already ship, instead of the
//! aws-sdk-s3 stack — the SDK chain alone gated the whole workspace
//! build for ~15 s. The SDK's wider credential chain (profile files,
//! IMDS instance roles, SSO) was dropped with it; a firewall appliance
//! only ever used explicit keys or env vars.

use rusty_s3::actions::ListObjectsV2;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::time::Duration;

const TEST_KEY_SUFFIX: &str = ".aifw-connectivity-test";

/// Validity window for presigned request URLs — generous enough for slow
/// uplinks and retries, far below any replay-concern horizon.
const SIGN_TTL: Duration = Duration::from_secs(300);

/// Per-request timeout for all S3 HTTP calls.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// ============================================================================
// Config
// ============================================================================

/// Operator-facing S3 backup settings, persisted as the single row of the
/// `s3_backup_config` table and serialized over the REST API (the secret is
/// masked on read).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// Whether new config snapshots are uploaded to S3
    pub enabled: bool,
    /// Target bucket name (required when enabled)
    pub bucket: String,
    /// AWS region, e.g. "us-east-1"
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
    /// Leave empty to use the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
    /// environment variables. Fill in both to use explicit creds.
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

/// Create the single-row `s3_backup_config` table if missing and seed
/// row id 1 with defaults
pub async fn migrate(pool: &SqlitePool) -> aifw_common::Result<()> {
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

/// Read the stored config row; a missing row or query failure yields
/// `S3Config::default()` (disabled) rather than an error
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

/// Everything needed to issue signed S3 requests: the bucket/endpoint
/// descriptor, credentials, and a reqwest client.
struct S3Client {
    bucket: Bucket,
    creds: Credentials,
    http: reqwest::Client,
}

fn client(cfg: &S3Config) -> Result<S3Client, String> {
    if cfg.bucket.trim().is_empty() {
        return Err("bucket is required".into());
    }

    let endpoint: url::Url = match cfg.endpoint.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(ep) => ep
            .parse()
            .map_err(|e| format!("invalid endpoint '{ep}': {e}"))?,
        None => format!("https://s3.{}.amazonaws.com", cfg.region)
            .parse()
            .map_err(|e| format!("invalid region '{}': {e}", cfg.region))?,
    };
    let style = if cfg.path_style {
        UrlStyle::Path
    } else {
        UrlStyle::VirtualHost
    };
    let bucket = Bucket::new(endpoint, style, cfg.bucket.clone(), cfg.region.clone())
        .map_err(|e| format!("bucket config: {e}"))?;

    // Explicit creds win; otherwise fall back to the AWS env variables.
    let creds = match (
        cfg.access_key_id
            .as_deref()
            .filter(|s| !s.trim().is_empty()),
        cfg.secret_access_key
            .as_deref()
            .filter(|s| !s.trim().is_empty()),
    ) {
        (Some(ak), Some(sk)) => Credentials::new(ak, sk),
        _ => Credentials::from_env().ok_or_else(|| {
            "credentials required: set access key + secret, or the \
             AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables"
                .to_string()
        })?,
    };

    let http = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    Ok(S3Client {
        bucket,
        creds,
        http,
    })
}

/// Render a non-2xx S3 response into a bounded, human-readable error.
/// S3 error bodies are small XML documents that name the failing
/// permission (`AccessDenied`, `NoSuchBucket`, …), so a snippet is the
/// most useful thing to surface in the UI.
async fn error_text(resp: reqwest::Response) -> String {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();
    if snippet.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {snippet}")
    }
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

/// Build the S3 object key for a config version:
/// `<prefix><hostname>/<sanitized-timestamp>-v<version>.json`. Timestamp
/// comes first so lexicographic listing sorts chronologically.
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

/// Outcome of [`test_connection`], serialized to the UI
#[derive(Debug, Serialize)]
pub struct TestResult {
    /// True when write, read, and delete all succeeded
    pub ok: bool,
    /// Human-readable summary, or the first failing step's error
    pub message: String,
    /// Whether each subtest succeeded. Useful in the UI for showing exactly
    /// which permission is missing (e.g. "write ok, read failed").
    pub write: bool,
    /// s3:GetObject subtest succeeded
    pub read: bool,
    /// s3:DeleteObject subtest succeeded
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
    let c = match client(cfg) {
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

    let put_url = c.bucket.put_object(Some(&c.creds), &key).sign(SIGN_TTL);
    match c
        .http
        .put(put_url)
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body(payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => r.write = true,
        Ok(resp) => {
            r.message = format!("write failed: {}", error_text(resp).await);
            return r;
        }
        Err(e) => {
            r.message = format!("write failed: {e}");
            return r;
        }
    }

    let get_url = c.bucket.get_object(Some(&c.creds), &key).sign(SIGN_TTL);
    match c.http.get(get_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(_) => r.read = true,
            Err(e) => {
                r.message = format!("read drain failed: {e}");
                return r;
            }
        },
        Ok(resp) => {
            r.message = format!("read failed: {}", error_text(resp).await);
            return r;
        }
        Err(e) => {
            r.message = format!("read failed: {e}");
            return r;
        }
    }

    let del_url = c.bucket.delete_object(Some(&c.creds), &key).sign(SIGN_TTL);
    match c.http.delete(del_url).send().await {
        Ok(resp) if resp.status().is_success() => r.delete = true,
        Ok(resp) => {
            r.message = format!("delete failed: {}", error_text(resp).await);
            return r;
        }
        Err(e) => {
            r.message = format!("delete failed: {e}");
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

/// One archived config version listed from the bucket
#[derive(Debug, Clone, Serialize)]
pub struct RemoteObject {
    /// Full S3 object key
    pub key: String,
    /// Object size in bytes
    pub size: i64,
    /// S3 last-modified timestamp, when the API returned one
    pub last_modified: Option<String>,
}

/// List all config backups under the configured prefix (scoped to this host).
/// Returns up to `max` objects, newest-first.
pub async fn list(cfg: &S3Config, max: usize) -> Result<Vec<RemoteObject>, String> {
    let c = client(cfg)?;
    let prefix = format!("{}{}/", normalize_prefix(&cfg.prefix), hostname());
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut action = c.bucket.list_objects_v2(Some(&c.creds));
        action.with_prefix(prefix.as_str());
        if let Some(t) = token.as_deref() {
            action.with_continuation_token(t);
        }
        let url = action.sign(SIGN_TTL);
        let resp = c
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("list failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("list failed: {}", error_text(resp).await));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("list read failed: {e}"))?;
        let parsed =
            ListObjectsV2::parse_response(&text).map_err(|e| format!("list parse failed: {e}"))?;
        for obj in parsed.contents {
            if obj.key.ends_with(TEST_KEY_SUFFIX) {
                continue;
            }
            out.push(RemoteObject {
                key: obj.key,
                size: obj.size as i64,
                last_modified: Some(obj.last_modified),
            });
        }
        if out.len() >= max {
            break;
        }
        match parsed.next_continuation_token {
            Some(t) => token = Some(t),
            None => break,
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
    let c = client(cfg)?;
    let url = c.bucket.get_object(Some(&c.creds), key).sign(SIGN_TTL);
    let resp = c
        .http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("fetch failed: {}", error_text(resp).await));
    }
    resp.text().await.map_err(|e| e.to_string())
}

/// Upload one config version. Idempotent (PUT always succeeds).
pub async fn upload_version(
    cfg: &S3Config,
    version: i64,
    created_at: &str,
    config_json: &str,
) -> Result<String, String> {
    let c = client(cfg)?;
    let key = object_key(&cfg.prefix, version, created_at);
    let url = c.bucket.put_object(Some(&c.creds), &key).sign(SIGN_TTL);
    let resp = c
        .http
        .put(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(config_json.to_string())
        .send()
        .await
        .map_err(|e| format!("upload failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("upload failed: {}", error_text(resp).await));
    }
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
