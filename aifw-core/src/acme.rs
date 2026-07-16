//! ACME / Let's Encrypt cert manager.
//!
//! Issues and renews TLS certificates from any ACME v2 CA, with first-class
//! DNS-01 support so wildcard certs (`*.example.com`) can be obtained for
//! internal services that aren't reachable from the public internet.
//!
//! ## Why DNS-01 is the priority
//! Wildcard certs require DNS-01 — HTTP-01 cannot validate `*.example.com`.
//! For an appliance that fronts many internal services from one cert, that
//! makes DNS-01 the default path.
//!
//! ## Architecture
//! - **Schema** lives here. Tables: account, certs, DNS providers, export
//!   targets. Engine functions read/write rows + drive the ACME flow via
//!   `instant_acme`.
//! - **Renewal scheduler** lives in `aifw-daemon` (per the project rule that
//!   background workers do not run in the API process). The daemon ticks
//!   daily and calls `renew_due()` here.
//! - **HTTP handlers** live in `aifw-api/src/acme.rs` — thin CRUD shims.
//!
//! ## Cred storage
//! ACME account keys, DNS provider API tokens, and cert private keys are
//! stored in SQLite. Sensitive columns are returned MASKED via the API
//! (write-only — `null` means "unchanged" on update; empty string means
//! "clear"). Same dance as `s3_backup` and `smtp_notify`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

// =============================================================================
// Public types — mirrored to the API + UI
// =============================================================================

/// One ACME account per (CA directory URL, contact email) pair. The account
/// key is regenerated on first use; `key_pem` persists it across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    /// Row id in `acme_account`
    pub id: i64,
    /// ACME v2 directory URL of the CA (e.g. `LE_PRODUCTION`)
    pub directory_url: String,
    /// Contact email registered with the CA for expiry notices
    pub contact_email: String,
    /// Account private key in PEM. Returned as `None` to API callers — only
    /// the engine ever needs to read this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    /// When the account row was first created
    pub created_at: DateTime<Utc>,
}

/// Default to Let's Encrypt production. The UI presents a dropdown:
/// production / staging / custom.
pub const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory — untrusted certs, but no rate limits;
/// use for testing the issuance flow
pub const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME challenge used to prove domain control. Wire values are kebab-case
/// (`dns-01` / `http-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeType {
    /// DNS-01: publish a TXT record; the only challenge that can validate wildcards
    Dns01,
    /// HTTP-01: serve a token on port 80; requires the FQDN to be publicly reachable
    Http01,
}

impl ChallengeType {
    /// Wire/DB string for this challenge (`"dns-01"` or `"http-01"`)
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeType::Dns01 => "dns-01",
            ChallengeType::Http01 => "http-01",
        }
    }
    /// Parse a DB/wire string; anything unrecognized falls back to `Dns01`
    pub fn from_str(s: &str) -> ChallengeType {
        match s {
            "http-01" => ChallengeType::Http01,
            _ => ChallengeType::Dns01,
        }
    }
}

/// Lifecycle state of a managed certificate. Wire values are kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertStatus {
    /// Created but never successfully issued
    Pending,
    /// Issued and not yet expired
    Active,
    /// Last issue/renew attempt failed (see `last_renew_error`)
    Failed,
    /// A renewal is currently in progress
    Renewing,
    /// Past `expires_at` without a successful renewal
    Expired,
}

impl CertStatus {
    /// Wire/DB string for this status (e.g. `"active"`)
    pub fn as_str(self) -> &'static str {
        match self {
            CertStatus::Pending => "pending",
            CertStatus::Active => "active",
            CertStatus::Failed => "failed",
            CertStatus::Renewing => "renewing",
            CertStatus::Expired => "expired",
        }
    }
    /// Parse a DB/wire string; anything unrecognized falls back to `Pending`
    pub fn from_str(s: &str) -> CertStatus {
        match s {
            "active" => CertStatus::Active,
            "failed" => CertStatus::Failed,
            "renewing" => CertStatus::Renewing,
            "expired" => CertStatus::Expired,
            _ => CertStatus::Pending,
        }
    }
}

/// One managed certificate: requested names, renewal policy, current status,
/// and (once issued) the PEM material. Backed by the `acme_cert` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeCert {
    /// Row id in `acme_cert`
    pub id: i64,
    /// Subject common name (may be a wildcard like `*.example.com`)
    pub common_name: String,
    /// Including the CN. Empty = CN-only cert.
    pub sans: Vec<String>,
    /// How domain control is proven (DNS-01 required for wildcards)
    pub challenge_type: ChallengeType,
    /// FK into `acme_dns_provider`. Required when challenge_type == Dns01.
    pub dns_provider_id: Option<i64>,
    /// Whether the daemon's daily tick renews this cert automatically
    pub auto_renew: bool,
    /// Renew when `expires_at - days <= now`. Default 30.
    pub renew_days_before_expiry: i32,
    /// Current lifecycle state (pending/active/failed/renewing/expired)
    pub status: CertStatus,
    /// When the current cert was issued. None until first successful issue
    pub issued_at: Option<DateTime<Utc>>,
    /// NotAfter of the current cert. None until first successful issue
    pub expires_at: Option<DateTime<Utc>>,
    /// When issuance/renewal was last attempted (success or failure)
    pub last_renew_attempt: Option<DateTime<Utc>>,
    /// Error message from the last failed attempt; None after a success
    pub last_renew_error: Option<String>,
    /// PEM of the leaf cert. None until first successful issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// PEM of the issuing chain (intermediate(s) only). Concatenate cert_pem
    /// + chain_pem to get the fullchain a server should present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    /// PEM of the leaf private key. Never serialized to API responses.
    #[serde(skip_serializing)]
    pub key_pem: Option<String>,
}

impl AcmeCert {
    /// Days until expiry, or None if not yet issued.
    pub fn days_until_expiry(&self) -> Option<i64> {
        self.expires_at.map(|t| (t - Utc::now()).num_days())
    }

    /// True when within the renew window OR already expired.
    pub fn needs_renewal(&self) -> bool {
        if !self.auto_renew {
            return false;
        }
        match self.expires_at {
            None => false,
            Some(t) => (t - Utc::now()).num_days() <= self.renew_days_before_expiry as i64,
        }
    }
}

/// DNS provider backend used to publish DNS-01 TXT records. Wire values are
/// kebab-case (e.g. `route53`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProviderKind {
    /// Cloudflare DNS API (scoped API token)
    Cloudflare,
    /// AWS Route53 (access key + secret)
    Route53,
    /// DigitalOcean DNS API
    DigitalOcean,
    /// RFC 2136 dynamic DNS update against a nameserver (TSIG key in `extra`)
    Rfc2136,
    /// No automation — the operator publishes the TXT record by hand
    Manual,
}

impl DnsProviderKind {
    /// Wire/DB string for this provider kind (e.g. `"cloudflare"`)
    pub fn as_str(self) -> &'static str {
        match self {
            DnsProviderKind::Cloudflare => "cloudflare",
            DnsProviderKind::Route53 => "route53",
            DnsProviderKind::DigitalOcean => "digitalocean",
            DnsProviderKind::Rfc2136 => "rfc2136",
            DnsProviderKind::Manual => "manual",
        }
    }
    /// Parse a DB/wire string; None if the value isn't a known provider kind
    pub fn from_str(s: &str) -> Option<DnsProviderKind> {
        Some(match s {
            "cloudflare" => DnsProviderKind::Cloudflare,
            "route53" => DnsProviderKind::Route53,
            "digitalocean" => DnsProviderKind::DigitalOcean,
            "rfc2136" => DnsProviderKind::Rfc2136,
            "manual" => DnsProviderKind::Manual,
            _ => return None,
        })
    }
}

/// A configured DNS provider that the engine uses to solve DNS-01 challenges
/// for certs whose names fall under its `zone`. Backed by `acme_dns_provider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDnsProvider {
    /// Row id in `acme_dns_provider`
    pub id: i64,
    /// Unique display name chosen by the operator
    pub name: String,
    /// Which provider API/mechanism to use for TXT record updates
    pub kind: DnsProviderKind,
    /// API token / access key for the provider. Write-only via API.
    #[serde(skip_serializing)]
    pub api_token: Option<String>,
    /// AWS secret access key (Route53 only). Write-only.
    #[serde(skip_serializing)]
    pub aws_secret_key: Option<String>,
    /// DNS zone the provider can manage. Used to scope which certs can be
    /// issued via this provider — `example.com` here means the provider can
    /// solve DNS-01 for any FQDN under `example.com`.
    pub zone: String,
    /// Provider-specific extras (region, nameserver address, key name, etc).
    /// Stored as JSON; the engine deserializes per `kind`.
    pub extra: serde_json::Value,
}

/// Where a freshly issued/renewed cert gets pushed. Wire values are
/// kebab-case (e.g. `local-tls-store`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportTargetKind {
    /// Write cert + key to a file path on the local filesystem.
    File,
    /// POST cert + key as JSON to a URL.
    Webhook,
    /// Drop into AiFw's own /usr/local/etc/aifw/tls/ + reload aifw-api.
    LocalTlsStore,
}

impl ExportTargetKind {
    /// Wire/DB string for this target kind (e.g. `"local-tls-store"`)
    pub fn as_str(self) -> &'static str {
        match self {
            ExportTargetKind::File => "file",
            ExportTargetKind::Webhook => "webhook",
            ExportTargetKind::LocalTlsStore => "local-tls-store",
        }
    }
    /// Parse a DB/wire string; None if the value isn't a known target kind
    pub fn from_str(s: &str) -> Option<ExportTargetKind> {
        Some(match s {
            "file" => ExportTargetKind::File,
            "webhook" => ExportTargetKind::Webhook,
            "local-tls-store" => ExportTargetKind::LocalTlsStore,
            _ => return None,
        })
    }
}

/// A per-cert delivery destination: after each successful issue/renew the
/// cert + key are pushed here. Backed by the `acme_export_target` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeExportTarget {
    /// Row id in `acme_export_target`
    pub id: i64,
    /// The `acme_cert` row this target exports (cascade-deleted with it)
    pub cert_id: i64,
    /// Delivery mechanism (file / webhook / local TLS store)
    pub kind: ExportTargetKind,
    /// Kind-specific config. Schema:
    ///   file:    { "cert_path": "...", "key_path": "...", "chain_path": "...",
    ///              "owner": `user[:group]`, "mode": "0644" }
    ///   webhook: { "url": "https://...", "auth_header": "Bearer ..." }
    ///   local-tls-store: { "reload_service": "aifw_api" }
    pub config: serde_json::Value,
    /// When this target last ran. None if it has never run
    pub last_run_at: Option<DateTime<Utc>>,
    /// Whether the most recent run succeeded
    pub last_run_ok: bool,
    /// Error message from the most recent failed run
    pub last_run_error: Option<String>,
}

// =============================================================================
// Schema
// =============================================================================

/// Create the ACME tables (`acme_account`, `acme_dns_provider`, `acme_cert`,
/// `acme_export_target`) and their indexes if they don't exist. Idempotent;
/// called once at startup.
pub async fn migrate(pool: &SqlitePool) -> aifw_common::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acme_account (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            directory_url   TEXT    NOT NULL,
            contact_email   TEXT    NOT NULL,
            key_pem         TEXT,
            created_at      TEXT    NOT NULL,
            UNIQUE (directory_url, contact_email)
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acme_dns_provider (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT    NOT NULL UNIQUE,
            kind           TEXT    NOT NULL,
            api_token      TEXT,
            aws_secret_key TEXT,
            zone           TEXT    NOT NULL,
            extra          TEXT    NOT NULL DEFAULT '{}'
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acme_cert (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name              TEXT    NOT NULL,
            sans                     TEXT    NOT NULL DEFAULT '[]', -- JSON array
            challenge_type           TEXT    NOT NULL DEFAULT 'dns-01',
            dns_provider_id          INTEGER REFERENCES acme_dns_provider(id) ON DELETE SET NULL,
            auto_renew               INTEGER NOT NULL DEFAULT 1,
            renew_days_before_expiry INTEGER NOT NULL DEFAULT 30,
            status                   TEXT    NOT NULL DEFAULT 'pending',
            issued_at                TEXT,
            expires_at               TEXT,
            last_renew_attempt       TEXT,
            last_renew_error         TEXT,
            cert_pem                 TEXT,
            chain_pem                TEXT,
            key_pem                  TEXT
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS acme_export_target (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id         INTEGER NOT NULL REFERENCES acme_cert(id) ON DELETE CASCADE,
            kind            TEXT    NOT NULL,
            config          TEXT    NOT NULL DEFAULT '{}',
            last_run_at     TEXT,
            last_run_ok     INTEGER NOT NULL DEFAULT 0,
            last_run_error  TEXT
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_acme_export_target_cert ON acme_export_target(cert_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_acme_cert_expires ON acme_cert(expires_at)")
        .execute(pool)
        .await?;

    Ok(())
}

// =============================================================================
// Loaders
// =============================================================================

fn parse_dt(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|x| DateTime::parse_from_rfc3339(&x).ok())
        .map(|d| d.with_timezone(&Utc))
}

/// Explicit column list for `acme_account` selects (#348). `SELECT *` triggers
/// a sqlx-sqlite column-count panic and blocks column pruning; an explicit list
/// keeps the count deterministic. Columns in `CREATE TABLE` schema order.
const ACME_ACCOUNT_COLUMNS: &str = "id, directory_url, contact_email, key_pem, created_at";

fn row_to_account(row: &sqlx::sqlite::SqliteRow) -> AcmeAccount {
    AcmeAccount {
        id: row.get("id"),
        directory_url: row.get("directory_url"),
        contact_email: row.get("contact_email"),
        key_pem: row.get("key_pem"),
        created_at: parse_dt(row.get("created_at")).unwrap_or_else(Utc::now),
    }
}

/// Fetch one ACME account by row id. None if missing or on a query error
pub async fn load_account(pool: &SqlitePool, id: i64) -> Option<AcmeAccount> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_ACCOUNT_COLUMNS} FROM acme_account WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| row_to_account(&r))
}

/// Fetch the oldest (lowest-id) ACME account, used when no account is named
/// explicitly. None if no account has been created yet
pub async fn load_default_account(pool: &SqlitePool) -> Option<AcmeAccount> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_ACCOUNT_COLUMNS} FROM acme_account ORDER BY id LIMIT 1"
    )))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| row_to_account(&r))
}

/// Upsert an ACME account keyed on (directory_url, contact_email) and return
/// its row id. On conflict, `key_pem` only overwrites the stored key when
/// `Some` — passing `None` keeps the existing key
pub async fn save_account(
    pool: &SqlitePool,
    directory_url: &str,
    contact_email: &str,
    key_pem: Option<&str>,
) -> Result<i64, String> {
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(
        r#"
        INSERT INTO acme_account (directory_url, contact_email, key_pem, created_at)
             VALUES (?, ?, ?, ?)
        ON CONFLICT(directory_url, contact_email)
        DO UPDATE SET key_pem = COALESCE(excluded.key_pem, acme_account.key_pem)
    "#,
    )
    .bind(directory_url)
    .bind(contact_email)
    .bind(key_pem)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    if res.last_insert_rowid() != 0 {
        return Ok(res.last_insert_rowid());
    }
    // ON CONFLICT path returned 0 rowid — look up the existing one.
    sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM acme_account WHERE directory_url = ? AND contact_email = ?",
    )
    .bind(directory_url)
    .bind(contact_email)
    .fetch_one(pool)
    .await
    .map(|(id,)| id)
    .map_err(|e| e.to_string())
}

/// Explicit column list for `acme_cert` selects (#348). Avoids the sqlx-sqlite
/// column-count panic and enables column pruning. Columns in `CREATE TABLE`
/// schema order.
const ACME_CERT_COLUMNS: &str = "id, common_name, sans, challenge_type, dns_provider_id, \
    auto_renew, renew_days_before_expiry, status, issued_at, expires_at, last_renew_attempt, \
    last_renew_error, cert_pem, chain_pem, key_pem";

fn row_to_cert(row: &sqlx::sqlite::SqliteRow) -> AcmeCert {
    let sans_json: String = row.get("sans");
    let sans: Vec<String> = serde_json::from_str(&sans_json).unwrap_or_default();
    AcmeCert {
        id: row.get("id"),
        common_name: row.get("common_name"),
        sans,
        challenge_type: ChallengeType::from_str(&row.get::<String, _>("challenge_type")),
        dns_provider_id: row.get("dns_provider_id"),
        auto_renew: row.get::<i64, _>("auto_renew") != 0,
        renew_days_before_expiry: row.get::<i64, _>("renew_days_before_expiry") as i32,
        status: CertStatus::from_str(&row.get::<String, _>("status")),
        issued_at: parse_dt(row.get("issued_at")),
        expires_at: parse_dt(row.get("expires_at")),
        last_renew_attempt: parse_dt(row.get("last_renew_attempt")),
        last_renew_error: row.get("last_renew_error"),
        cert_pem: row.get("cert_pem"),
        chain_pem: row.get("chain_pem"),
        key_pem: row.get("key_pem"),
    }
}

/// Fetch one cert (including PEM material) by row id. None if missing or on
/// a query error
pub async fn load_cert(pool: &SqlitePool, id: i64) -> Option<AcmeCert> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_CERT_COLUMNS} FROM acme_cert WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| row_to_cert(&r))
}

/// Fetch every cert ordered by common name. Empty on query error
pub async fn load_all_certs(pool: &SqlitePool) -> Vec<AcmeCert> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_CERT_COLUMNS} FROM acme_cert ORDER BY common_name"
    )))
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .iter()
    .map(row_to_cert)
    .collect()
}

/// Certs with auto-renew on that are inside their renewal window (or already
/// expired). Called by the daemon's daily renewal tick
pub async fn certs_due_for_renewal(pool: &SqlitePool) -> Vec<AcmeCert> {
    load_all_certs(pool)
        .await
        .into_iter()
        .filter(|c| c.needs_renewal())
        .collect()
}

/// Explicit column list for `acme_dns_provider` selects (#348). Avoids the
/// sqlx-sqlite column-count panic and enables column pruning. Columns in
/// `CREATE TABLE` schema order.
const ACME_DNS_PROVIDER_COLUMNS: &str = "id, name, kind, api_token, aws_secret_key, zone, extra";

fn row_to_provider(row: &sqlx::sqlite::SqliteRow) -> AcmeDnsProvider {
    let extra_str: String = row.get("extra");
    let extra: serde_json::Value =
        serde_json::from_str(&extra_str).unwrap_or(serde_json::json!({}));
    AcmeDnsProvider {
        id: row.get("id"),
        name: row.get("name"),
        kind: DnsProviderKind::from_str(&row.get::<String, _>("kind"))
            .unwrap_or(DnsProviderKind::Manual),
        api_token: row.get("api_token"),
        aws_secret_key: row.get("aws_secret_key"),
        zone: row.get("zone"),
        extra,
    }
}

/// Fetch one DNS provider (including credentials) by row id. None if missing
/// or on a query error
pub async fn load_provider(pool: &SqlitePool, id: i64) -> Option<AcmeDnsProvider> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_DNS_PROVIDER_COLUMNS} FROM acme_dns_provider WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| row_to_provider(&r))
}

/// Fetch every DNS provider ordered by name. Empty on query error
pub async fn load_all_providers(pool: &SqlitePool) -> Vec<AcmeDnsProvider> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_DNS_PROVIDER_COLUMNS} FROM acme_dns_provider ORDER BY name"
    )))
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .iter()
    .map(row_to_provider)
    .collect()
}

/// Explicit column list for `acme_export_target` selects (#348). Avoids the
/// sqlx-sqlite column-count panic and enables column pruning. Columns in
/// `CREATE TABLE` schema order.
const ACME_EXPORT_TARGET_COLUMNS: &str =
    "id, cert_id, kind, config, last_run_at, last_run_ok, last_run_error";

fn row_to_target(row: &sqlx::sqlite::SqliteRow) -> AcmeExportTarget {
    let cfg_str: String = row.get("config");
    let config: serde_json::Value = serde_json::from_str(&cfg_str).unwrap_or(serde_json::json!({}));
    AcmeExportTarget {
        id: row.get("id"),
        cert_id: row.get("cert_id"),
        kind: ExportTargetKind::from_str(&row.get::<String, _>("kind"))
            .unwrap_or(ExportTargetKind::Webhook),
        config,
        last_run_at: parse_dt(row.get("last_run_at")),
        last_run_ok: row.get::<i64, _>("last_run_ok") != 0,
        last_run_error: row.get("last_run_error"),
    }
}

/// Fetch all export targets attached to a cert, oldest first. Empty on query
/// error or when the cert has no targets
pub async fn load_targets_for_cert(pool: &SqlitePool, cert_id: i64) -> Vec<AcmeExportTarget> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {ACME_EXPORT_TARGET_COLUMNS} FROM acme_export_target WHERE cert_id = ? ORDER BY id"
    )))
    .bind(cert_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .iter()
    .map(row_to_target)
    .collect()
}

// =============================================================================
// Validation (used by the API layer)
// =============================================================================

/// RFC 1035 label check; allows leading `*.` for wildcard certs.
pub fn validate_dns_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 253 {
        return Err("name length out of range".into());
    }
    let body = n.strip_prefix("*.").unwrap_or(n);
    for label in body.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid label '{label}'"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("label '{label}' has invalid characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("label '{label}' must not start or end with '-'"));
        }
    }
    if !body.contains('.') {
        return Err("name must be a fully-qualified domain".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_validation() {
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("*.example.com").is_ok());
        assert!(validate_dns_name("sub.example.com").is_ok());
        assert!(validate_dns_name("nope").is_err()); // no dot
        assert!(validate_dns_name("-bad.com").is_err()); // leading hyphen
        assert!(validate_dns_name("bad-.com").is_err()); // trailing hyphen
        assert!(validate_dns_name("bad..com").is_err()); // empty label
        assert!(validate_dns_name("").is_err());
    }

    #[test]
    fn challenge_status_round_trip() {
        for c in [ChallengeType::Dns01, ChallengeType::Http01] {
            assert_eq!(ChallengeType::from_str(c.as_str()), c);
        }
        for s in [
            CertStatus::Pending,
            CertStatus::Active,
            CertStatus::Failed,
            CertStatus::Renewing,
            CertStatus::Expired,
        ] {
            assert_eq!(CertStatus::from_str(s.as_str()), s);
        }
    }

    #[test]
    fn needs_renewal_logic() {
        let mut c = AcmeCert {
            id: 1,
            common_name: "x.test".into(),
            sans: vec![],
            challenge_type: ChallengeType::Dns01,
            dns_provider_id: None,
            auto_renew: true,
            renew_days_before_expiry: 30,
            status: CertStatus::Active,
            issued_at: Some(Utc::now()),
            expires_at: Some(Utc::now() + chrono::Duration::days(20)),
            last_renew_attempt: None,
            last_renew_error: None,
            cert_pem: None,
            chain_pem: None,
            key_pem: None,
        };
        assert!(c.needs_renewal(), "20 days < 30 day window");

        c.expires_at = Some(Utc::now() + chrono::Duration::days(60));
        assert!(!c.needs_renewal(), "60 days > 30 day window");

        c.auto_renew = false;
        c.expires_at = Some(Utc::now() + chrono::Duration::days(1));
        assert!(!c.needs_renewal(), "auto_renew off => never renew");

        c.auto_renew = true;
        c.expires_at = None;
        assert!(!c.needs_renewal(), "no expiry yet => no renewal");
    }
}
