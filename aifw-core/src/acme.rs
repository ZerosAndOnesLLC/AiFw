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
    pub id: i64,
    pub directory_url: String,
    pub contact_email: String,
    /// Account private key in PEM. Returned as `None` to API callers — only
    /// the engine ever needs to read this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Default to Let's Encrypt production. The UI presents a dropdown:
/// production / staging / custom.
pub const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LE_STAGING:    &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeType {
    Dns01,
    Http01,
}

impl ChallengeType {
    pub fn as_str(self) -> &'static str {
        match self { ChallengeType::Dns01 => "dns-01", ChallengeType::Http01 => "http-01" }
    }
    pub fn from_str(s: &str) -> ChallengeType {
        match s { "http-01" => ChallengeType::Http01, _ => ChallengeType::Dns01 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertStatus {
    Pending,
    Active,
    Failed,
    Renewing,
    Expired,
}

impl CertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CertStatus::Pending  => "pending",
            CertStatus::Active   => "active",
            CertStatus::Failed   => "failed",
            CertStatus::Renewing => "renewing",
            CertStatus::Expired  => "expired",
        }
    }
    pub fn from_str(s: &str) -> CertStatus {
        match s {
            "active"   => CertStatus::Active,
            "failed"   => CertStatus::Failed,
            "renewing" => CertStatus::Renewing,
            "expired"  => CertStatus::Expired,
            _          => CertStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeCert {
    pub id: i64,
    pub common_name: String,
    /// Including the CN. Empty = CN-only cert.
    pub sans: Vec<String>,
    pub challenge_type: ChallengeType,
    /// FK into `acme_dns_provider`. Required when challenge_type == Dns01.
    pub dns_provider_id: Option<i64>,
    pub auto_renew: bool,
    /// Renew when `expires_at - days <= now`. Default 30.
    pub renew_days_before_expiry: i32,
    pub status: CertStatus,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_renew_attempt: Option<DateTime<Utc>>,
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
        if !self.auto_renew { return false; }
        match self.expires_at {
            None => false,
            Some(t) => (t - Utc::now()).num_days() <= self.renew_days_before_expiry as i64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProviderKind {
    Cloudflare,
    Route53,
    DigitalOcean,
    Rfc2136,
    Manual,
}

impl DnsProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsProviderKind::Cloudflare   => "cloudflare",
            DnsProviderKind::Route53      => "route53",
            DnsProviderKind::DigitalOcean => "digitalocean",
            DnsProviderKind::Rfc2136      => "rfc2136",
            DnsProviderKind::Manual       => "manual",
        }
    }
    pub fn from_str(s: &str) -> Option<DnsProviderKind> {
        Some(match s {
            "cloudflare"   => DnsProviderKind::Cloudflare,
            "route53"      => DnsProviderKind::Route53,
            "digitalocean" => DnsProviderKind::DigitalOcean,
            "rfc2136"      => DnsProviderKind::Rfc2136,
            "manual"       => DnsProviderKind::Manual,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDnsProvider {
    pub id: i64,
    pub name: String,
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
    pub fn as_str(self) -> &'static str {
        match self {
            ExportTargetKind::File          => "file",
            ExportTargetKind::Webhook       => "webhook",
            ExportTargetKind::LocalTlsStore => "local-tls-store",
        }
    }
    pub fn from_str(s: &str) -> Option<ExportTargetKind> {
        Some(match s {
            "file"            => ExportTargetKind::File,
            "webhook"         => ExportTargetKind::Webhook,
            "local-tls-store" => ExportTargetKind::LocalTlsStore,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeExportTarget {
    pub id: i64,
    pub cert_id: i64,
    pub kind: ExportTargetKind,
    /// Kind-specific config. Schema:
    ///   file:    { "cert_path": "...", "key_path": "...", "chain_path": "...",
    ///              "owner": "user[:group]", "mode": "0644" }
    ///   webhook: { "url": "https://...", "auth_header": "Bearer ..." }
    ///   local-tls-store: { "reload_service": "aifw_api" }
    pub config: serde_json::Value,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_ok: bool,
    pub last_run_error: Option<String>,
}

// =============================================================================
// Schema
// =============================================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS acme_account (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            directory_url   TEXT    NOT NULL,
            contact_email   TEXT    NOT NULL,
            key_pem         TEXT,
            created_at      TEXT    NOT NULL,
            UNIQUE (directory_url, contact_email)
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS acme_dns_provider (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            name           TEXT    NOT NULL UNIQUE,
            kind           TEXT    NOT NULL,
            api_token      TEXT,
            aws_secret_key TEXT,
            zone           TEXT    NOT NULL,
            extra          TEXT    NOT NULL DEFAULT '{}'
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
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
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS acme_export_target (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_id         INTEGER NOT NULL REFERENCES acme_cert(id) ON DELETE CASCADE,
            kind            TEXT    NOT NULL,
            config          TEXT    NOT NULL DEFAULT '{}',
            last_run_at     TEXT,
            last_run_ok     INTEGER NOT NULL DEFAULT 0,
            last_run_error  TEXT
        )
    "#).execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_acme_export_target_cert ON acme_export_target(cert_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_acme_cert_expires ON acme_cert(expires_at)")
        .execute(pool).await?;

    Ok(())
}

// =============================================================================
// Loaders
// =============================================================================

fn parse_dt(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|x| DateTime::parse_from_rfc3339(&x).ok()).map(|d| d.with_timezone(&Utc))
}

fn row_to_account(row: &sqlx::sqlite::SqliteRow) -> AcmeAccount {
    AcmeAccount {
        id: row.get("id"),
        directory_url: row.get("directory_url"),
        contact_email: row.get("contact_email"),
        key_pem: row.get("key_pem"),
        created_at: parse_dt(row.get("created_at"))
            .unwrap_or_else(Utc::now),
    }
}

pub async fn load_account(pool: &SqlitePool, id: i64) -> Option<AcmeAccount> {
    sqlx::query("SELECT * FROM acme_account WHERE id = ?")
        .bind(id)
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_account(&r))
}

pub async fn load_default_account(pool: &SqlitePool) -> Option<AcmeAccount> {
    sqlx::query("SELECT * FROM acme_account ORDER BY id LIMIT 1")
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_account(&r))
}

pub async fn save_account(pool: &SqlitePool, directory_url: &str, contact_email: &str, key_pem: Option<&str>) -> Result<i64, String> {
    let now = Utc::now().to_rfc3339();
    let res = sqlx::query(r#"
        INSERT INTO acme_account (directory_url, contact_email, key_pem, created_at)
             VALUES (?, ?, ?, ?)
        ON CONFLICT(directory_url, contact_email)
        DO UPDATE SET key_pem = COALESCE(excluded.key_pem, acme_account.key_pem)
    "#)
    .bind(directory_url).bind(contact_email).bind(key_pem).bind(&now)
    .execute(pool).await.map_err(|e| e.to_string())?;
    if res.last_insert_rowid() != 0 {
        return Ok(res.last_insert_rowid());
    }
    // ON CONFLICT path returned 0 rowid — look up the existing one.
    sqlx::query_as::<_, (i64,)>(
        "SELECT id FROM acme_account WHERE directory_url = ? AND contact_email = ?"
    ).bind(directory_url).bind(contact_email)
    .fetch_one(pool).await.map(|(id,)| id).map_err(|e| e.to_string())
}

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

pub async fn load_cert(pool: &SqlitePool, id: i64) -> Option<AcmeCert> {
    sqlx::query("SELECT * FROM acme_cert WHERE id = ?")
        .bind(id)
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_cert(&r))
}

pub async fn load_all_certs(pool: &SqlitePool) -> Vec<AcmeCert> {
    sqlx::query("SELECT * FROM acme_cert ORDER BY common_name")
        .fetch_all(pool).await.unwrap_or_default()
        .iter().map(row_to_cert).collect()
}

pub async fn certs_due_for_renewal(pool: &SqlitePool) -> Vec<AcmeCert> {
    load_all_certs(pool).await
        .into_iter()
        .filter(|c| c.needs_renewal())
        .collect()
}

fn row_to_provider(row: &sqlx::sqlite::SqliteRow) -> AcmeDnsProvider {
    let extra_str: String = row.get("extra");
    let extra: serde_json::Value = serde_json::from_str(&extra_str).unwrap_or(serde_json::json!({}));
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

pub async fn load_provider(pool: &SqlitePool, id: i64) -> Option<AcmeDnsProvider> {
    sqlx::query("SELECT * FROM acme_dns_provider WHERE id = ?")
        .bind(id)
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_provider(&r))
}

pub async fn load_all_providers(pool: &SqlitePool) -> Vec<AcmeDnsProvider> {
    sqlx::query("SELECT * FROM acme_dns_provider ORDER BY name")
        .fetch_all(pool).await.unwrap_or_default()
        .iter().map(row_to_provider).collect()
}

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

pub async fn load_targets_for_cert(pool: &SqlitePool, cert_id: i64) -> Vec<AcmeExportTarget> {
    sqlx::query("SELECT * FROM acme_export_target WHERE cert_id = ? ORDER BY id")
        .bind(cert_id)
        .fetch_all(pool).await.unwrap_or_default()
        .iter().map(row_to_target).collect()
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
        assert!(validate_dns_name("nope").is_err());          // no dot
        assert!(validate_dns_name("-bad.com").is_err());      // leading hyphen
        assert!(validate_dns_name("bad-.com").is_err());      // trailing hyphen
        assert!(validate_dns_name("bad..com").is_err());      // empty label
        assert!(validate_dns_name("").is_err());
    }

    #[test]
    fn challenge_status_round_trip() {
        for c in [ChallengeType::Dns01, ChallengeType::Http01] {
            assert_eq!(ChallengeType::from_str(c.as_str()), c);
        }
        for s in [CertStatus::Pending, CertStatus::Active, CertStatus::Failed,
                  CertStatus::Renewing, CertStatus::Expired] {
            assert_eq!(CertStatus::from_str(s.as_str()), s);
        }
    }

    #[test]
    fn needs_renewal_logic() {
        let mut c = AcmeCert {
            id: 1, common_name: "x.test".into(), sans: vec![],
            challenge_type: ChallengeType::Dns01, dns_provider_id: None,
            auto_renew: true, renew_days_before_expiry: 30,
            status: CertStatus::Active,
            issued_at: Some(Utc::now()),
            expires_at: Some(Utc::now() + chrono::Duration::days(20)),
            last_renew_attempt: None, last_renew_error: None,
            cert_pem: None, chain_pem: None, key_pem: None,
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
