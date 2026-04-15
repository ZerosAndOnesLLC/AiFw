//! Dynamic DNS — keep an A/AAAA record pointed at the appliance's current
//! WAN IP.
//!
//! Architecture mirrors ACME on purpose: provider credentials live in the
//! existing `acme_dns_provider` table (Cloudflare API token / Route53 IAM
//! creds work for both DNS-01 and A-record updates), so the operator
//! configures a provider once and uses it for both ACME issue + DDNS.
//!
//! The daemon scheduler ticks every 5 minutes, detects the current WAN
//! IPv4 (and optionally IPv6), and if it differs from the last-published
//! value, calls the provider's `upsert_a_record` to update DNS.
//!
//! ## Why a separate table
//! Each ddns_record is a (hostname, record_type, source) tuple — multiple
//! records can share one provider. Keeping it separate from the cert table
//! means deleting an ACME cert doesn't drop the matching DDNS record (and
//! vice versa).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::net::IpAddr;
use std::time::Duration;

// =============================================================================
// Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordType {
    /// IPv4 only.
    A,
    /// IPv6 only.
    Aaaa,
    /// Both A (v4) and AAAA (v6) — two records updated together.
    Both,
}

impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self { RecordType::A => "a", RecordType::Aaaa => "aaaa", RecordType::Both => "both" }
    }
    pub fn from_str(s: &str) -> RecordType {
        match s.to_ascii_lowercase().as_str() {
            "aaaa" => RecordType::Aaaa,
            "both" => RecordType::Both,
            _      => RecordType::A,
        }
    }
}

/// How the WAN IP is determined for this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpSource {
    /// Query a public IP-echo service (default: api.ipify.org).
    AutoPublic,
    /// Read the primary IP off a named local interface (e.g. `wan0`).
    Interface,
    /// Always set to a fixed IP (useful for one-shot manual records).
    Explicit,
}

impl IpSource {
    pub fn as_str(self) -> &'static str {
        match self {
            IpSource::AutoPublic => "auto-public",
            IpSource::Interface  => "interface",
            IpSource::Explicit   => "explicit",
        }
    }
    pub fn from_str(s: &str) -> IpSource {
        match s {
            "interface" => IpSource::Interface,
            "explicit"  => IpSource::Explicit,
            _           => IpSource::AutoPublic,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsRecord {
    pub id: i64,
    /// FK into `acme_dns_provider` — same credential row used for ACME.
    pub provider_id: i64,
    /// FQDN to update (e.g. `home.example.com`).
    pub hostname: String,
    pub record_type: RecordType,
    pub source: IpSource,
    /// Local interface name when `source = Interface`. Ignored otherwise.
    pub interface: Option<String>,
    /// Explicit IP when `source = Explicit`. Ignored otherwise. Stored as
    /// a string so v4 and v6 can both go in one column.
    pub explicit_ip: Option<String>,
    /// TTL we publish on the record. Defaults to 60 — short enough that
    /// IP changes propagate quickly without risk of hot-spots.
    pub ttl: i32,
    pub enabled: bool,
    /// Last IP we successfully published, so the scheduler can no-op when
    /// nothing has changed.
    pub last_ip: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_updated: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    pub last_error: Option<String>,
}

// =============================================================================
// Schema
// =============================================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS ddns_record (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id     INTEGER NOT NULL REFERENCES acme_dns_provider(id) ON DELETE CASCADE,
            hostname        TEXT    NOT NULL,
            record_type     TEXT    NOT NULL DEFAULT 'a',
            source          TEXT    NOT NULL DEFAULT 'auto-public',
            interface       TEXT,
            explicit_ip     TEXT,
            ttl             INTEGER NOT NULL DEFAULT 60,
            enabled         INTEGER NOT NULL DEFAULT 1,
            last_ip         TEXT,
            last_ipv6       TEXT,
            last_updated    TEXT,
            last_status     TEXT,
            last_error      TEXT,
            UNIQUE (provider_id, hostname, record_type)
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS ddns_config (
            id                 INTEGER PRIMARY KEY CHECK (id = 1),
            poll_interval_secs INTEGER NOT NULL DEFAULT 300,
            ip_echo_url_v4     TEXT    NOT NULL DEFAULT 'https://api.ipify.org',
            ip_echo_url_v6     TEXT    NOT NULL DEFAULT 'https://api6.ipify.org'
        )
    "#).execute(pool).await?;
    sqlx::query(r#"
        INSERT OR IGNORE INTO ddns_config (id) VALUES (1)
    "#).execute(pool).await?;

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdnsConfig {
    pub poll_interval_secs: i64,
    pub ip_echo_url_v4: String,
    pub ip_echo_url_v6: String,
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: 300,
            ip_echo_url_v4: "https://api.ipify.org".into(),
            ip_echo_url_v6: "https://api6.ipify.org".into(),
        }
    }
}

pub async fn load_config(pool: &SqlitePool) -> DdnsConfig {
    sqlx::query_as::<_, (i64, String, String)>(
        "SELECT poll_interval_secs, ip_echo_url_v4, ip_echo_url_v6 FROM ddns_config WHERE id = 1"
    )
    .fetch_optional(pool).await.ok().flatten()
    .map(|(p, u4, u6)| DdnsConfig { poll_interval_secs: p.max(60), ip_echo_url_v4: u4, ip_echo_url_v6: u6 })
    .unwrap_or_default()
}

pub async fn save_config(pool: &SqlitePool, c: &DdnsConfig) -> Result<(), String> {
    if c.poll_interval_secs < 60 || c.poll_interval_secs > 86400 {
        return Err("poll_interval_secs must be 60..86400".into());
    }
    sqlx::query("UPDATE ddns_config SET poll_interval_secs = ?, ip_echo_url_v4 = ?, ip_echo_url_v6 = ? WHERE id = 1")
        .bind(c.poll_interval_secs)
        .bind(&c.ip_echo_url_v4)
        .bind(&c.ip_echo_url_v6)
        .execute(pool).await.map_err(|e| e.to_string())?;
    Ok(())
}

// =============================================================================
// Loaders
// =============================================================================

fn parse_dt(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|x| DateTime::parse_from_rfc3339(&x).ok()).map(|d| d.with_timezone(&Utc))
}

fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> DdnsRecord {
    DdnsRecord {
        id: row.get("id"),
        provider_id: row.get("provider_id"),
        hostname: row.get("hostname"),
        record_type: RecordType::from_str(&row.get::<String, _>("record_type")),
        source: IpSource::from_str(&row.get::<String, _>("source")),
        interface: row.get("interface"),
        explicit_ip: row.get("explicit_ip"),
        ttl: row.get::<i64, _>("ttl") as i32,
        enabled: row.get::<i64, _>("enabled") != 0,
        last_ip: row.get("last_ip"),
        last_ipv6: row.get("last_ipv6"),
        last_updated: parse_dt(row.get("last_updated")),
        last_status: row.get("last_status"),
        last_error: row.get("last_error"),
    }
}

pub async fn load_record(pool: &SqlitePool, id: i64) -> Option<DdnsRecord> {
    sqlx::query("SELECT * FROM ddns_record WHERE id = ?")
        .bind(id)
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_record(&r))
}

pub async fn load_all_records(pool: &SqlitePool) -> Vec<DdnsRecord> {
    sqlx::query("SELECT * FROM ddns_record ORDER BY hostname")
        .fetch_all(pool).await.unwrap_or_default()
        .iter().map(row_to_record).collect()
}

// =============================================================================
// IP detection
// =============================================================================

/// Resolve the IPv4 we should publish for this record. Returns None if
/// detection failed — caller should leave the record alone in that case.
pub async fn detect_ipv4(record: &DdnsRecord, cfg: &DdnsConfig) -> Result<IpAddr, String> {
    detect_ip(record, cfg, false).await
}

pub async fn detect_ipv6(record: &DdnsRecord, cfg: &DdnsConfig) -> Result<IpAddr, String> {
    detect_ip(record, cfg, true).await
}

async fn detect_ip(record: &DdnsRecord, cfg: &DdnsConfig, want_v6: bool) -> Result<IpAddr, String> {
    match record.source {
        IpSource::Explicit => {
            let s = record.explicit_ip.as_deref()
                .ok_or_else(|| "explicit_ip required when source=explicit".to_string())?;
            let ip: IpAddr = s.parse().map_err(|e| format!("invalid explicit_ip: {e}"))?;
            if want_v6 != ip.is_ipv6() {
                return Err(format!("explicit_ip family doesn't match record_type (got {:?})", ip));
            }
            Ok(ip)
        }
        IpSource::Interface => {
            let iface = record.interface.as_deref()
                .ok_or_else(|| "interface required when source=interface".to_string())?;
            interface_ip(iface, want_v6).await
        }
        IpSource::AutoPublic => {
            let url = if want_v6 { &cfg.ip_echo_url_v6 } else { &cfg.ip_echo_url_v4 };
            public_ip(url, want_v6).await
        }
    }
}

/// Read a primary, non-link-local address off a local interface. Uses
/// `ifconfig <name>` on FreeBSD — getifaddrs would avoid the fork but
/// this is a 5-minute-cadence call so the cost is irrelevant.
async fn interface_ip(name: &str, want_v6: bool) -> Result<IpAddr, String> {
    let out = tokio::process::Command::new("/sbin/ifconfig")
        .arg(name)
        .output().await
        .map_err(|e| format!("ifconfig: {e}"))?;
    if !out.status.success() {
        return Err(format!("ifconfig {name} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let l = line.trim();
        if want_v6 {
            if let Some(rest) = l.strip_prefix("inet6 ") {
                let addr = rest.split_whitespace().next().unwrap_or("");
                // Strip scope id (fe80::1%vtnet0 -> fe80::1)
                let addr = addr.split('%').next().unwrap_or(addr);
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    if ip.is_ipv6() && !ip.is_loopback()
                        && !addr.starts_with("fe80")          // link-local
                        && !addr.starts_with("fc")            // ULA
                        && !addr.starts_with("fd") {
                        return Ok(ip);
                    }
                }
            }
        } else if let Some(rest) = l.strip_prefix("inet ") {
            let addr = rest.split_whitespace().next().unwrap_or("");
            if let Ok(ip) = addr.parse::<IpAddr>() {
                if ip.is_ipv4() && !ip.is_loopback() && !addr.starts_with("169.254") {
                    return Ok(ip);
                }
            }
        }
    }
    Err(format!("no usable {} address on {name}", if want_v6 { "IPv6" } else { "IPv4" }))
}

/// Query a public IP-echo service. We force the resolver family so a v4
/// query doesn't accidentally reach a v6 endpoint and vice versa.
async fn public_ip(url: &str, want_v6: bool) -> Result<IpAddr, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .local_address(if want_v6 {
            Some("::".parse::<IpAddr>().unwrap())
        } else {
            Some("0.0.0.0".parse::<IpAddr>().unwrap())
        })
        .build()
        .map_err(|e| format!("reqwest: {e}"))?;
    let body = client.get(url).send().await
        .map_err(|e| format!("GET {url}: {e}"))?
        .text().await
        .map_err(|e| format!("read {url}: {e}"))?;
    let s = body.trim();
    let ip: IpAddr = s.parse().map_err(|e| format!("'{s}' is not an IP: {e}"))?;
    if want_v6 != ip.is_ipv6() {
        return Err(format!("ip-echo returned wrong family: got {ip} (wanted v{})",
            if want_v6 { 6 } else { 4 }));
    }
    Ok(ip)
}

// =============================================================================
// Update flow — called by the daemon scheduler + the "force update" API
// =============================================================================

/// Update a single DDNS record. No-ops when the detected IP matches the
/// last successfully-published value. Persists status + error on the row.
pub async fn update_record(pool: &SqlitePool, record_id: i64) -> Result<UpdateOutcome, String> {
    let mut record = load_record(pool, record_id).await
        .ok_or_else(|| format!("ddns record {record_id} not found"))?;
    if !record.enabled {
        return Ok(UpdateOutcome::Skipped("record disabled".into()));
    }
    let provider = crate::acme::load_provider(pool, record.provider_id).await
        .ok_or_else(|| format!("provider {} not found", record.provider_id))?;
    let writer = crate::acme_dns::build_record_writer(&provider)?;
    let cfg = load_config(pool).await;

    let mut changed: Vec<(String, IpAddr)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    // ----- v4 -----
    if matches!(record.record_type, RecordType::A | RecordType::Both) {
        match detect_ipv4(&record, &cfg).await {
            Ok(ip) => {
                let prev = record.last_ip.as_deref();
                if prev == Some(ip.to_string().as_str()) {
                    // Same as last update — skip the API call.
                } else if let Err(e) = writer.upsert_a(&record.hostname, ip, record.ttl as u32).await {
                    errors.push(format!("v4: {e}"));
                } else {
                    record.last_ip = Some(ip.to_string());
                    changed.push(("A".into(), ip));
                }
            }
            Err(e) => errors.push(format!("detect v4: {e}")),
        }
    }
    // ----- v6 -----
    if matches!(record.record_type, RecordType::Aaaa | RecordType::Both) {
        match detect_ipv6(&record, &cfg).await {
            Ok(ip) => {
                let prev = record.last_ipv6.as_deref();
                if prev == Some(ip.to_string().as_str()) {
                    // unchanged
                } else if let Err(e) = writer.upsert_aaaa(&record.hostname, ip, record.ttl as u32).await {
                    errors.push(format!("v6: {e}"));
                } else {
                    record.last_ipv6 = Some(ip.to_string());
                    changed.push(("AAAA".into(), ip));
                }
            }
            Err(e) => errors.push(format!("detect v6: {e}")),
        }
    }

    let now = Utc::now().to_rfc3339();
    let (status, err_str): (&str, Option<String>) = if !errors.is_empty() {
        ("error", Some(errors.join("; ")))
    } else if changed.is_empty() {
        ("unchanged", None)
    } else {
        ("updated", None)
    };
    sqlx::query("UPDATE ddns_record SET last_ip = ?, last_ipv6 = ?, last_updated = ?, last_status = ?, last_error = ? WHERE id = ?")
        .bind(&record.last_ip)
        .bind(&record.last_ipv6)
        .bind(&now)
        .bind(status)
        .bind(&err_str)
        .bind(record.id)
        .execute(pool).await
        .map_err(|e| format!("persist ddns: {e}"))?;

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(if changed.is_empty() {
        UpdateOutcome::Unchanged
    } else {
        UpdateOutcome::Updated(changed)
    })
}

#[derive(Debug)]
pub enum UpdateOutcome {
    Updated(Vec<(String, IpAddr)>),
    Unchanged,
    Skipped(String),
}

/// Run [`update_record`] on every enabled record. Used by the daemon
/// scheduler. Errors per-record are recorded on the row; this never
/// returns Err.
pub async fn update_all(pool: &SqlitePool) {
    for r in load_all_records(pool).await {
        if !r.enabled { continue; }
        if let Err(e) = update_record(pool, r.id).await {
            tracing::warn!(record_id = r.id, host = %r.hostname, error = %e, "ddns update failed");
        }
    }
}

/// Spawn the daemon scheduler. Sleeps for `poll_interval_secs` between
/// sweeps; the interval is re-read each tick so changing it from the UI
/// takes effect on the next cycle without a restart.
pub fn spawn_scheduler(pool: SqlitePool) {
    tokio::spawn(async move {
        // Brief startup grace so the WAN interface comes up first.
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let cfg = load_config(&pool).await;
            update_all(&pool).await;
            tokio::time::sleep(Duration::from_secs(cfg.poll_interval_secs.max(60) as u64)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_round_trip() {
        for t in [RecordType::A, RecordType::Aaaa, RecordType::Both] {
            assert_eq!(RecordType::from_str(t.as_str()), t);
        }
    }

    #[test]
    fn ip_source_round_trip() {
        for s in [IpSource::AutoPublic, IpSource::Interface, IpSource::Explicit] {
            assert_eq!(IpSource::from_str(s.as_str()), s);
        }
    }
}
