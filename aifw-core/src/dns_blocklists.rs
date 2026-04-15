//! DNS blocklist engine — schema, downloader, scheduler.
//!
//! HTTP handlers live in `aifw-api`; the actual work (downloads, parsing,
//! atomic file writes, rDNS reload, scheduling) lives here so the daemon
//! can own the background scheduler instead of the API process.
//!
//! ## File layout
//!
//! Each enabled source becomes one file at:
//!   `/usr/local/etc/rdns/rpz/blocklist-<id>.rpz`
//! Plus `custom.rpz` for whitelist (passthru) + admin custom blocks.
//! rDNS loads each as its own RPZ zone, so per-list hit counters are
//! reported by zone name.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Semaphore;

pub const RPZ_DIR: &str = "/usr/local/etc/rdns/rpz";
pub const CONTROL_SOCKET: &str = "/var/run/rdns/control.sock";
const MAX_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;
const HTTP_TIMEOUT_SECS: u64 = 30;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSource {
    pub id: i64,
    pub name: String,
    pub category: String,
    pub url: String,
    pub format: String,
    pub enabled: bool,
    pub action: String,
    pub redirect_ip: Option<String>,
    pub last_updated: Option<i64>,
    pub last_sha256: Option<String>,
    pub rule_count: i64,
    pub last_error: Option<String>,
    pub built_in: bool,
}

#[derive(Debug, Deserialize)]
pub struct NewBlocklistSource {
    pub name: String,
    pub category: String,
    pub url: String,
    pub format: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_action")]
    pub action: String,
    pub redirect_ip: Option<String>,
}

fn default_true() -> bool { true }
fn default_action() -> String { "nxdomain".into() }

#[derive(Debug, Deserialize)]
pub struct UpdateBlocklistSource {
    pub name: Option<String>,
    pub category: Option<String>,
    pub url: Option<String>,
    pub format: Option<String>,
    pub enabled: Option<bool>,
    pub action: Option<String>,
    pub redirect_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSchedule {
    pub cron: String,
    pub on_boot: bool,
    pub concurrency: i64,
    /// Master on/off for the entire DNS blocklisting feature. When false:
    ///   - scheduler skips cron-driven refreshes,
    ///   - refresh endpoints return an error,
    ///   - on-disk blocklist files are removed and rDNS is reloaded.
    /// Whitelist + custom blocks still apply (they are not blocklists).
    #[serde(default)]
    pub enabled: bool,
}

impl Default for BlocklistSchedule {
    fn default() -> Self {
        Self { cron: "0 0 3 * * *".into(), on_boot: true, concurrency: 4, enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    pub id: i64,
    pub pattern: String,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NewPatternEntry {
    pub pattern: String,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RefreshOutcome {
    pub source_id: i64,
    pub ok: bool,
    pub rule_count: i64,
    pub bytes: usize,
    pub sha256: String,
    pub error: Option<String>,
}

// ============================================================================
// Schema + seed
// ============================================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_blocklist_source (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL UNIQUE,
            category     TEXT NOT NULL,
            url          TEXT NOT NULL,
            format       TEXT NOT NULL DEFAULT 'hosts',
            enabled      INTEGER NOT NULL DEFAULT 1,
            action       TEXT NOT NULL DEFAULT 'nxdomain',
            redirect_ip  TEXT,
            last_updated INTEGER,
            last_sha256  TEXT,
            rule_count   INTEGER NOT NULL DEFAULT 0,
            last_error   TEXT,
            built_in     INTEGER NOT NULL DEFAULT 0
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_blocklist_schedule (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            cron        TEXT NOT NULL DEFAULT '0 0 3 * * *',
            on_boot     INTEGER NOT NULL DEFAULT 1,
            concurrency INTEGER NOT NULL DEFAULT 4,
            enabled     INTEGER NOT NULL DEFAULT 0
        )
    "#).execute(pool).await?;
    // Idempotent column add for existing deployments that predate the `enabled` flag.
    let _ = sqlx::query("ALTER TABLE dns_blocklist_schedule ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0")
        .execute(pool).await;
    sqlx::query(r#"
        INSERT OR IGNORE INTO dns_blocklist_schedule (id, cron, on_boot, concurrency, enabled)
        VALUES (1, '0 0 3 * * *', 1, 4, 0)
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_whitelist (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            note    TEXT
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_blocklist_custom (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL UNIQUE,
            note    TEXT
        )
    "#).execute(pool).await?;

    seed_builtin_sources(pool).await?;
    Ok(())
}

async fn seed_builtin_sources(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let seeds: &[(&str, &str, &str, &str)] = &[
        ("StevenBlack Hosts",  "ads",      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts"),
        ("OISD Big",           "ads",      "https://big.oisd.nl/domainswild",                                  "domains"),
        ("OISD NSFW",          "adult",    "https://nsfw.oisd.nl/domainswild",                                 "domains"),
        ("AdGuard DNS",        "ads",      "https://v.firebog.net/hosts/AdguardDNS.txt",                       "domains"),
        ("EasyList",           "ads",      "https://v.firebog.net/hosts/Easylist.txt",                         "domains"),
        ("EasyPrivacy",        "tracking", "https://v.firebog.net/hosts/Easyprivacy.txt",                      "domains"),
        ("Disconnect Tracking","tracking", "https://v.firebog.net/hosts/Disconnect-Tracking.txt",              "domains"),
        ("URLhaus",            "malware",  "https://urlhaus.abuse.ch/downloads/hostfile/",                     "hosts"),
        ("DigitalSide Threat", "malware",  "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt","domains"),
        ("Phishing Army",      "phishing", "https://phishing.army/download/phishing_army_blocklist_extended.txt","domains"),
        ("NoCoin Mining",      "crypto",   "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt","hosts"),
        ("CoinBlocker",        "crypto",   "https://zerodot1.gitlab.io/CoinBlockerLists/hosts",                "hosts"),
        ("Smart-TV Tracking",  "tracking", "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt","hosts"),
        ("Facebook (social)",  "social",   "https://raw.githubusercontent.com/jmdugan/blocklists/master/corporations/facebook/all","domains"),
    ];

    for (name, category, url, format) in seeds {
        sqlx::query(r#"
            INSERT OR IGNORE INTO dns_blocklist_source
                (name, category, url, format, enabled, action, built_in)
            VALUES (?, ?, ?, ?, 0, 'nxdomain', 1)
        "#)
        .bind(name).bind(category).bind(url).bind(format)
        .execute(pool).await?;
    }
    Ok(())
}

// ============================================================================
// Validation
// ============================================================================

pub fn validate_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("URL must use http or https".into());
    }
    let lower = url.to_ascii_lowercase();
    for bad in [
        "://127.", "://localhost", "://0.0.0.0",
        "://169.254.", "://[::1]", "://10.",
        "://192.168.", "://172.16.", "://172.17.",
        "://172.18.", "://172.19.", "://172.20.",
        "://172.21.", "://172.22.", "://172.23.",
        "://172.24.", "://172.25.", "://172.26.",
        "://172.27.", "://172.28.", "://172.29.",
        "://172.30.", "://172.31.",
    ] {
        if lower.contains(bad) {
            return Err(format!("URL targets a private or loopback address: {bad}"));
        }
    }
    Ok(())
}

pub fn validate_format(format: &str) -> Result<(), String> {
    match format {
        "hosts" | "domains" | "adblock" | "rpz" => Ok(()),
        _ => Err("format must be one of: hosts, domains, adblock, rpz".into()),
    }
}

pub fn validate_action(action: &str) -> Result<(), String> {
    match action {
        "nxdomain" | "nodata" | "drop" | "redirect" => Ok(()),
        _ => Err("action must be one of: nxdomain, nodata, drop, redirect".into()),
    }
}

pub fn validate_redirect_ip(action: &str, ip: Option<&str>) -> Result<(), String> {
    if action != "redirect" { return Ok(()); }
    let ip = ip.ok_or_else(|| "redirect_ip required when action=redirect".to_string())?;
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err("redirect_ip must be a valid IPv4 or IPv6 address".into());
    }
    Ok(())
}

pub fn validate_pattern(p: &str) -> Result<(), String> {
    let p = p.trim().trim_end_matches('.');
    let body = p.strip_prefix("*.").unwrap_or(p);
    if body.is_empty() || body.len() > 253 {
        return Err("pattern length out of range".into());
    }
    for label in body.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid label length".into());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("labels must be alphanumeric or hyphen".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("labels must not start or end with hyphen".into());
        }
    }
    if !p.contains('.') {
        return Err("pattern must contain at least one dot".into());
    }
    Ok(())
}

// ============================================================================
// Loaders
// ============================================================================

fn row_to_source(row: &sqlx::sqlite::SqliteRow) -> BlocklistSource {
    BlocklistSource {
        id: row.get("id"),
        name: row.get("name"),
        category: row.get("category"),
        url: row.get("url"),
        format: row.get("format"),
        enabled: row.get::<i64, _>("enabled") != 0,
        action: row.get("action"),
        redirect_ip: row.get("redirect_ip"),
        last_updated: row.get("last_updated"),
        last_sha256: row.get("last_sha256"),
        rule_count: row.get("rule_count"),
        last_error: row.get("last_error"),
        built_in: row.get::<i64, _>("built_in") != 0,
    }
}

pub async fn load_source(pool: &SqlitePool, id: i64) -> Option<BlocklistSource> {
    sqlx::query("SELECT * FROM dns_blocklist_source WHERE id = ?")
        .bind(id)
        .fetch_optional(pool).await.ok().flatten()
        .map(|r| row_to_source(&r))
}

pub async fn load_all_sources(pool: &SqlitePool) -> Vec<BlocklistSource> {
    sqlx::query("SELECT * FROM dns_blocklist_source ORDER BY category, name")
        .fetch_all(pool).await
        .unwrap_or_default()
        .iter().map(row_to_source).collect()
}

pub async fn load_schedule(pool: &SqlitePool) -> BlocklistSchedule {
    sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT cron, on_boot, concurrency, COALESCE(enabled, 0) FROM dns_blocklist_schedule WHERE id = 1"
    )
    .fetch_optional(pool).await.ok().flatten()
    .map(|(cron, on_boot, concurrency, enabled)| BlocklistSchedule {
        cron,
        on_boot: on_boot != 0,
        concurrency: concurrency.max(1),
        enabled: enabled != 0,
    })
    .unwrap_or_default()
}

pub async fn put_schedule(pool: &SqlitePool, s: &BlocklistSchedule) -> Result<(), String> {
    cron::Schedule::try_from(s.cron.as_str()).map_err(|e| format!("invalid cron: {e}"))?;
    if s.concurrency < 1 || s.concurrency > 32 {
        return Err("concurrency must be 1..32".into());
    }
    sqlx::query(r#"
        UPDATE dns_blocklist_schedule
           SET cron=?, on_boot=?, concurrency=?, enabled=?
         WHERE id=1
    "#)
    .bind(&s.cron).bind(s.on_boot as i64).bind(s.concurrency).bind(s.enabled as i64)
    .execute(pool).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Toggle blocklisting on/off. When disabling, removes every blocklist RPZ
/// file so rDNS matches drop to zero on reload. When enabling, refreshes
/// every enabled source immediately.
pub async fn set_enabled(pool: &SqlitePool, enabled: bool) -> Result<(), String> {
    sqlx::query("UPDATE dns_blocklist_schedule SET enabled = ? WHERE id = 1")
        .bind(enabled as i64)
        .execute(pool).await.map_err(|e| e.to_string())?;

    if enabled {
        // Kick off a refresh of all enabled sources. Returns the outcomes but
        // we don't surface them here — the UI polls `list_sources` afterwards.
        refresh_all(pool).await;
    } else {
        // Wipe all per-source files; custom.rpz (whitelist/custom) stays.
        for src in load_all_sources(pool).await {
            remove_blocklist_file(&rpz_path_for(src.id)).await;
        }
        let _ = trigger_rdns_reload().await;
    }
    Ok(())
}

pub async fn load_whitelist(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT pattern FROM dns_whitelist")
        .fetch_all(pool).await
        .unwrap_or_default()
        .into_iter().map(|(p,)| p).collect()
}

pub async fn load_custom_blocks(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT pattern FROM dns_blocklist_custom")
        .fetch_all(pool).await
        .unwrap_or_default()
        .into_iter().map(|(p,)| p).collect()
}

// ============================================================================
// CRUD
// ============================================================================

pub async fn create_source(pool: &SqlitePool, req: NewBlocklistSource) -> Result<BlocklistSource, String> {
    validate_url(&req.url)?;
    validate_format(&req.format)?;
    validate_action(&req.action)?;
    validate_redirect_ip(&req.action, req.redirect_ip.as_deref())?;
    if req.name.trim().is_empty() {
        return Err("name required".into());
    }
    let res = sqlx::query(r#"
        INSERT INTO dns_blocklist_source
            (name, category, url, format, enabled, action, redirect_ip, built_in)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    "#)
    .bind(&req.name).bind(&req.category).bind(&req.url).bind(&req.format)
    .bind(req.enabled as i64).bind(&req.action).bind(&req.redirect_ip)
    .execute(pool).await
    .map_err(|e| e.to_string())?;
    let id = res.last_insert_rowid();
    load_source(pool, id).await.ok_or_else(|| "post-insert read failed".into())
}

pub async fn update_source(pool: &SqlitePool, id: i64, req: UpdateBlocklistSource) -> Result<BlocklistSource, String> {
    let existing = load_source(pool, id).await.ok_or_else(|| "not found".to_string())?;

    let name        = req.name.unwrap_or(existing.name.clone());
    let category    = req.category.unwrap_or(existing.category.clone());
    let url         = req.url.unwrap_or(existing.url.clone());
    let format      = req.format.unwrap_or(existing.format.clone());
    let enabled     = req.enabled.unwrap_or(existing.enabled);
    let action      = req.action.unwrap_or(existing.action.clone());
    let redirect_ip = match req.redirect_ip {
        Some(v) if v.is_empty() => None,
        Some(v) => Some(v),
        None => existing.redirect_ip.clone(),
    };

    validate_url(&url)?;
    validate_format(&format)?;
    validate_action(&action)?;
    validate_redirect_ip(&action, redirect_ip.as_deref())?;

    sqlx::query(r#"
        UPDATE dns_blocklist_source
           SET name=?, category=?, url=?, format=?, enabled=?, action=?, redirect_ip=?
         WHERE id=?
    "#)
    .bind(&name).bind(&category).bind(&url).bind(&format)
    .bind(enabled as i64).bind(&action).bind(&redirect_ip).bind(id)
    .execute(pool).await.map_err(|e| e.to_string())?;

    if !enabled {
        remove_blocklist_file(&rpz_path_for(id)).await;
        let _ = trigger_rdns_reload().await;
    }
    load_source(pool, id).await.ok_or_else(|| "post-update read failed".into())
}

pub async fn delete_source(pool: &SqlitePool, id: i64) -> Result<(), String> {
    let existing = load_source(pool, id).await.ok_or_else(|| "not found".to_string())?;
    if existing.built_in {
        return Err("cannot delete built-in source — disable it instead".into());
    }
    sqlx::query("DELETE FROM dns_blocklist_source WHERE id=?")
        .bind(id).execute(pool).await.map_err(|e| e.to_string())?;
    remove_blocklist_file(&rpz_path_for(id)).await;
    let _ = trigger_rdns_reload().await;
    Ok(())
}

// ============================================================================
// Pattern table CRUD (whitelist / custom)
// ============================================================================

pub async fn list_patterns(pool: &SqlitePool, table: &str) -> Vec<PatternEntry> {
    let q = format!("SELECT id, pattern, note FROM {table} ORDER BY pattern");
    sqlx::query_as::<_, (i64, String, Option<String>)>(&q)
        .fetch_all(pool).await
        .unwrap_or_default()
        .into_iter()
        .map(|(id, pattern, note)| PatternEntry { id, pattern, note })
        .collect()
}

pub async fn insert_pattern(pool: &SqlitePool, table: &str, req: NewPatternEntry) -> Result<PatternEntry, String> {
    validate_pattern(&req.pattern)?;
    let q = format!("INSERT INTO {table} (pattern, note) VALUES (?, ?)");
    let res = sqlx::query(&q)
        .bind(&req.pattern).bind(&req.note)
        .execute(pool).await.map_err(|e| e.to_string())?;
    Ok(PatternEntry { id: res.last_insert_rowid(), pattern: req.pattern, note: req.note })
}

pub async fn delete_pattern(pool: &SqlitePool, table: &str, id: i64) -> Result<(), String> {
    let q = format!("DELETE FROM {table} WHERE id=?");
    sqlx::query(&q).bind(id).execute(pool).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// Downloader / parser / writer
// ============================================================================

async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let out = tokio::process::Command::new("curl")
        .args([
            "-sfL",
            "--max-time", &HTTP_TIMEOUT_SECS.to_string(),
            "--max-filesize", &MAX_DOWNLOAD_BYTES.to_string(),
            "-A", "AiFw-Blocklist-Updater/1.0",
            url,
        ])
        .output().await
        .map_err(|e| format!("spawn curl failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("HTTP fetch failed (curl exit {})", out.status.code().unwrap_or(-1)));
    }
    if out.stdout.len() > MAX_DOWNLOAD_BYTES {
        return Err(format!("response exceeds {MAX_DOWNLOAD_BYTES} bytes"));
    }
    Ok(out.stdout)
}

pub fn parse_body(body: &[u8], format: &str) -> HashSet<String> {
    let body = String::from_utf8_lossy(body);
    let mut domains = HashSet::new();

    for raw_line in body.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }

        let candidates: Vec<&str> = match format {
            "hosts" => {
                let mut it = line.split_whitespace();
                let first = it.next().unwrap_or("");
                if first == "0.0.0.0" || first == "127.0.0.1" || first == "::" {
                    vec![it.next().unwrap_or("")]
                } else {
                    vec![first]
                }
            }
            "adblock" => {
                if let Some(rest) = line.strip_prefix("||") {
                    let end = rest.find(['^', '/', '*']).unwrap_or(rest.len());
                    vec![&rest[..end]]
                } else {
                    vec![]
                }
            }
            "domains" => vec![line.split_whitespace().next().unwrap_or("")],
            "rpz" => vec![],
            _ => vec![line],
        };

        for c in candidates {
            let d = c.trim()
                .trim_end_matches('.')
                .trim_start_matches("*.");
            if d.is_empty() || d == "localhost" || d == "local" || d == "broadcasthost" {
                continue;
            }
            if !d.contains('.') || d.contains(char::is_whitespace) {
                continue;
            }
            domains.insert(d.to_ascii_lowercase());
        }
    }
    domains
}

pub fn build_rpz(domains: &HashSet<String>, action: &str, redirect_ip: Option<&str>, zone: &str) -> String {
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut out = format!(
        "$TTL 300\n@ IN SOA {zone}. admin.{zone}. {serial} 3600 900 604800 300\n  IN NS  localhost.\n"
    );
    let mut sorted: Vec<&String> = domains.iter().collect();
    sorted.sort();
    let action_line: Box<dyn Fn(&str) -> String> = match action {
        "redirect" => {
            let ip = redirect_ip.unwrap_or("0.0.0.0").to_string();
            if ip.contains(':') {
                Box::new(move |d| format!("{d} AAAA {ip}\n"))
            } else {
                Box::new(move |d| format!("{d} A {ip}\n"))
            }
        }
        "nodata" => Box::new(|d| format!("{d} CNAME *.\n")),
        "drop"   => Box::new(|d| format!("{d} CNAME rpz-drop.\n")),
        _        => Box::new(|d| format!("{d} CNAME .\n")),
    };
    for d in sorted {
        out.push_str(&action_line(d));
    }
    out
}

/// Write `body` to `path` via `sudo /usr/bin/install` — matches the existing
/// AiFw pattern in `dns_resolver.rs` because the API/daemon both run as the
/// `aifw` user, which has no direct write access to `/usr/local/etc/rdns/`.
///
/// Steps: write to `/tmp/aifw_blocklist_<basename>.tmp` as aifw, then
/// `sudo /usr/bin/install -m 0644` it into place. Final rename inside
/// `install(1)` is atomic on the destination filesystem.
async fn atomic_write(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use tokio::process::Command;
    let basename = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("blocklist.rpz");
    let tmp = format!("/tmp/aifw_blocklist_{basename}.tmp");

    // Best-effort mkdir of parent (sudo /bin/mkdir is in sudoers).
    if let Some(parent) = path.parent() {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/mkdir", "-p", parent.to_str().unwrap_or("")])
            .output().await;
    }

    tokio::fs::write(&tmp, body).await?;

    let dest = path.to_str().ok_or_else(|| std::io::Error::other("non-utf8 path"))?;
    let out = Command::new("/usr/local/bin/sudo")
        .args(["/usr/bin/install", "-m", "0644", &tmp, dest])
        .output().await?;
    let _ = tokio::fs::remove_file(&tmp).await;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "sudo install failed for {dest}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Remove a blocklist file via sudo. The sudoers entry restricts `rm` to the
/// rdns rpz directory.
async fn remove_blocklist_file(path: &std::path::Path) {
    use tokio::process::Command;
    if let Some(p) = path.to_str() {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/rm", "-f", p])
            .output().await;
    }
}

pub fn rpz_path_for(id: i64) -> PathBuf {
    PathBuf::from(format!("{RPZ_DIR}/blocklist-{id}.rpz"))
}

pub fn custom_rpz_path() -> PathBuf {
    PathBuf::from(format!("{RPZ_DIR}/custom.rpz"))
}

pub async fn refresh_source(pool: &SqlitePool, id: i64) -> RefreshOutcome {
    let mut outcome = RefreshOutcome {
        source_id: id, ok: false, rule_count: 0, bytes: 0,
        sha256: String::new(), error: None,
    };

    let sched = load_schedule(pool).await;
    if !sched.enabled {
        outcome.error = Some("blocklisting globally disabled — turn it on first".into());
        return outcome;
    }

    let Some(src) = load_source(pool, id).await else {
        outcome.error = Some("source not found".into());
        return outcome;
    };
    if !src.enabled {
        remove_blocklist_file(&rpz_path_for(id)).await;
        outcome.ok = true;
        return outcome;
    }

    let body = match fetch(&src.url).await {
        Ok(b) => b,
        Err(e) => {
            record_error(pool, id, &e).await;
            outcome.error = Some(e);
            return outcome;
        }
    };
    outcome.bytes = body.len();

    let sha = {
        let mut h = Sha256::new();
        h.update(&body);
        hex::encode(h.finalize())
    };
    outcome.sha256 = sha.clone();

    if Some(sha.as_str()) == src.last_sha256.as_deref() && rpz_path_for(id).exists() {
        record_unchanged(pool, id).await;
        outcome.ok = true;
        outcome.rule_count = src.rule_count;
        return outcome;
    }

    let zone_body = if src.format == "rpz" {
        String::from_utf8_lossy(&body).to_string()
    } else {
        let mut domains = parse_body(&body, &src.format);
        for w in load_whitelist(pool).await {
            let w = w.trim().trim_end_matches('.').to_ascii_lowercase();
            domains.remove(&w);
        }
        let zone = format!("rpz.blocklist-{id}");
        build_rpz(&domains, &src.action, src.redirect_ip.as_deref(), &zone)
    };

    let rule_count = zone_body.lines().filter(|l| {
        let l = l.trim();
        !l.is_empty() && !l.starts_with(';') && !l.starts_with('$') && !l.starts_with('@')
    }).count() as i64;

    if let Err(e) = atomic_write(&rpz_path_for(id), &zone_body).await {
        record_error(pool, id, &format!("write rpz: {e}")).await;
        outcome.error = Some(format!("write rpz: {e}"));
        return outcome;
    }

    record_success(pool, id, rule_count, &sha).await;
    outcome.ok = true;
    outcome.rule_count = rule_count;
    outcome
}

async fn record_success(pool: &SqlitePool, id: i64, rules: i64, sha: &str) {
    let now = chrono::Utc::now().timestamp();
    let _ = sqlx::query(r#"
        UPDATE dns_blocklist_source
           SET last_updated = ?, last_sha256 = ?, rule_count = ?, last_error = NULL
         WHERE id = ?
    "#).bind(now).bind(sha).bind(rules).bind(id).execute(pool).await;
}

async fn record_unchanged(pool: &SqlitePool, id: i64) {
    let now = chrono::Utc::now().timestamp();
    let _ = sqlx::query(
        "UPDATE dns_blocklist_source SET last_updated = ?, last_error = NULL WHERE id = ?"
    ).bind(now).bind(id).execute(pool).await;
}

async fn record_error(pool: &SqlitePool, id: i64, err: &str) {
    let _ = sqlx::query(
        "UPDATE dns_blocklist_source SET last_error = ? WHERE id = ?"
    ).bind(err).bind(id).execute(pool).await;
}

pub async fn rebuild_custom_rpz(pool: &SqlitePool) -> std::io::Result<i64> {
    let whitelist = load_whitelist(pool).await;
    let custom = load_custom_blocks(pool).await;
    let serial = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut out = format!(
        "$TTL 300\n@ IN SOA rpz.custom. admin.rpz.custom. {serial} 3600 900 604800 300\n  IN NS  localhost.\n"
    );
    for w in &whitelist {
        let d = w.trim().trim_end_matches('.');
        if d.is_empty() { continue; }
        out.push_str(&format!("{d} CNAME rpz-passthru.\n"));
    }
    for c in &custom {
        let d = c.trim().trim_end_matches('.');
        if d.is_empty() { continue; }
        out.push_str(&format!("{d} CNAME .\n"));
    }
    atomic_write(&custom_rpz_path(), &out).await?;
    Ok((whitelist.len() + custom.len()) as i64)
}

pub async fn refresh_all(pool: &SqlitePool) -> Vec<RefreshOutcome> {
    let sched = load_schedule(pool).await;
    if !sched.enabled {
        tracing::debug!("refresh_all: blocklisting globally disabled — skipping");
        return Vec::new();
    }
    let permits = Arc::new(Semaphore::new(sched.concurrency.max(1) as usize));
    let sources = load_all_sources(pool).await;

    let mut handles = Vec::new();
    for s in sources {
        if !s.enabled { continue; }
        let pool = pool.clone();
        let permits = permits.clone();
        handles.push(tokio::spawn(async move {
            let _p = permits.acquire().await.ok();
            refresh_source(&pool, s.id).await
        }));
    }

    let mut out = Vec::new();
    for h in handles {
        if let Ok(o) = h.await { out.push(o); }
    }
    if let Err(e) = rebuild_custom_rpz(pool).await {
        tracing::warn!("rebuild custom.rpz failed: {}", e);
    }
    if let Err(e) = trigger_rdns_reload().await {
        tracing::warn!("rdns reload failed: {}", e);
    }
    out
}

/// Send `reload-rpz` to the rDNS control socket and return the response.
pub async fn trigger_rdns_reload() -> std::io::Result<String> {
    let stream = tokio::net::UnixStream::connect(CONTROL_SOCKET).await?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(b"reload-rpz\n").await?;
    writer.flush().await?;
    let mut br = BufReader::new(reader);
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), br.read_line(&mut line)).await;
    Ok(line.trim().to_string())
}

// ============================================================================
// Scheduler — owned by the daemon, not the API
// ============================================================================

/// Spawn the cron-driven background scheduler. Call this from `aifw-daemon`.
/// Ticks every 60 s, runs jobs whose next-fire time has passed since the last
/// tick. Also runs all enabled sources on boot when `on_boot=1`.
pub fn spawn_scheduler(pool: SqlitePool) {
    tokio::spawn(async move {
        let sched = load_schedule(&pool).await;
        if sched.on_boot {
            tokio::time::sleep(Duration::from_secs(15)).await;
            tracing::info!("blocklist scheduler: running on-boot refresh");
            refresh_all(&pool).await;
        }

        let mut last_check = chrono::Utc::now();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let sched = load_schedule(&pool).await;
            let Ok(parsed) = cron::Schedule::try_from(sched.cron.as_str()) else {
                tracing::warn!(cron = %sched.cron, "invalid cron expression — skipping");
                continue;
            };
            let now = chrono::Utc::now();
            let due = parsed.after(&last_check).take_while(|t| t <= &now).count();
            last_check = now;
            if due > 0 {
                tracing::info!("blocklist scheduler: cron fire — refreshing all enabled sources");
                refresh_all(&pool).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_format() {
        let body = b"# comment\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.test\nlocalhost\n";
        let set = parse_body(body, "hosts");
        assert!(set.contains("ads.example.com"));
        assert!(set.contains("tracker.test"));
        assert!(!set.contains("localhost"));
    }

    #[test]
    fn parses_adblock_format() {
        let body = b"||example.com^\n||ads.test/\n!comment\n";
        let set = parse_body(body, "adblock");
        assert!(set.contains("example.com"));
        assert!(set.contains("ads.test"));
    }

    #[test]
    fn parses_domains_format() {
        let body = b"a.test\nb.test\n#skip\n*.wild.test\n";
        let set = parse_body(body, "domains");
        assert!(set.contains("a.test"));
        assert!(set.contains("b.test"));
        assert!(set.contains("wild.test"));
    }

    #[test]
    fn validates_pattern_basic() {
        assert!(validate_pattern("example.com").is_ok());
        assert!(validate_pattern("*.example.com").is_ok());
        assert!(validate_pattern("sub.example.com").is_ok());
        assert!(validate_pattern("nopd").is_err());
        assert!(validate_pattern("-bad.com").is_err());
        assert!(validate_pattern("bad-.com").is_err());
        assert!(validate_pattern("bad..com").is_err());
    }

    #[test]
    fn validates_url_basic() {
        assert!(validate_url("https://example.com/list.txt").is_ok());
        assert!(validate_url("http://foo.test/").is_ok());
        assert!(validate_url("ftp://x.test").is_err());
        assert!(validate_url("https://127.0.0.1/list").is_err());
        assert!(validate_url("https://192.168.1.1/list").is_err());
        assert!(validate_url("https://localhost/list").is_err());
    }

    #[test]
    fn rpz_build_basic() {
        let mut s = HashSet::new();
        s.insert("a.test".to_string());
        s.insert("b.test".to_string());
        let body = build_rpz(&s, "nxdomain", None, "rpz.x");
        assert!(body.contains("a.test CNAME .\n"));
        assert!(body.contains("b.test CNAME .\n"));
    }

    #[test]
    fn rpz_build_redirect_v4() {
        let mut s = HashSet::new();
        s.insert("a.test".into());
        let body = build_rpz(&s, "redirect", Some("0.0.0.0"), "rpz.x");
        assert!(body.contains("a.test A 0.0.0.0\n"));
    }
}
