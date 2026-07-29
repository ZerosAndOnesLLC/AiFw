//! Remote syslog configuration: the `syslog_config` singleton row.

use serde::{Deserialize, Serialize};
use sqlx::{SqliteConnection, SqlitePool};

/// How syslog messages travel to the server. Wire values are lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Classic fire-and-forget datagrams (RFC 5426-style)
    #[default]
    Udp,
    /// Stream with LF framing (RFC 6587 non-transparent), reconnects with backoff
    Tcp,
}

impl Transport {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            _ => Transport::Udp,
        }
    }
    /// Lowercase wire/DB value (`udp` / `tcp`)
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// On-the-wire message format. Wire values are lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    /// BSD syslog (RFC 3164): `<PRI>MMM dd HH:MM:SS host app[pid]: msg`
    #[default]
    Rfc3164,
    /// Modern syslog (RFC 5424): `<PRI>1 TIMESTAMP host app pid - - msg`
    Rfc5424,
}

impl SyslogFormat {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "rfc5424" => SyslogFormat::Rfc5424,
            _ => SyslogFormat::Rfc3164,
        }
    }
    /// Lowercase wire/DB value (`rfc3164` / `rfc5424`)
    pub fn as_str(self) -> &'static str {
        match self {
            SyslogFormat::Rfc3164 => "rfc3164",
            SyslogFormat::Rfc5424 => "rfc5424",
        }
    }
}

/// Log category a message belongs to; each has its own enable toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// pf packet logs (pass/block lines captured from pflog0)
    Pf,
    /// IDS alerts
    Ids,
    /// Application logs (tracing output of the AiFw services)
    App,
}

/// Remote syslog settings — a singleton row (`syslog_config`, id = 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Master switch; when false nothing is forwarded (test-send still works)
    pub enabled: bool,
    /// Syslog server hostname or IP; empty means unconfigured
    pub host: String,
    /// Syslog server port (default 514)
    pub port: u16,
    /// UDP or TCP (default UDP)
    #[serde(default)]
    pub transport: Transport,
    /// BSD (RFC 3164) or RFC 5424 framing (default BSD)
    #[serde(default)]
    pub format: SyslogFormat,
    /// Syslog facility 0-23 (default 16 = local0)
    pub facility: u8,
    /// HOSTNAME field override; empty = use the system hostname
    #[serde(default)]
    pub hostname_override: String,
    /// Forward pf packet logs
    #[serde(default)]
    pub pf_enabled: bool,
    /// Forward IDS alerts
    #[serde(default)]
    pub ids_enabled: bool,
    /// Forward application (tracing) logs
    #[serde(default)]
    pub app_enabled: bool,
    /// Minimum app-log level forwarded: `error` | `warn` | `info` | `debug`
    #[serde(default = "default_app_min_level")]
    pub app_min_level: String,
    /// Stop writing local log files (pf log file + app stdout logs) while
    /// remote forwarding is active. IDS alerts always stay in the local DB.
    #[serde(default)]
    pub disable_local: bool,
}

fn default_app_min_level() -> String {
    "info".into()
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 514,
            transport: Transport::Udp,
            format: SyslogFormat::Rfc3164,
            facility: 16,
            hostname_override: String::new(),
            pf_enabled: false,
            ids_enabled: false,
            app_enabled: false,
            app_min_level: default_app_min_level(),
            disable_local: false,
        }
    }
}

/// Valid `app_min_level` values, most to least severe.
const APP_LEVELS: [&str; 4] = ["error", "warn", "info", "debug"];

impl SyslogConfig {
    /// Human-readable validation for API/CLI input.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.host.trim().is_empty() {
            return Err("host is required when remote syslog is enabled".into());
        }
        if self.host.len() > 255 {
            return Err("host must be at most 255 characters".into());
        }
        if self
            .host
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_control())
        {
            return Err("host must not contain whitespace or control characters".into());
        }
        if self.port == 0 {
            return Err("port must be 1-65535".into());
        }
        if self.facility > 23 {
            return Err("facility must be 0-23".into());
        }
        if self.hostname_override.len() > 255 {
            return Err("hostname_override must be at most 255 characters".into());
        }
        if self
            .hostname_override
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_control())
        {
            return Err(
                "hostname_override must not contain whitespace or control characters".into(),
            );
        }
        if !APP_LEVELS.contains(&self.app_min_level.as_str()) {
            return Err(format!(
                "app_min_level must be one of: {}",
                APP_LEVELS.join(", ")
            ));
        }
        Ok(())
    }

    /// True when forwarding is on overall and for this category.
    pub fn category_enabled(&self, cat: Category) -> bool {
        self.enabled
            && !self.host.is_empty()
            && match cat {
                Category::Pf => self.pf_enabled,
                Category::Ids => self.ids_enabled,
                Category::App => self.app_enabled,
            }
    }

    /// Rank of `app_min_level` for comparisons: error=3 … debug=7 (syslog
    /// severity numbers; a message passes when its severity <= this).
    pub fn app_min_severity(&self) -> u8 {
        match self.app_min_level.as_str() {
            "error" => 3,
            "warn" => 4,
            "debug" => 7,
            _ => 6, // info
        }
    }
}

/// Well-known facility names, indexed by facility number 0-23.
const FACILITY_NAMES: [&str; 24] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

/// Parse a facility given as a name (`local0`, `daemon`, …) or a number 0-23.
pub fn facility_from_name(s: &str) -> Option<u8> {
    let lower = s.to_ascii_lowercase();
    if let Some(idx) = FACILITY_NAMES.iter().position(|n| *n == lower) {
        return Some(idx as u8);
    }
    lower.parse::<u8>().ok().filter(|n| *n <= 23)
}

/// Name for a facility number, or `None` when out of range.
pub fn facility_name(facility: u8) -> Option<&'static str> {
    FACILITY_NAMES.get(facility as usize).copied()
}

/// Create the `syslog_config` table if missing and seed the singleton row.
/// Idempotent; called at startup by all AiFw services.
pub async fn migrate(pool: &SqlitePool) -> crate::Result<()> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS syslog_config (
            id                INTEGER PRIMARY KEY CHECK (id = 1),
            enabled           INTEGER NOT NULL DEFAULT 0,
            host              TEXT    NOT NULL DEFAULT '',
            port              INTEGER NOT NULL DEFAULT 514,
            transport         TEXT    NOT NULL DEFAULT 'udp',
            format            TEXT    NOT NULL DEFAULT 'rfc3164',
            facility          INTEGER NOT NULL DEFAULT 16,
            hostname_override TEXT    NOT NULL DEFAULT '',
            pf_enabled        INTEGER NOT NULL DEFAULT 0,
            ids_enabled       INTEGER NOT NULL DEFAULT 0,
            app_enabled       INTEGER NOT NULL DEFAULT 0,
            app_min_level     TEXT    NOT NULL DEFAULT 'info',
            disable_local     INTEGER NOT NULL DEFAULT 0
        )"#,
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT OR IGNORE INTO syslog_config (id) VALUES (1)")
        .execute(pool)
        .await?;
    Ok(())
}

type Row = (
    i64,
    String,
    i64,
    String,
    String,
    i64,
    String,
    i64,
    i64,
    i64,
    String,
    i64,
);

fn row_to_config(r: Row) -> SyslogConfig {
    let (
        enabled,
        host,
        port,
        transport,
        format,
        facility,
        hostname_override,
        pf_enabled,
        ids_enabled,
        app_enabled,
        app_min_level,
        disable_local,
    ) = r;
    SyslogConfig {
        enabled: enabled != 0,
        host,
        port: port as u16,
        transport: Transport::from_str(&transport),
        format: SyslogFormat::from_str(&format),
        facility: (facility as u8).min(23),
        hostname_override,
        pf_enabled: pf_enabled != 0,
        ids_enabled: ids_enabled != 0,
        app_enabled: app_enabled != 0,
        app_min_level,
        disable_local: disable_local != 0,
    }
}

const LOAD_SQL: &str = r#"SELECT enabled, host, port, transport, format, facility,
        hostname_override, pf_enabled, ids_enabled, app_enabled, app_min_level, disable_local
      FROM syslog_config WHERE id = 1"#;

/// Read the singleton config row. A missing row (fresh DB) is defaults; a
/// query error (e.g. SQLITE_BUSY on the shared WAL database) is an `Err` so
/// callers can distinguish "not configured" from "could not read" — the
/// config pollers must NOT treat a transient read failure as "forwarding
/// was disabled".
pub async fn try_load(pool: &SqlitePool) -> Result<SyslogConfig, sqlx::Error> {
    Ok(sqlx::query_as::<_, Row>(LOAD_SQL)
        .fetch_optional(pool)
        .await?
        .map(row_to_config)
        .unwrap_or_default())
}

/// Read the singleton config row; falls back to defaults if missing or on
/// error (logged). Use [`try_load`] where a transient failure must not be
/// mistaken for a disabled config.
pub async fn load(pool: &SqlitePool) -> SyslogConfig {
    match try_load(pool).await {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load syslog config; using defaults");
            SyslogConfig::default()
        }
    }
}

const SAVE_SQL: &str = r#"UPDATE syslog_config
      SET enabled=?, host=?, port=?, transport=?, format=?, facility=?,
          hostname_override=?, pf_enabled=?, ids_enabled=?, app_enabled=?,
          app_min_level=?, disable_local=?
    WHERE id=1"#;

/// Persist the singleton config row.
pub async fn save(pool: &SqlitePool, cfg: &SyslogConfig) -> crate::Result<()> {
    bind_save(sqlx::query(SAVE_SQL), cfg).execute(pool).await?;
    Ok(())
}

/// Persist within an existing transaction/connection (config-restore path).
pub async fn save_on(conn: &mut SqliteConnection, cfg: &SyslogConfig) -> Result<(), sqlx::Error> {
    bind_save(sqlx::query(SAVE_SQL), cfg).execute(conn).await?;
    Ok(())
}

fn bind_save<'q>(
    q: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>,
    cfg: &'q SyslogConfig,
) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
    q.bind(cfg.enabled as i64)
        .bind(&cfg.host)
        .bind(cfg.port as i64)
        .bind(cfg.transport.as_str())
        .bind(cfg.format.as_str())
        .bind(cfg.facility as i64)
        .bind(&cfg.hostname_override)
        .bind(cfg.pf_enabled as i64)
        .bind(cfg.ids_enabled as i64)
        .bind(cfg.app_enabled as i64)
        .bind(&cfg.app_min_level)
        .bind(cfg.disable_local as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_pool() -> SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite always connects")
    }

    #[tokio::test]
    async fn defaults_when_table_missing() {
        let pool = mem_pool().await;
        assert_eq!(load(&pool).await, SyslogConfig::default());
    }

    #[tokio::test]
    async fn save_load_round_trip() {
        let pool = mem_pool().await;
        migrate(&pool).await.unwrap();
        assert_eq!(load(&pool).await, SyslogConfig::default());

        let cfg = SyslogConfig {
            enabled: true,
            host: "192.0.2.10".into(),
            port: 5514,
            transport: Transport::Tcp,
            format: SyslogFormat::Rfc5424,
            facility: 17,
            hostname_override: "fw1".into(),
            pf_enabled: true,
            ids_enabled: true,
            app_enabled: true,
            app_min_level: "warn".into(),
            disable_local: true,
        };
        save(&pool, &cfg).await.unwrap();
        assert_eq!(load(&pool).await, cfg);
        // migrate is idempotent and must not clobber the row
        migrate(&pool).await.unwrap();
        assert_eq!(load(&pool).await, cfg);
    }

    #[test]
    fn validate_rejects_bad_input() {
        let mut cfg = SyslogConfig {
            enabled: true,
            host: "log.example.com".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok());

        cfg.host.clear();
        assert!(cfg.validate().is_err()); // enabled without host

        cfg.host = "h".repeat(256);
        assert!(cfg.validate().is_err());

        cfg.host = "ok".into();
        cfg.port = 0;
        assert!(cfg.validate().is_err());

        cfg.port = 514;
        cfg.facility = 24;
        assert!(cfg.validate().is_err());

        cfg.facility = 23;
        cfg.app_min_level = "verbose".into();
        assert!(cfg.validate().is_err());

        cfg.app_min_level = "info".into();
        cfg.host = "log server".into(); // whitespace in host
        assert!(cfg.validate().is_err());
        cfg.host = "log\nserver".into(); // control char in host
        assert!(cfg.validate().is_err());
        cfg.host = "192.0.2.1".into();
        cfg.hostname_override = "fw one".into(); // whitespace in override
        assert!(cfg.validate().is_err());
        cfg.hostname_override = "h".repeat(256);
        assert!(cfg.validate().is_err());
        cfg.hostname_override = "fw1".into();
        assert!(cfg.validate().is_ok());
        // Bare IPv6 literals are valid hosts (bracketed on the wire).
        cfg.host = "2001:db8::1".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn category_gating() {
        let cfg = SyslogConfig {
            enabled: true,
            host: "s".into(),
            pf_enabled: true,
            ..Default::default()
        };
        assert!(cfg.category_enabled(Category::Pf));
        assert!(!cfg.category_enabled(Category::Ids));
        assert!(!cfg.category_enabled(Category::App));
        let off = SyslogConfig {
            enabled: false,
            ..cfg.clone()
        };
        assert!(!off.category_enabled(Category::Pf));
    }

    #[test]
    fn facility_names_round_trip() {
        assert_eq!(facility_from_name("local0"), Some(16));
        assert_eq!(facility_from_name("LOCAL7"), Some(23));
        assert_eq!(facility_from_name("daemon"), Some(3));
        assert_eq!(facility_from_name("4"), Some(4));
        assert_eq!(facility_from_name("24"), None);
        assert_eq!(facility_from_name("nope"), None);
        assert_eq!(facility_name(16), Some("local0"));
        assert_eq!(facility_name(24), None);
    }

    #[test]
    fn app_min_severity_ranks() {
        let mut cfg = SyslogConfig::default();
        assert_eq!(cfg.app_min_severity(), 6);
        cfg.app_min_level = "error".into();
        assert_eq!(cfg.app_min_severity(), 3);
        cfg.app_min_level = "debug".into();
        assert_eq!(cfg.app_min_severity(), 7);
    }
}
