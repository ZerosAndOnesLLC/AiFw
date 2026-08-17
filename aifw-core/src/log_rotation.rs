//! Log rotation for AiFw-managed service logs (#205).
//!
//! Every long-running AiFw service is supervised by daemon(8) with `-o`
//! pointing at its own log file. Nothing rotated those files, and a busy
//! appliance grew `rtime.log` to ~200 MB in days. This module owns one
//! global policy (size cap, retained generations, compression), renders it
//! into `/usr/local/etc/newsyslog.conf.d/aifw.conf`, and drives newsyslog
//! through the `aifw-sudo-newsyslog` helper. FreeBSD's stock
//! `/etc/newsyslog.conf` includes that directory, and cron runs newsyslog
//! hourly, so once the fragment exists rotation just happens.
//!
//! The rc.d scripts pass `-H` to daemon(8) so the SIGHUP newsyslog sends
//! to the supervisor pidfile makes it reopen `-o` on the fresh file; without
//! `-H` the supervisor keeps writing to the unlinked inode.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tracing::{info, warn};

use crate::{CoreError, Result};

/// Where the rendered fragment lives. Included by `/etc/newsyslog.conf`.
pub const CONF_PATH: &str = "/usr/local/etc/newsyslog.conf.d/aifw.conf";
const CONF_DIR: &str = "/usr/local/etc/newsyslog.conf.d";

/// Smallest allowed size cap (MB); mirrored in the UI form and CLI help.
pub const MIN_SIZE_MB: u32 = 1;
/// Largest allowed size cap (MB).
pub const MAX_SIZE_MB: u32 = 500;
/// Most rotated generations that may be retained.
pub const MAX_KEEP: u32 = 50;

/// One log file rotated by the policy.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ManagedLog {
    /// Service the log belongs to (display name).
    pub service: &'static str,
    /// Absolute path of the live log file.
    pub path: &'static str,
    /// daemon(8) supervisor pidfile that receives SIGHUP after rotation.
    pub pidfile: &'static str,
    /// `owner:group` newsyslog gives the freshly created file. Services
    /// that run under `daemon -u aifw` reopen the log as `aifw`, so their
    /// new file must be aifw-owned; root-run services keep root:aifw so
    /// aifw-api can still read them.
    pub owner: &'static str,
}

/// Every log the rc.d scripts write via `daemon(8) -o`. Keep in sync with
/// `freebsd/overlay/usr/local/etc/rc.d/*` and the `rotate` allowlist in
/// `freebsd/overlay/usr/local/libexec/aifw-sudo-newsyslog` (guard test
/// below). TrafficCop's access.log is deliberately absent: TrafficCop
/// holds it open itself and does not reopen on SIGHUP.
pub const MANAGED_LOGS: &[ManagedLog] = &[
    ManagedLog {
        service: "aifw-api",
        path: "/var/log/aifw/api.log",
        pidfile: "/var/run/aifw_api-supervisor.pid",
        owner: "aifw:aifw",
    },
    ManagedLog {
        service: "aifw-daemon",
        path: "/var/log/aifw/daemon.log",
        pidfile: "/var/run/aifw_daemon-supervisor.pid",
        owner: "aifw:aifw",
    },
    ManagedLog {
        service: "aifw-ids",
        path: "/var/log/aifw/ids.log",
        pidfile: "/var/run/aifw_ids-supervisor.pid",
        owner: "aifw:aifw",
    },
    ManagedLog {
        service: "aifw-watchdog",
        path: "/var/log/aifw/watchdog.log",
        pidfile: "/var/run/aifw_watchdog-supervisor.pid",
        owner: "root:aifw",
    },
    ManagedLog {
        service: "rDNS",
        path: "/var/log/rdns/rdns.log",
        pidfile: "/var/run/rdns/rdns-supervisor.pid",
        owner: "root:aifw",
    },
    ManagedLog {
        service: "rDHCP",
        path: "/var/log/rdhcpd/rdhcpd.log",
        pidfile: "/var/run/rdhcpd/rdhcpd-supervisor.pid",
        owner: "root:aifw",
    },
    ManagedLog {
        service: "rTIME",
        path: "/var/log/rtime/rtime.log",
        pidfile: "/var/run/rtime/rtime-supervisor.pid",
        owner: "root:aifw",
    },
    ManagedLog {
        service: "TrafficCop",
        path: "/var/log/trafficcop/trafficcop.log",
        pidfile: "/var/run/trafficcop/trafficcop-supervisor.pid",
        owner: "aifw:aifw",
    },
];

/// Compression applied to rotated generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    /// No compression.
    None,
    /// gzip (`newsyslog` flag `Z`) — the default; universally readable.
    #[default]
    Gzip,
    /// bzip2 (`J`).
    Bzip2,
    /// xz (`X`).
    Xz,
    /// zstd (`Y`).
    Zstd,
}

impl Compression {
    /// newsyslog flag letter for this compression, empty for none.
    pub fn flag(self) -> &'static str {
        match self {
            Compression::None => "",
            Compression::Gzip => "Z",
            Compression::Bzip2 => "J",
            Compression::Xz => "X",
            Compression::Zstd => "Y",
        }
    }

    /// Wire / CLI name.
    pub fn as_str(self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Gzip => "gzip",
            Compression::Bzip2 => "bzip2",
            Compression::Xz => "xz",
            Compression::Zstd => "zstd",
        }
    }

    /// Parse a CLI / DB value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" => Some(Compression::None),
            "gzip" | "gz" => Some(Compression::Gzip),
            "bzip2" | "bz2" => Some(Compression::Bzip2),
            "xz" => Some(Compression::Xz),
            "zstd" | "zst" => Some(Compression::Zstd),
            _ => None,
        }
    }
}

/// The single global rotation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Rotate a log once it exceeds this many MB (1–500).
    pub max_size_mb: u32,
    /// Rotated generations to keep (0–50); 0 = truncate, keep nothing.
    pub keep: u32,
    /// Compression for rotated generations.
    #[serde(default)]
    pub compression: Compression,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_size_mb: 5,
            keep: 7,
            compression: Compression::Gzip,
        }
    }
}

impl LogRotationConfig {
    /// Reject out-of-range values before they reach the DB or newsyslog.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !(MIN_SIZE_MB..=MAX_SIZE_MB).contains(&self.max_size_mb) {
            return Err(format!(
                "max_size_mb must be between {MIN_SIZE_MB} and {MAX_SIZE_MB}"
            ));
        }
        if self.keep > MAX_KEEP {
            return Err(format!("keep must be between 0 and {MAX_KEEP}"));
        }
        Ok(())
    }
}

/// Render the newsyslog fragment for `cfg`. Pure — unit-tested against a
/// golden string; `apply` writes the result.
pub fn render_conf(cfg: &LogRotationConfig) -> String {
    // Flags: B = don't write a "logfile turned over" line into a log another
    // program owns, plus the compression letter. No C (create-if-missing):
    // a service that has never started has no log dir yet and C would make
    // every hourly cron pass complain; newsyslog always creates the fresh
    // file after an actual rotation regardless. Size is in KB. `*` for
    // `when` = size-only rotation. Signal 1 = SIGHUP to the supervisor,
    // which daemon(8) -H turns into a reopen.
    let size_kb = cfg.max_size_mb * 1024;
    let flags = format!("B{}", cfg.compression.flag());
    let mut out = String::new();
    out.push_str(
        "# AiFw log rotation — generated by aifw-api / `aifw logrotate`; edits are overwritten.\n",
    );
    out.push_str("# Policy: rotate above ");
    out.push_str(&format!(
        "{} MB, keep {}, compression {}.\n",
        cfg.max_size_mb,
        cfg.keep,
        cfg.compression.as_str()
    ));
    out.push_str("# logfilename                     [owner:group]  mode  count  size   when  flags  [/pid_file]  [sig_num]\n");
    for log in MANAGED_LOGS {
        out.push_str(&format!(
            "{:<33} {:<13} 640   {:<6} {:<6} *     {:<6} {}  1\n",
            log.path, log.owner, cfg.keep, size_kb, flags, log.pidfile
        ));
    }
    out
}

/// Load the stored policy (defaults if the row is missing or unreadable).
pub async fn load(pool: &SqlitePool) -> LogRotationConfig {
    let row = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT max_size_mb, keep, compression FROM log_rotation_config WHERE id = 1",
    )
    .fetch_optional(pool)
    .await;
    match row {
        Ok(Some((size, keep, comp))) => LogRotationConfig {
            max_size_mb: u32::try_from(size).unwrap_or(5),
            keep: u32::try_from(keep).unwrap_or(7),
            compression: Compression::parse(&comp).unwrap_or_default(),
        },
        Ok(None) => LogRotationConfig::default(),
        Err(e) => {
            warn!(error = %e, "log_rotation: config read failed, using defaults");
            LogRotationConfig::default()
        }
    }
}

const SAVE_SQL: &str =
    "INSERT INTO log_rotation_config (id, max_size_mb, keep, compression, updated_at)
         VALUES (1, ?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
         ON CONFLICT(id) DO UPDATE SET
           max_size_mb = excluded.max_size_mb,
           keep = excluded.keep,
           compression = excluded.compression,
           updated_at = excluded.updated_at";

/// Persist the policy (validated).
pub async fn save(pool: &SqlitePool, cfg: &LogRotationConfig) -> Result<()> {
    cfg.validate().map_err(CoreError::Validation)?;
    sqlx::query(SAVE_SQL)
        .bind(i64::from(cfg.max_size_mb))
        .bind(i64::from(cfg.keep))
        .bind(cfg.compression.as_str())
        .execute(pool)
        .await?;
    Ok(())
}

/// Persist inside a caller-owned transaction (config restore). Validation
/// is the caller's job (`FirewallConfig::validate`).
pub async fn save_on(
    conn: &mut sqlx::SqliteConnection,
    cfg: &LogRotationConfig,
) -> std::result::Result<(), sqlx::Error> {
    sqlx::query(SAVE_SQL)
        .bind(i64::from(cfg.max_size_mb))
        .bind(i64::from(cfg.keep))
        .bind(cfg.compression.as_str())
        .execute(conn)
        .await?;
    Ok(())
}

/// Write the fragment for `cfg` to [`CONF_PATH`] (as root, via the sudo
/// write helper). Returns whether anything changed on disk.
pub async fn write_conf(cfg: &LogRotationConfig) -> Result<bool> {
    let rendered = render_conf(cfg);
    if let Ok(existing) = tokio::fs::read_to_string(CONF_PATH).await
        && existing == rendered
    {
        return Ok(false);
    }
    if !Path::new(CONF_DIR).is_dir() {
        let out = crate::sudo::mkdir(&["-p", CONF_DIR]).await?;
        if !out.status.success() {
            return Err(CoreError::Io(std::io::Error::other(format!(
                "mkdir {CONF_DIR}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))));
        }
    }
    crate::sudo::write_file(Path::new(CONF_PATH), rendered.as_bytes()).await?;
    info!(path = CONF_PATH, "log_rotation: newsyslog fragment written");
    Ok(true)
}

/// Run one newsyslog pass over the AiFw fragment (rotates anything already
/// over its limit). Cron does this hourly anyway; this is for "apply now".
pub async fn run_now() -> Result<String> {
    let out = crate::sudo::newsyslog(&["run"]).await?;
    newsyslog_result(out)
}

/// Force-rotate one managed log regardless of size.
pub async fn rotate_now(path: &str) -> Result<String> {
    if !MANAGED_LOGS.iter().any(|l| l.path == path) {
        return Err(CoreError::Validation(format!(
            "{path} is not an AiFw-managed log"
        )));
    }
    let out = crate::sudo::newsyslog(&["rotate", path]).await?;
    newsyslog_result(out)
}

fn newsyslog_result(out: std::process::Output) -> Result<String> {
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if out.status.success() {
        Ok(if stdout.is_empty() {
            "newsyslog: nothing to rotate".to_string()
        } else {
            stdout
        })
    } else {
        Err(CoreError::Other(format!(
            "newsyslog failed ({}): {}",
            out.status,
            if stderr.is_empty() { stdout } else { stderr }
        )))
    }
}

/// Startup reconcile: make sure the fragment on disk matches the stored
/// policy. Cheap when nothing changed (one file read). Best-effort —
/// failures are logged, never fatal, and on non-FreeBSD hosts (dev/WSL)
/// this is a no-op because the sudo helpers don't exist there.
pub async fn ensure_applied(pool: &SqlitePool) {
    if !cfg!(target_os = "freebsd") {
        return;
    }
    let cfg = load(pool).await;
    match write_conf(&cfg).await {
        Ok(true) => info!(
            max_size_mb = cfg.max_size_mb,
            keep = cfg.keep,
            compression = cfg.compression.as_str(),
            "log_rotation: policy applied"
        ),
        Ok(false) => {}
        Err(e) => warn!(error = %e, "log_rotation: could not write newsyslog fragment"),
    }
}

/// Current on-disk state of one managed log, for the status panel.
#[derive(Debug, Clone, Serialize)]
pub struct LogStatus {
    /// Service display name.
    pub service: &'static str,
    /// Live log path.
    pub path: &'static str,
    /// Size of the live file in bytes, `None` if missing/unreadable.
    pub size_bytes: Option<u64>,
    /// Number of rotated generations present (`<path>.0.gz`, `.1.gz`, …).
    pub rotated: u32,
    /// Total bytes across live + rotated generations.
    pub total_bytes: u64,
}

/// Inspect every managed log. Uses plain metadata calls (the log dirs are
/// world-listable and the files group-readable by `aifw`); anything not
/// visible reports `size_bytes: None`.
pub async fn status() -> Vec<LogStatus> {
    let mut out = Vec::with_capacity(MANAGED_LOGS.len());
    for log in MANAGED_LOGS {
        let size = tokio::fs::metadata(log.path).await.ok().map(|m| m.len());
        let (rotated, rotated_bytes) = rotated_generations(log.path).await;
        out.push(LogStatus {
            service: log.service,
            path: log.path,
            size_bytes: size,
            rotated,
            total_bytes: size.unwrap_or(0) + rotated_bytes,
        });
    }
    out
}

/// Count `<file>.<n>[.gz|.bz2|.xz|.zst]` siblings and sum their sizes.
async fn rotated_generations(path: &str) -> (u32, u64) {
    let p = Path::new(path);
    let (Some(dir), Some(name)) = (p.parent(), p.file_name().and_then(|n| n.to_str())) else {
        return (0, 0);
    };
    let Ok(mut rd) = tokio::fs::read_dir(dir).await else {
        return (0, 0);
    };
    let prefix = format!("{name}.");
    let mut count = 0u32;
    let mut bytes = 0u64;
    while let Ok(Some(entry)) = rd.next_entry().await {
        let fname = entry.file_name();
        let Some(fname) = fname.to_str() else {
            continue;
        };
        let Some(rest) = fname.strip_prefix(&prefix) else {
            continue;
        };
        // rest = "0", "0.gz", "12.bz2", …
        let generation = rest.split('.').next().unwrap_or("");
        if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        count += 1;
        if let Ok(md) = entry.metadata().await {
            bytes += md.len();
        }
    }
    (count, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_policy() {
        let d = LogRotationConfig::default();
        assert_eq!(d.max_size_mb, 5);
        assert_eq!(d.keep, 7);
        assert_eq!(d.compression, Compression::Gzip);
        assert!(d.validate().is_ok());
    }

    #[test]
    fn validation_bounds() {
        let mut c = LogRotationConfig {
            max_size_mb: 0,
            ..LogRotationConfig::default()
        };
        assert!(c.validate().is_err());
        c.max_size_mb = 501;
        assert!(c.validate().is_err());
        c.max_size_mb = 500;
        assert!(c.validate().is_ok());
        c.keep = 51;
        assert!(c.validate().is_err());
        c.keep = 0;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn compression_round_trips() {
        for c in [
            Compression::None,
            Compression::Gzip,
            Compression::Bzip2,
            Compression::Xz,
            Compression::Zstd,
        ] {
            assert_eq!(Compression::parse(c.as_str()), Some(c));
        }
        assert_eq!(Compression::parse("gz"), Some(Compression::Gzip));
        assert_eq!(Compression::parse("lz4"), None);
    }

    #[test]
    fn render_produces_one_line_per_managed_log() {
        let cfg = LogRotationConfig {
            max_size_mb: 10,
            keep: 3,
            compression: Compression::Zstd,
        };
        let conf = render_conf(&cfg);
        let entries: Vec<&str> = conf.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(entries.len(), MANAGED_LOGS.len());
        let rdns = entries
            .iter()
            .find(|l| l.starts_with("/var/log/rdns/rdns.log"))
            .expect("rdns entry");
        let cols: Vec<&str> = rdns.split_whitespace().collect();
        assert_eq!(
            cols,
            vec![
                "/var/log/rdns/rdns.log",
                "root:aifw",
                "640",
                "3",
                "10240",
                "*",
                "BY",
                "/var/run/rdns/rdns-supervisor.pid",
                "1"
            ]
        );
        // aifw-run services get aifw-owned files so daemon -H can reopen them
        let api = entries
            .iter()
            .find(|l| l.starts_with("/var/log/aifw/api.log"))
            .expect("api entry");
        assert_eq!(api.split_whitespace().nth(1), Some("aifw:aifw"));
        // no compression flag when off
        let plain = render_conf(&LogRotationConfig {
            compression: Compression::None,
            ..LogRotationConfig::default()
        });
        assert!(plain.lines().any(|l| l.contains(" B ")));
    }

    /// Guard: the helper's `rotate` allowlist and MANAGED_LOGS must agree,
    /// or "Rotate now" silently fails for a log (same drift family as the
    /// sudoers guard in aifw-setup).
    #[test]
    fn helper_rotate_allowlist_matches_managed_logs() {
        let helper = include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-newsyslog");
        for log in MANAGED_LOGS {
            assert!(
                helper.contains(log.path),
                "aifw-sudo-newsyslog rotate allowlist is missing {}",
                log.path
            );
        }
    }

    /// Guard: every managed log path/pidfile is what the rc.d overlay
    /// actually uses, and every daemon(8) invocation carries -H so the
    /// SIGHUP reopens the log instead of being ignored.
    #[test]
    fn rc_scripts_match_managed_logs_and_pass_dash_h() {
        let rcd = |name: &str| -> String {
            std::fs::read_to_string(format!(
                "{}/../freebsd/overlay/usr/local/etc/rc.d/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap_or_else(|e| panic!("read rc.d/{name}: {e}"))
        };
        let scripts = [
            ("aifw_api", "/var/log/aifw/api.log"),
            ("aifw_daemon", "/var/log/aifw/daemon.log"),
            ("aifw_ids", "/var/log/aifw/ids.log"),
            ("aifw_watchdog", "/var/log/aifw/watchdog.log"),
            ("rdns", "/var/log/rdns/rdns.log"),
            ("rdhcpd", "/var/log/rdhcpd/rdhcpd.log"),
            ("rtime", "/var/log/rtime/rtime.log"),
            ("trafficcop", "/var/log/trafficcop/trafficcop.log"),
        ];
        assert_eq!(scripts.len(), MANAGED_LOGS.len());
        for (name, path) in scripts {
            let body = rcd(name);
            let log = MANAGED_LOGS
                .iter()
                .find(|l| l.path == path)
                .unwrap_or_else(|| panic!("{path} not in MANAGED_LOGS"));
            assert!(body.contains(&format!("-o {path}")), "{name}: -o {path}");
            assert!(
                body.contains(&format!("{}\"", log.pidfile)),
                "{name}: supervisor pidfile {}",
                log.pidfile
            );
            let cmd = body
                .lines()
                .find(|l| l.starts_with("command_args="))
                .unwrap_or_else(|| panic!("{name}: no command_args"));
            assert!(cmd.contains(" -H "), "{name}: daemon(8) must pass -H");
        }
    }

    #[tokio::test]
    async fn save_and_load_round_trip() {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        assert_eq!(load(pool).await, LogRotationConfig::default());
        let cfg = LogRotationConfig {
            max_size_mb: 20,
            keep: 2,
            compression: Compression::None,
        };
        save(pool, &cfg).await.unwrap();
        assert_eq!(load(pool).await, cfg);
        let bad = LogRotationConfig {
            max_size_mb: 0,
            ..cfg
        };
        assert!(save(pool, &bad).await.is_err());
        assert_eq!(load(pool).await, cfg, "invalid save must not persist");
    }
}
