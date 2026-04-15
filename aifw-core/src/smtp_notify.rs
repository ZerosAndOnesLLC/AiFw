//! SMTP notification engine.
//!
//! Fires on backup-related events (config saved, S3 upload ok/failed,
//! restore ok/failed, retention prune). Which events actually send mail
//! is per-event configurable via a bitfield so operators can subscribe
//! to failures only (the default) and opt into success noise separately.

use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::time::Duration;

// ============================================================================
// Events
// ============================================================================

/// Notification event types. Bit positions are stable across releases; do
/// not reorder — mask values are persisted in the DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Event {
    BackupSaved,
    S3UploadOk,
    S3UploadFailed,
    RestoreOk,
    RestoreFailed,
    Pruned,
}

impl Event {
    fn bit(self) -> u32 {
        match self {
            Event::BackupSaved   => 1 << 0,
            Event::S3UploadOk    => 1 << 1,
            Event::S3UploadFailed=> 1 << 2,
            Event::RestoreOk     => 1 << 3,
            Event::RestoreFailed => 1 << 4,
            Event::Pruned        => 1 << 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Event::BackupSaved   => "Config snapshot saved",
            Event::S3UploadOk    => "S3 upload succeeded",
            Event::S3UploadFailed=> "S3 upload failed",
            Event::RestoreOk     => "Restore succeeded",
            Event::RestoreFailed => "Restore failed",
            Event::Pruned        => "Versions pruned",
        }
    }

    pub fn subject(self) -> &'static str {
        match self {
            Event::BackupSaved   => "AiFw: config snapshot saved",
            Event::S3UploadOk    => "AiFw: S3 backup uploaded",
            Event::S3UploadFailed=> "AiFw: S3 backup FAILED",
            Event::RestoreOk     => "AiFw: config restored",
            Event::RestoreFailed => "AiFw: config restore FAILED",
            Event::Pruned        => "AiFw: versions pruned",
        }
    }
}

/// Default enabled set: failures only. Everything else is opt-in so a busy
/// appliance doesn't flood the inbox on every auto-snapshot.
fn default_enabled_mask() -> u32 {
    Event::S3UploadFailed.bit() | Event::RestoreFailed.bit()
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    None,
    StartTls,
    ImplicitTls,
}

impl Default for TlsMode {
    fn default() -> Self { TlsMode::StartTls }
}

impl TlsMode {
    fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "none"        => TlsMode::None,
            "implicit"|"implicittls"|"tls" => TlsMode::ImplicitTls,
            _             => TlsMode::StartTls,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            TlsMode::None        => "none",
            TlsMode::StartTls    => "starttls",
            TlsMode::ImplicitTls => "implicit",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    #[serde(default)]
    pub username: Option<String>,
    /// Password is write-only — GET returns `""` if set, `null` otherwise.
    #[serde(default)]
    pub password: Option<String>,
    pub from_address: String,
    /// Comma-separated list of RFC 5322 recipients.
    pub recipients: String,
    /// Bitmask of [`Event`]. Defaults to failures-only.
    pub enabled_events: u32,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: 587,
            tls: TlsMode::StartTls,
            username: None,
            password: None,
            from_address: "aifw@localhost".into(),
            recipients: String::new(),
            enabled_events: default_enabled_mask(),
        }
    }
}

impl SmtpConfig {
    pub fn is_event_enabled(&self, ev: Event) -> bool {
        self.enabled && self.enabled_events & ev.bit() != 0
    }
}

// ============================================================================
// Schema
// ============================================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS smtp_notify_config (
            id             INTEGER PRIMARY KEY CHECK (id = 1),
            enabled        INTEGER NOT NULL DEFAULT 0,
            host           TEXT    NOT NULL DEFAULT '',
            port           INTEGER NOT NULL DEFAULT 587,
            tls            TEXT    NOT NULL DEFAULT 'starttls',
            username       TEXT,
            password       TEXT,
            from_address   TEXT    NOT NULL DEFAULT 'aifw@localhost',
            recipients     TEXT    NOT NULL DEFAULT '',
            enabled_events INTEGER NOT NULL DEFAULT 4 -- S3UploadFailed (bit 2)
        )"#,
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT OR IGNORE INTO smtp_notify_config (id) VALUES (1)")
        .execute(pool)
        .await?;
    // Back-fill the mask default for old rows that stored 0.
    sqlx::query(
        "UPDATE smtp_notify_config SET enabled_events = ?1 WHERE id = 1 AND enabled_events = 0",
    )
    .bind(default_enabled_mask() as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn load(pool: &SqlitePool) -> SmtpConfig {
    sqlx::query_as::<_, (i64, String, i64, String, Option<String>, Option<String>, String, String, i64)>(
        r#"SELECT enabled, host, port, tls, username, password, from_address, recipients, enabled_events
             FROM smtp_notify_config WHERE id = 1"#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(enabled, host, port, tls, u, p, from_address, recipients, mask)| SmtpConfig {
        enabled: enabled != 0,
        host,
        port: port as u16,
        tls: TlsMode::from_str(&tls),
        username: u,
        password: p,
        from_address,
        recipients,
        enabled_events: mask as u32,
    })
    .unwrap_or_default()
}

/// See [`s3_backup::save`] for the same `None` vs `Some("")` secret dance.
pub async fn save(pool: &SqlitePool, cfg: &SmtpConfig) -> Result<(), String> {
    let existing = load(pool).await;
    let final_password = match cfg.password.as_deref() {
        None => existing.password,
        Some("") => None,
        Some(v) => Some(v.to_string()),
    };
    sqlx::query(
        r#"UPDATE smtp_notify_config
              SET enabled=?, host=?, port=?, tls=?, username=?, password=?,
                  from_address=?, recipients=?, enabled_events=?
            WHERE id=1"#,
    )
    .bind(cfg.enabled as i64)
    .bind(&cfg.host)
    .bind(cfg.port as i64)
    .bind(cfg.tls.as_str())
    .bind(&cfg.username)
    .bind(&final_password)
    .bind(&cfg.from_address)
    .bind(&cfg.recipients)
    .bind(cfg.enabled_events as i64)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================================
// Transport
// ============================================================================

fn build_transport(cfg: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    if cfg.host.trim().is_empty() {
        return Err("SMTP host is required".into());
    }
    let mut builder = match cfg.tls {
        TlsMode::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
        TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|e| format!("starttls relay: {e}"))?,
        TlsMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
            .map_err(|e| format!("tls relay: {e}"))?,
    }
    .port(cfg.port)
    .timeout(Some(Duration::from_secs(20)));

    if let (Some(user), Some(pass)) = (cfg.username.as_deref().filter(|s| !s.is_empty()),
                                       cfg.password.as_deref().filter(|s| !s.is_empty())) {
        builder = builder.credentials(Credentials::new(user.into(), pass.into()));
    }
    Ok(builder.build())
}

fn build_message(cfg: &SmtpConfig, subject: &str, body: &str) -> Result<Message, String> {
    let from: Mailbox = cfg.from_address.parse().map_err(|e| format!("from: {e}"))?;
    let recipients: Vec<Mailbox> = cfg
        .recipients
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    if recipients.is_empty() {
        return Err("no valid recipients configured".into());
    }
    let mut builder = Message::builder().from(from).subject(subject);
    for r in recipients {
        builder = builder.to(r);
    }
    builder
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("message build: {e}"))
}

/// Send a synthetic "it works" email. Unlike [`send_event`], this ignores
/// the per-event enable flags and the global `enabled` field so the operator
/// can verify SMTP settings before turning notifications on.
pub async fn test_send(cfg: &SmtpConfig) -> Result<(), String> {
    let transport = build_transport(cfg)?;
    let msg = build_message(
        cfg,
        "AiFw: SMTP test",
        &format!(
            "This is a test email from AiFw at {}.\n\n\
             If you received this, your notification settings are correct.\n",
            chrono::Utc::now().to_rfc3339(),
        ),
    )?;
    transport.send(msg).await.map_err(|e| format!("send: {e}"))?;
    Ok(())
}

/// Fire-and-forget dispatch of an event. No-op if the event is not enabled
/// or SMTP is globally disabled. Errors are logged but not surfaced; this
/// runs from background tasks where there's no user to report to.
pub async fn send_event(pool: &SqlitePool, ev: Event, summary: &str) {
    let cfg = load(pool).await;
    if !cfg.is_event_enabled(ev) {
        return;
    }
    let body = format!(
        "Event:   {}\nHost:    {}\nTime:    {}\n\n{}\n",
        ev.label(),
        std::env::var("HOSTNAME").unwrap_or_else(|_| "aifw".into()),
        chrono::Utc::now().to_rfc3339(),
        summary,
    );
    let transport = match build_transport(&cfg) {
        Ok(t) => t,
        Err(e) => { tracing::warn!("smtp: transport build: {e}"); return; }
    };
    let msg = match build_message(&cfg, ev.subject(), &body) {
        Ok(m) => m,
        Err(e) => { tracing::warn!("smtp: message build: {e}"); return; }
    };
    if let Err(e) = transport.send(msg).await {
        tracing::warn!(event = ?ev, "smtp send failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mask_is_failures_only() {
        let c = SmtpConfig::default();
        assert!(!c.is_event_enabled(Event::BackupSaved));
        // `is_event_enabled` also checks the global enabled flag.
        let mut c = c;
        c.enabled = true;
        assert!(c.is_event_enabled(Event::S3UploadFailed));
        assert!(c.is_event_enabled(Event::RestoreFailed));
        assert!(!c.is_event_enabled(Event::BackupSaved));
    }

    #[test]
    fn tls_mode_parse_roundtrip() {
        for m in [TlsMode::None, TlsMode::StartTls, TlsMode::ImplicitTls] {
            assert_eq!(TlsMode::from_str(m.as_str()), m);
        }
    }
}
