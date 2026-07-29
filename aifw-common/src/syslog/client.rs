//! Async syslog client: bounded queue, background writer, UDP/TCP transports.
//!
//! Producers call [`SyslogHandle::enqueue`] which never blocks (`try_send`
//! into a bounded channel; overflow is counted, not waited on). A single
//! writer task owns the socket, reconnects TCP with capped backoff, and
//! re-resolves the target on (re)configure and on error.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};

use super::config::{Category, SyslogConfig, Transport, try_load};
use super::error::SyslogError;
use super::format::{SyslogRecord, format_message};

/// Bounded queue size shared by all producers in a process.
const QUEUE_CAPACITY: usize = 2048;
/// Connect/write/resolve timeout for one send attempt.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP reconnect backoff bounds.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How often [`spawn_config_poller`] re-reads the DB.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Delivery counters for the current process (the writer task's view).
#[derive(Default)]
pub struct SyslogStats {
    sent: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
    connected: AtomicBool,
    last_error: std::sync::Mutex<Option<String>>,
}

/// Point-in-time copy of [`SyslogStats`] for the API/UI.
#[derive(Debug, Clone, Serialize)]
pub struct SyslogStatsSnapshot {
    /// Messages successfully handed to the transport
    pub sent: u64,
    /// Messages dropped because the queue was full or the target unreachable
    pub dropped: u64,
    /// Send/connect failures
    pub errors: u64,
    /// Whether the last send attempt succeeded (UDP) / stream is up (TCP)
    pub connected: bool,
    /// Most recent transport error, if any
    pub last_error: Option<String>,
}

impl SyslogStats {
    fn record_error(&self, e: String) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.connected.store(false, Ordering::Relaxed);
        if let Ok(mut g) = self.last_error.lock() {
            *g = Some(e);
        }
    }

    fn snapshot(&self) -> SyslogStatsSnapshot {
        SyslogStatsSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            connected: self.connected.load(Ordering::Relaxed),
            last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
        }
    }
}

/// State shared between the manager/handles and the writer task.
struct Shared {
    config: ArcSwap<SyslogConfig>,
    stats: SyslogStats,
    hostname: String,
}

impl Shared {
    fn hostname_for<'a>(&'a self, cfg: &'a SyslogConfig) -> &'a str {
        if cfg.hostname_override.is_empty() {
            &self.hostname
        } else {
            &cfg.hostname_override
        }
    }
}

/// Owns the writer task and the live configuration for one process.
///
/// Create once at startup with [`SyslogManager::start`], apply the DB config
/// when the pool is ready, and pass [`SyslogHandle`]s to producers.
pub struct SyslogManager {
    shared: Arc<Shared>,
    tx: mpsc::Sender<SyslogRecord>,
    reload: watch::Sender<u64>,
}

impl SyslogManager {
    /// Spawn the writer task and return the manager. Starts with forwarding
    /// disabled; call [`SyslogManager::apply`] once config is loaded.
    /// Must be called from within a tokio runtime.
    pub fn start() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let (reload_tx, reload_rx) = watch::channel(0u64);
        let shared = Arc::new(Shared {
            config: ArcSwap::from_pointee(SyslogConfig::default()),
            stats: SyslogStats::default(),
            hostname: detect_hostname(),
        });
        tokio::spawn(writer_task(shared.clone(), rx, reload_rx));
        Arc::new(Self {
            shared,
            tx,
            reload: reload_tx,
        })
    }

    /// Swap in a new configuration; the writer drops its connection and
    /// re-resolves the target. No-op when the config is unchanged, so a
    /// no-op Save/poll never tears down a healthy TCP connection (the
    /// writer reconnects on config *pointer* change).
    pub fn apply(&self, cfg: SyslogConfig) {
        if *self.current() == cfg {
            return;
        }
        self.shared.config.store(Arc::new(cfg));
        self.reload.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// Current configuration as seen by producers.
    pub fn current(&self) -> Arc<SyslogConfig> {
        self.shared.config.load_full()
    }

    /// Cheap-clone producer handle for hot paths.
    pub fn handle(&self) -> SyslogHandle {
        SyslogHandle {
            shared: self.shared.clone(),
            tx: self.tx.clone(),
        }
    }

    /// Delivery counters for this process.
    pub fn stats(&self) -> SyslogStatsSnapshot {
        self.shared.stats.snapshot()
    }
}

/// Non-blocking producer handle; clone freely.
#[derive(Clone)]
pub struct SyslogHandle {
    shared: Arc<Shared>,
    tx: mpsc::Sender<SyslogRecord>,
}

impl SyslogHandle {
    /// True when forwarding is enabled for this category. O(1); check this
    /// before building an expensive message body.
    pub fn enabled_for(&self, cat: Category) -> bool {
        self.shared.config.load().category_enabled(cat)
    }

    /// Current configuration (for callers that need more than the toggles).
    pub fn config(&self) -> Arc<SyslogConfig> {
        self.shared.config.load_full()
    }

    /// Queue one message. Never blocks: on a full queue the message is
    /// dropped and counted. No-op when the category is disabled.
    pub fn enqueue(&self, cat: Category, severity: u8, app_name: &'static str, msg: String) {
        if !self.enabled_for(cat) {
            return;
        }
        let rec = SyslogRecord {
            severity,
            app_name,
            timestamp: Utc::now(),
            msg,
        };
        if self.tx.try_send(rec).is_err() {
            self.shared.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Re-read the config from the DB every 60s and apply changes (covers edits
/// made by other processes, e.g. the CLI writing SQLite directly).
pub fn spawn_config_poller(pool: SqlitePool, mgr: Arc<SyslogManager>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            // A transient read failure (SQLITE_BUSY on the shared WAL DB)
            // must not masquerade as "config reset to defaults" — that
            // would flap forwarding off for a poll interval. Skip the tick.
            match try_load(&pool).await {
                Ok(cfg) => mgr.apply(cfg),
                Err(e) => {
                    tracing::warn!(error = %e, "syslog config poll failed; keeping current config");
                }
            }
        }
    });
}

/// One-shot delivery of a test message using `cfg` (which need not be saved
/// or enabled). Note UDP is fire-and-forget: success means the datagram
/// left this host, not that the server received it.
pub async fn test_send(cfg: &SyslogConfig, msg: &str) -> Result<(), SyslogError> {
    if cfg.host.trim().is_empty() {
        return Err(SyslogError::HostRequired);
    }
    let hostname = detect_hostname();
    let hostname = if cfg.hostname_override.is_empty() {
        hostname.as_str()
    } else {
        cfg.hostname_override.as_str()
    };
    let rec = SyslogRecord {
        severity: 5,
        app_name: "aifw",
        timestamp: Utc::now(),
        msg: msg.to_string(),
    };
    let line = format_message(cfg, hostname, &rec);
    let mut conn = open_conn(cfg).await?;
    send_line(&mut conn, &line).await
}

fn detect_hostname() -> String {
    #[cfg(unix)]
    {
        nix::unistd::gethostname()
            .ok()
            .and_then(|h| h.into_string().ok())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "aifw".into())
    }
    #[cfg(not(unix))]
    {
        "aifw".into()
    }
}

enum Conn {
    Udp {
        sock: UdpSocket,
        peer: std::net::SocketAddr,
    },
    Tcp(TcpStream),
}

/// `host:port` target string, bracketing bare IPv6 literals so
/// `lookup_host` can parse them (`2001:db8::1` -> `[2001:db8::1]:514`;
/// already-bracketed input is passed through).
fn target_string(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn open_conn(cfg: &SyslogConfig) -> Result<Conn, SyslogError> {
    let target = target_string(&cfg.host, cfg.port);
    let addrs: Vec<std::net::SocketAddr> = timeout(IO_TIMEOUT, lookup_host(&target))
        .await
        .map_err(|_| SyslogError::ResolveTimeout {
            target: target.clone(),
        })?
        .map_err(|e| SyslogError::Resolve {
            target: target.clone(),
            source: e,
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SyslogError::NoAddresses { target });
    }
    match cfg.transport {
        Transport::Udp => {
            let peer = addrs[0];
            let bind = if peer.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let sock = UdpSocket::bind(bind).await.map_err(SyslogError::Bind)?;
            Ok(Conn::Udp { sock, peer })
        }
        Transport::Tcp => {
            // Try every resolved address (a dual-stack hostname may
            // resolve v6-first on a v4-only deployment); keep the last
            // error for the report.
            let mut last: Option<SyslogError> = None;
            for peer in addrs {
                match timeout(IO_TIMEOUT, TcpStream::connect(peer)).await {
                    Ok(Ok(stream)) => return Ok(Conn::Tcp(stream)),
                    Ok(Err(e)) => {
                        last = Some(SyslogError::Connect {
                            target: target.clone(),
                            source: e,
                        });
                    }
                    Err(_) => {
                        last = Some(SyslogError::ConnectTimeout {
                            target: target.clone(),
                        });
                    }
                }
            }
            // Non-empty addrs guarantees at least one attempt ran.
            Err(last.unwrap_or(SyslogError::NoAddresses { target }))
        }
    }
}

async fn send_line(conn: &mut Conn, line: &str) -> Result<(), SyslogError> {
    match conn {
        Conn::Udp { sock, peer } => {
            timeout(IO_TIMEOUT, sock.send_to(line.as_bytes(), *peer))
                .await
                .map_err(|_| SyslogError::SendTimeout { transport: "UDP" })?
                .map_err(|e| SyslogError::Send {
                    transport: "UDP",
                    source: e,
                })?;
        }
        Conn::Tcp(stream) => {
            // RFC 6587 non-transparent framing: LF-terminated records.
            let mut buf = Vec::with_capacity(line.len() + 1);
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
            timeout(IO_TIMEOUT, stream.write_all(&buf))
                .await
                .map_err(|_| SyslogError::SendTimeout { transport: "TCP" })?
                .map_err(|e| SyslogError::Send {
                    transport: "TCP",
                    source: e,
                })?;
        }
    }
    Ok(())
}

async fn writer_task(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<SyslogRecord>,
    reload: watch::Receiver<u64>,
) {
    // The connection is tagged with the config Arc it was opened for; a
    // pointer comparison per message replaces "drop the connection on every
    // reload notification", which tore down healthy connections when the
    // notification raced with already-processed messages.
    let mut conn: Option<(Conn, Arc<SyslogConfig>)> = None;
    let mut backoff = BACKOFF_MIN;
    let mut retry_at: Option<Instant> = None;
    let mut was_failing = false;
    // None once the manager is dropped: keep draining messages from
    // still-live handles instead of exiting with queued records unsent.
    let mut reload = Some(reload);

    loop {
        tokio::select! {
            changed = async {
                match reload.as_mut() {
                    Some(r) => r.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_err() {
                    reload = None; // manager dropped; drain remaining messages
                    continue;
                }
                // A config change ends any backoff immediately; the stale
                // connection (if the config really changed) is detected by
                // the per-message pointer check below.
                backoff = BACKOFF_MIN;
                retry_at = None;
            }
            rec = rx.recv() => {
                let Some(rec) = rec else { return }; // all senders dropped
                let cfg = shared.config.load_full();
                if !cfg.enabled || cfg.host.is_empty() {
                    continue; // drain silently while disabled
                }
                // While in backoff after a failure, shed load instead of
                // stalling the queue behind a dead target.
                if let Some(t) = retry_at
                    && Instant::now() < t
                {
                    shared.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // Reconnect when the config this connection was opened for
                // is no longer current.
                if let Some((_, conn_cfg)) = &conn
                    && !Arc::ptr_eq(conn_cfg, &cfg)
                {
                    conn = None;
                }
                let line = format_message(&cfg, shared.hostname_for(&cfg), &rec);
                let result = match &mut conn {
                    Some((c, _)) => send_line(c, &line).await,
                    None => match open_conn(&cfg).await {
                        Ok(mut c) => {
                            let r = send_line(&mut c, &line).await;
                            if r.is_ok() {
                                conn = Some((c, cfg.clone()));
                            }
                            r
                        }
                        Err(e) => Err(e),
                    },
                };
                match result {
                    Ok(()) => {
                        shared.stats.sent.fetch_add(1, Ordering::Relaxed);
                        shared.stats.connected.store(true, Ordering::Relaxed);
                        backoff = BACKOFF_MIN;
                        retry_at = None;
                        if was_failing {
                            was_failing = false;
                            tracing::info!("remote syslog delivery recovered");
                        }
                    }
                    Err(e) => {
                        conn = None;
                        // Warn once per outage, not per message; the layer's
                        // recursion guard also drops this module's events.
                        if !was_failing {
                            was_failing = true;
                            tracing::warn!(error = %e, "remote syslog delivery failing; backing off");
                        }
                        shared.stats.record_error(e.to_string());
                        retry_at = Some(Instant::now() + backoff);
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::SyslogFormat;
    use super::*;

    fn cfg_to(port: u16, transport: Transport) -> SyslogConfig {
        SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            transport,
            format: SyslogFormat::Rfc3164,
            pf_enabled: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn udp_delivery_and_gating() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        let mgr = SyslogManager::start();
        mgr.apply(cfg_to(port, Transport::Udp));
        let handle = mgr.handle();

        assert!(handle.enabled_for(Category::Pf));
        assert!(!handle.enabled_for(Category::Ids)); // toggle off → gated

        handle.enqueue(Category::Ids, 6, "aifw-test", "must not arrive".into());
        handle.enqueue(
            Category::Pf,
            5,
            "aifw-pf",
            "action=block src=1.2.3.4".into(),
        );

        let mut buf = [0u8; 4096];
        let (n, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("datagram should arrive")
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.contains("aifw-pf"), "got: {got}");
        assert!(got.contains("action=block src=1.2.3.4"));
        assert!(got.starts_with("<133>")); // local0(16)*8 + notice(5)

        // Nothing else queued: the gated IDS message never went out.
        let extra = timeout(Duration::from_millis(200), server.recv_from(&mut buf)).await;
        assert!(extra.is_err(), "gated message unexpectedly delivered");

        let stats = mgr.stats();
        assert_eq!(stats.sent, 1);
        assert!(stats.connected);
    }

    #[tokio::test]
    async fn tcp_delivery_lf_framed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mgr = SyslogManager::start();
        let mut cfg = cfg_to(port, Transport::Tcp);
        cfg.format = SyslogFormat::Rfc5424;
        cfg.ids_enabled = true;
        mgr.apply(cfg);
        let handle = mgr.handle();

        handle.enqueue(Category::Ids, 2, "aifw-ids", "alert one".into());
        handle.enqueue(Category::Ids, 2, "aifw-ids", "alert two".into());

        let (mut sock, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("client should connect")
            .unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        while data.iter().filter(|b| **b == b'\n').count() < 2 {
            let n = timeout(
                Duration::from_secs(5),
                tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
            )
            .await
            .expect("read should not time out")
            .unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        let text = String::from_utf8(data).unwrap();
        let lines: Vec<&str> = text.split('\n').filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "text: {text:?}");
        assert!(lines[0].contains("alert one"));
        assert!(lines[1].contains("alert two"));
        // RFC 5424: VERSION "1" right after PRI
        assert!(lines[0].starts_with("<130>1 "), "line: {}", lines[0]);
    }

    #[tokio::test]
    async fn disabled_config_sends_nothing() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        let mgr = SyslogManager::start();
        let mut cfg = cfg_to(port, Transport::Udp);
        cfg.enabled = false;
        mgr.apply(cfg);
        let handle = mgr.handle();
        handle.enqueue(Category::Pf, 5, "aifw-pf", "nope".into());

        let mut buf = [0u8; 64];
        let r = timeout(Duration::from_millis(200), server.recv_from(&mut buf)).await;
        assert!(r.is_err());
        assert_eq!(mgr.stats().sent, 0);
    }

    #[tokio::test]
    async fn test_send_reports_connection_refused() {
        // Reserve a port, then close it so the connect is refused.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let cfg = cfg_to(port, Transport::Tcp);
        let err = test_send(&cfg, "test message")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot connect"), "err: {err}");
    }

    #[test]
    fn target_string_brackets_bare_ipv6() {
        assert_eq!(target_string("2001:db8::1", 514), "[2001:db8::1]:514");
        assert_eq!(target_string("[2001:db8::1]", 514), "[2001:db8::1]:514");
        assert_eq!(target_string("192.0.2.1", 514), "192.0.2.1:514");
        assert_eq!(
            target_string("log.example.com", 6514),
            "log.example.com:6514"
        );
    }

    #[tokio::test]
    async fn test_send_requires_host() {
        let cfg = SyslogConfig::default();
        assert!(test_send(&cfg, "x").await.is_err());
    }

    #[tokio::test]
    async fn test_send_udp_ok() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let mut cfg = cfg_to(port, Transport::Udp);
        cfg.enabled = false; // test_send works even when forwarding is off
        test_send(&cfg, "hello from test").await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("test datagram should arrive")
            .unwrap();
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .contains("hello from test")
        );
    }
}
