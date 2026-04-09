pub mod action;
pub mod capture;
pub mod config;
pub mod decode;
pub mod detect;
pub mod flow;
pub mod output;
pub mod protocol;
pub mod rules;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use aifw_common::ids::{IdsAlert, IdsConfig, IdsMode, IdsStats};
use aifw_pf::PfBackend;
use crossbeam::channel;
use sqlx::SqlitePool;
use tracing::{error, info, warn};

use crate::action::ActionEngine;
use crate::config::RuntimeConfig;
use crate::detect::DetectionEngine;
use crate::flow::FlowTable;
use crate::output::AlertPipeline;
use crate::rules::RuleDatabase;

/// Errors produced by the IDS engine
#[derive(Debug, thiserror::Error)]
pub enum IdsError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("capture error: {0}")]
    Capture(String),
    #[error("rule parse error: {0}")]
    RuleParse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IdsError>;

/// Alert channel capacity — bounded to prevent unbounded memory growth
const ALERT_CHANNEL_CAPACITY: usize = 10_000;

/// Shared counters for engine statistics
#[derive(Debug, Default)]
pub struct EngineCounters {
    pub packets_inspected: AtomicU64,
    pub alerts_total: AtomicU64,
    pub drops_total: AtomicU64,
    pub bytes_total: AtomicU64,
    pub start_time: AtomicU64,
}

/// The IDS/IPS engine — orchestrates capture, detection, and response.
pub struct IdsEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    config: Arc<RuntimeConfig>,
    rule_db: Arc<RuleDatabase>,
    flow_table: Arc<FlowTable>,
    detection: Arc<DetectionEngine>,
    action: Arc<ActionEngine>,
    alert_pipeline: Arc<AlertPipeline>,
    alert_tx: channel::Sender<IdsAlert>,
    alert_rx: channel::Receiver<IdsAlert>,
    counters: Arc<EngineCounters>,
    running: Arc<AtomicBool>,
}

impl IdsEngine {
    /// Create a new IDS engine with the given database pool and pf backend.
    ///
    /// When mode is `Disabled`, uses minimal allocations (small flow table, no channel).
    /// Full resources are allocated only when IDS/IPS mode is active.
    pub async fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Result<Self> {
        Self::migrate(&pool).await?;

        let config = Arc::new(RuntimeConfig::load(&pool).await?);
        let disabled = config.config().mode == IdsMode::Disabled;

        // Minimal allocations when disabled — just enough for API endpoints to work
        let flow_table_size = if disabled {
            16 // trivial map, no real flows tracked
        } else {
            config.config().flow_table_size.unwrap_or(65536) as usize
        };
        let channel_cap = if disabled { 1 } else { ALERT_CHANNEL_CAPACITY };

        let rule_db = Arc::new(RuleDatabase::new());
        let flow_table = Arc::new(FlowTable::new(flow_table_size));
        let detection = Arc::new(DetectionEngine::new(rule_db.clone(), flow_table.clone()));
        let action = Arc::new(ActionEngine::new(pf.clone(), config.clone()));
        let alert_pipeline = Arc::new(AlertPipeline::new(pool.clone()));

        let (alert_tx, alert_rx) = channel::bounded(channel_cap);

        let counters = Arc::new(EngineCounters::default());
        counters.start_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );

        Ok(Self {
            pool,
            pf,
            config,
            rule_db,
            flow_table,
            detection,
            action,
            alert_pipeline,
            alert_tx,
            alert_rx,
            counters,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Run database migrations for IDS tables.
    pub async fn migrate(pool: &SqlitePool) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ids_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ids_rulesets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_url TEXT,
                rule_format TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                auto_update INTEGER NOT NULL DEFAULT 1,
                update_interval_hours INTEGER NOT NULL DEFAULT 24,
                last_updated TEXT,
                rule_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ids_rules (
                id TEXT PRIMARY KEY,
                ruleset_id TEXT NOT NULL REFERENCES ids_rulesets(id),
                sid INTEGER,
                rule_text TEXT NOT NULL,
                msg TEXT,
                severity INTEGER DEFAULT 3,
                enabled INTEGER NOT NULL DEFAULT 1,
                action_override TEXT,
                hit_count INTEGER NOT NULL DEFAULT 0,
                last_hit TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_rules_sid ON ids_rules(sid)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_rules_ruleset ON ids_rules(ruleset_id)")
            .execute(pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                signature_id INTEGER,
                signature_msg TEXT NOT NULL,
                severity INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_source TEXT NOT NULL,
                flow_id TEXT,
                payload_excerpt TEXT,
                metadata TEXT,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        // Alert classification and analyst notes (added for threat investigation workflow)
        let _ = sqlx::query("ALTER TABLE ids_alerts ADD COLUMN classification TEXT NOT NULL DEFAULT 'unreviewed'")
            .execute(pool).await;
        let _ = sqlx::query("ALTER TABLE ids_alerts ADD COLUMN analyst_notes TEXT")
            .execute(pool).await;

        // AI analysis audit log
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS ai_audit_log (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                signature_id INTEGER,
                signature_msg TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                prompt TEXT NOT NULL,
                response TEXT NOT NULL,
                classification TEXT,
                tokens_used INTEGER,
                duration_ms INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )"#,
        ).execute(pool).await?;

        // Track which signature_ids have already been analyzed by AI
        // to avoid duplicate queries for the same rule
        let _ = sqlx::query("ALTER TABLE ids_alerts ADD COLUMN ai_analyzed INTEGER NOT NULL DEFAULT 0")
            .execute(pool).await;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_alerts_ts ON ids_alerts(timestamp)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_alerts_src ON ids_alerts(src_ip)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_alerts_sid ON ids_alerts(signature_id)")
            .execute(pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_ids_alerts_sev ON ids_alerts(severity)")
            .execute(pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ids_suppressions (
                id TEXT PRIMARY KEY,
                sid INTEGER NOT NULL,
                suppress_type TEXT NOT NULL,
                ip_cidr TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            "#,
        )
        .execute(pool)
        .await?;

        // Seed default rulesets with deterministic UUIDs
        // (migrate old plain-string IDs from earlier versions)
        let et_uuid = "a0000000-0000-0000-0000-000000000001";
        let abuse_uuid = "a0000000-0000-0000-0000-000000000002";

        // Migrate old non-UUID IDs to proper UUIDs (idempotent)
        sqlx::query("UPDATE ids_rulesets SET id = ?1 WHERE id = 'et-open-default'")
            .bind(et_uuid).execute(pool).await?;
        sqlx::query("UPDATE ids_rulesets SET id = ?1 WHERE id = 'abuse-ch-default'")
            .bind(abuse_uuid).execute(pool).await?;
        // Also migrate any rules that referenced the old IDs
        sqlx::query("UPDATE ids_rules SET ruleset_id = ?1 WHERE ruleset_id = 'et-open-default'")
            .bind(et_uuid).execute(pool).await?;
        sqlx::query("UPDATE ids_rules SET ruleset_id = ?1 WHERE ruleset_id = 'abuse-ch-default'")
            .bind(abuse_uuid).execute(pool).await?;

        sqlx::query(
            r#"INSERT OR IGNORE INTO ids_rulesets (id, name, source_url, rule_format, enabled, auto_update, update_interval_hours)
               VALUES (?1, 'ET Open (Emerging Threats)', 'https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules', 'suricata', 0, 1, 24)"#,
        )
        .bind(et_uuid)
        .execute(pool)
        .await?;

        sqlx::query(
            r#"INSERT OR IGNORE INTO ids_rulesets (id, name, source_url, rule_format, enabled, auto_update, update_interval_hours)
               VALUES (?1, 'Abuse.ch SSLBL', 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules', 'suricata', 0, 1, 24)"#,
        )
        .bind(abuse_uuid)
        .execute(pool)
        .await?;

        info!("IDS database migrations complete");
        Ok(())
    }

    /// Start the IDS engine — spawns worker threads and alert output pipeline.
    pub async fn start(&self) -> Result<()> {
        if self.config.config().mode == IdsMode::Disabled {
            info!("IDS engine disabled by configuration");
            return Ok(());
        }

        if self.running.swap(true, Ordering::SeqCst) {
            warn!("IDS engine already running");
            return Ok(());
        }

        info!(mode = %self.config.config().mode, "IDS engine starting");

        // Start the alert output consumer
        let pipeline = self.alert_pipeline.clone();
        let rx = self.alert_rx.clone();
        let counters = self.counters.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                match rx.try_recv() {
                    Ok(alert) => {
                        counters.alerts_total.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = pipeline.emit(&alert).await {
                            error!("alert pipeline error: {e}");
                        }
                    }
                    Err(channel::TryRecvError::Empty) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(channel::TryRecvError::Disconnected) => break,
                }
            }
        });

        // Start packet capture worker — reads from network interfaces,
        // decodes packets, runs through detection engine, submits alerts
        let interfaces = self.config.config().interfaces.clone();
        let detection = self.detection.clone();
        let alert_tx = self.alert_tx.clone();
        let counters2 = self.counters.clone();
        let running2 = self.running.clone();
        let is_ips = self.config.config().mode == IdsMode::Ips;

        // Determine which interfaces to capture on
        let capture_ifaces = if interfaces.is_empty() {
            // Default: detect all non-loopback/non-pflog interfaces and capture on them.
            // pflog0 only sees blocked/logged pf traffic — we need the real interfaces
            // to inspect all passing traffic.
            let mut ifaces = detect_network_interfaces();
            if ifaces.is_empty() {
                // Fallback to pflog0 if we can't detect interfaces
                ifaces.push("pflog0".to_string());
            }
            ifaces
        } else {
            interfaces
        };

        for iface in capture_ifaces {
            let detection = detection.clone();
            let alert_tx = alert_tx.clone();
            let counters = counters2.clone();
            let running = running2.clone();
            let iface_name = iface.clone();

            std::thread::spawn(move || {
                capture_interface_worker(&iface, &detection, &alert_tx, &counters, &running, is_ips);
            });
            info!(interface = %iface_name, "capture worker started");
        }

        info!("IDS engine started");
        Ok(())
    }

    /// Stop the IDS engine gracefully.
    pub async fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        info!("IDS engine stopping");
        if let Err(e) = self.alert_pipeline.flush().await {
            error!("error flushing alert pipeline: {e}");
        }
        info!("IDS engine stopped");
    }

    /// Get current engine statistics.
    pub fn stats(&self) -> IdsStats {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.counters.start_time.load(Ordering::Relaxed);
        let uptime = now.saturating_sub(start);
        let packets = self.counters.packets_inspected.load(Ordering::Relaxed);
        let bytes = self.counters.bytes_total.load(Ordering::Relaxed);

        IdsStats {
            packets_inspected: packets,
            alerts_total: self.counters.alerts_total.load(Ordering::Relaxed),
            drops_total: self.counters.drops_total.load(Ordering::Relaxed),
            bytes_per_sec: if uptime > 0 {
                bytes as f64 / uptime as f64
            } else {
                0.0
            },
            packets_per_sec: if uptime > 0 {
                packets as f64 / uptime as f64
            } else {
                0.0
            },
            active_flows: self.flow_table.len() as u64,
            uptime_secs: uptime,
        }
    }

    /// Get a reference to the runtime configuration.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Get a reference to the rule database.
    pub fn rule_db(&self) -> &RuleDatabase {
        &self.rule_db
    }

    /// Get the flow table.
    pub fn flow_table(&self) -> &FlowTable {
        &self.flow_table
    }

    /// Get the detection engine.
    pub fn detection(&self) -> &DetectionEngine {
        &self.detection
    }

    /// Get the action engine.
    pub fn action_engine(&self) -> &ActionEngine {
        &self.action
    }

    /// Get the alert pipeline.
    pub fn alert_pipeline(&self) -> &AlertPipeline {
        &self.alert_pipeline
    }

    /// Get the alert sender for submitting alerts from worker threads.
    pub fn alert_sender(&self) -> &channel::Sender<IdsAlert> {
        &self.alert_tx
    }

    /// Get the database pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Get the pf backend.
    pub fn pf(&self) -> &Arc<dyn PfBackend> {
        &self.pf
    }

    /// Check if the engine is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get engine counters for direct atomic access.
    pub fn counters(&self) -> &Arc<EngineCounters> {
        &self.counters
    }

    /// Submit an alert to the pipeline.
    pub fn submit_alert(&self, alert: IdsAlert) {
        if let Err(e) = self.alert_tx.try_send(alert) {
            warn!("alert channel full, dropping alert: {e}");
        }
    }

    /// Load IDS configuration from the database.
    pub async fn load_config(&self) -> Result<IdsConfig> {
        self.config.load_from_db(&self.pool).await
    }

    /// Save IDS configuration to the database.
    pub async fn save_config(&self, cfg: &IdsConfig) -> Result<()> {
        self.config.save_to_db(&self.pool, cfg).await
    }
}

/// Detect network interfaces for packet capture.
fn detect_network_interfaces() -> Vec<String> {
    #[cfg(target_os = "freebsd")]
    {
        if let Ok(output) = std::process::Command::new("ifconfig").arg("-l").output() {
            let list = String::from_utf8_lossy(&output.stdout);
            return list
                .split_whitespace()
                .filter(|iface| {
                    !iface.starts_with("lo")
                        && !iface.starts_with("pflog")
                        && !iface.starts_with("pfsync")
                        && !iface.starts_with("enc")
                })
                .map(String::from)
                .collect();
        }
    }

    #[cfg(not(target_os = "freebsd"))]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            return entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| n != "lo")
                .collect();
        }
    }

    Vec::new()
}

/// Capture worker — uses BPF on FreeBSD, pcap mock on Linux.
/// Reads raw packets directly from the kernel with zero shell overhead.
fn capture_interface_worker(
    iface: &str,
    detection: &std::sync::Arc<detect::DetectionEngine>,
    alert_tx: &channel::Sender<IdsAlert>,
    counters: &std::sync::Arc<EngineCounters>,
    running: &std::sync::Arc<AtomicBool>,
    _is_ips: bool,
) {
    use capture::CaptureConfig;

    info!(interface = %iface, "BPF capture worker starting");

    while running.load(Ordering::Relaxed) {
        let config = CaptureConfig::default();
        let mut cap = match capture::create_capture(iface, &config) {
            Ok(c) => c,
            Err(e) => {
                error!(interface = %iface, error = %e, "failed to open BPF capture, retrying in 5s");
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };

        info!(interface = %iface, "BPF capture active");

        while running.load(Ordering::Relaxed) {
            if let Some(pkt) = cap.next_packet() {
                counters.packets_inspected.fetch_add(1, Ordering::Relaxed);
                counters.bytes_total.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);

                if let Some(decoded) = decode::decode_packet(&pkt.data, pkt.timestamp_us) {
                    let alerts = detection.detect(&decoded);
                    for alert in alerts {
                        if let Err(e) = alert_tx.try_send(alert) {
                            tracing::debug!("alert channel full: {e}");
                        }
                    }
                }
            }
        }

        cap.close();
    }

    info!(interface = %iface, "BPF capture worker stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        SqlitePool::connect("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_migrate() {
        let pool = test_pool().await;
        IdsEngine::migrate(&pool).await.unwrap();
        // Verify tables exist
        let row: (i64,) =
            sqlx::query_as("SELECT count(*) FROM ids_config")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.0, 0);
    }

    #[tokio::test]
    async fn test_engine_create() {
        let pool = test_pool().await;
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = IdsEngine::new(pool, pf).await.unwrap();
        assert!(!engine.is_running());
        let stats = engine.stats();
        assert_eq!(stats.packets_inspected, 0);
    }

    #[tokio::test]
    async fn test_engine_disabled_start() {
        let pool = test_pool().await;
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = IdsEngine::new(pool, pf).await.unwrap();
        // Should succeed but not actually run since mode is Disabled
        engine.start().await.unwrap();
        assert!(!engine.is_running());
    }
}
