use aifw_common::{AifwError, Gateway, GatewayEvent, GatewayState, Result};
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::probe::{ProbeKind, ProbeOutcome, ProbeSpec, run_probe};

/// Per-gateway hysteresis tracker computed from probe samples.
#[derive(Debug, Default, Clone)]
pub struct GatewayMetrics {
    pub consec_fail: u32,
    pub consec_ok: u32,
    pub recent_loss: f64,
    pub last_rtt_ms: Option<f64>,
    pub last_jitter_ms: Option<f64>,
    pub last_mos: Option<f64>,
    pub last_probe_ts: Option<DateTime<Utc>>,
    pub samples: Vec<f64>, // RTTs of last 20 probes for jitter calc
}

impl GatewayMetrics {
    pub fn ingest(&mut self, outcome: &ProbeOutcome, ts: DateTime<Utc>) {
        self.last_probe_ts = Some(ts);
        if outcome.success {
            self.consec_fail = 0;
            self.consec_ok = self.consec_ok.saturating_add(1);
            if let Some(rtt) = outcome.rtt_ms {
                self.last_rtt_ms = Some(rtt);
                self.samples.push(rtt);
                if self.samples.len() > 20 {
                    self.samples.remove(0);
                }
                self.last_jitter_ms = Some(jitter(&self.samples));
                self.last_mos = Some(mos_score(rtt, self.last_jitter_ms.unwrap_or(0.0), 0.0));
            }
        } else {
            self.consec_ok = 0;
            self.consec_fail = self.consec_fail.saturating_add(1);
        }
        // Recent loss: % failures in last 20 attempts
        // Push a synthetic 1.0 = success, 0.0 = failure into a parallel buffer
        // Simpler: derive from consecutive counters' ratio.
        let total = self.consec_fail + self.consec_ok;
        if total > 0 {
            self.recent_loss = (self.consec_fail as f64 / total as f64) * 100.0;
        }
    }
}

fn jitter(samples: &[f64]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mut sum_diff = 0.0;
    for w in samples.windows(2) {
        sum_diff += (w[1] - w[0]).abs();
    }
    sum_diff / (samples.len() - 1) as f64
}

/// Simplified MOS approximation (1.0–4.5 scale).
fn mos_score(rtt_ms: f64, jitter_ms: f64, loss_pct: f64) -> f64 {
    let r_factor = 93.2 - (rtt_ms + 2.0 * jitter_ms) / 40.0 - 2.5 * loss_pct;
    let r = r_factor.clamp(0.0, 100.0);
    if r < 6.5 {
        1.0
    } else if r > 100.0 {
        4.5
    } else {
        1.0 + 0.035 * r + 7.0e-6 * r * (r - 60.0) * (100.0 - r)
    }
}

/// Decide next state given current state, metrics, and gateway thresholds.
pub fn evaluate_transition(
    current: GatewayState,
    metrics: &GatewayMetrics,
    consec_fail_down: u32,
    consec_ok_up: u32,
    loss_pct_down: f64,
    loss_pct_up: f64,
) -> GatewayState {
    if metrics.consec_fail >= consec_fail_down {
        return GatewayState::Down;
    }
    if metrics.consec_ok >= consec_ok_up {
        if metrics.recent_loss > loss_pct_up {
            return GatewayState::Warning;
        }
        return GatewayState::Up;
    }
    if metrics.recent_loss > loss_pct_down {
        return GatewayState::Warning;
    }
    current
}

pub struct GatewayEngine {
    pool: SqlitePool,
    metrics: Arc<RwLock<HashMap<Uuid, GatewayMetrics>>>,
    monitors: Arc<Mutex<HashMap<Uuid, JoinHandle<()>>>>,
    events_tx: broadcast::Sender<GatewayEvent>,
}

impl GatewayEngine {
    pub fn new(pool: SqlitePool) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            pool,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            monitors: Arc::new(Mutex::new(HashMap::new())),
            events_tx: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GatewayEvent> {
        self.events_tx.subscribe()
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_gateways (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                instance_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                next_hop TEXT NOT NULL,
                ip_version TEXT NOT NULL DEFAULT 'v4',
                monitor_kind TEXT NOT NULL DEFAULT 'icmp',
                monitor_target TEXT,
                monitor_port INTEGER,
                monitor_expect TEXT,
                interval_ms INTEGER NOT NULL DEFAULT 500,
                timeout_ms INTEGER NOT NULL DEFAULT 1000,
                loss_pct_down REAL NOT NULL DEFAULT 20.0,
                loss_pct_up REAL NOT NULL DEFAULT 5.0,
                latency_ms_down INTEGER,
                latency_ms_up INTEGER,
                consec_fail_down INTEGER NOT NULL DEFAULT 3,
                consec_ok_up INTEGER NOT NULL DEFAULT 5,
                weight INTEGER NOT NULL DEFAULT 1,
                dampening_secs INTEGER NOT NULL DEFAULT 10,
                dscp_tag INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                state TEXT NOT NULL DEFAULT 'unknown',
                last_rtt_ms REAL,
                last_jitter_ms REAL,
                last_loss_pct REAL,
                last_mos REAL,
                last_probe_ts TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (instance_id) REFERENCES multiwan_instances(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_gateway_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                gateway_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                reason TEXT,
                probe_snapshot_json TEXT,
                FOREIGN KEY (gateway_id) REFERENCES multiwan_gateways(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_gw_events_gw_ts ON multiwan_gateway_events(gateway_id, ts DESC)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<Gateway>> {
        let rows = sqlx::query("SELECT * FROM multiwan_gateways ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows.iter().map(row_to_gw).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<Gateway> {
        let row = sqlx::query("SELECT * FROM multiwan_gateways WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?
            .ok_or_else(|| AifwError::NotFound(format!("gateway {id} not found")))?;
        Ok(row_to_gw(&row))
    }

    pub async fn add(&self, gw: Gateway) -> Result<Gateway> {
        if gw.name.trim().is_empty() {
            return Err(AifwError::Validation("gateway name required".into()));
        }
        sqlx::query(
            r#"INSERT INTO multiwan_gateways
            (id, name, instance_id, interface, next_hop, ip_version,
             monitor_kind, monitor_target, monitor_port, monitor_expect,
             interval_ms, timeout_ms, loss_pct_down, loss_pct_up,
             latency_ms_down, latency_ms_up, consec_fail_down, consec_ok_up,
             weight, dampening_secs, dscp_tag, enabled, state,
             last_rtt_ms, last_jitter_ms, last_loss_pct, last_mos, last_probe_ts,
             created_at, updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30)"#,
        )
        .bind(gw.id.to_string())
        .bind(&gw.name)
        .bind(gw.instance_id.to_string())
        .bind(&gw.interface)
        .bind(&gw.next_hop)
        .bind(&gw.ip_version)
        .bind(&gw.monitor_kind)
        .bind(gw.monitor_target.as_deref())
        .bind(gw.monitor_port.map(|p| p as i64))
        .bind(gw.monitor_expect.as_deref())
        .bind(gw.interval_ms as i64)
        .bind(gw.timeout_ms as i64)
        .bind(gw.loss_pct_down)
        .bind(gw.loss_pct_up)
        .bind(gw.latency_ms_down.map(|v| v as i64))
        .bind(gw.latency_ms_up.map(|v| v as i64))
        .bind(gw.consec_fail_down as i64)
        .bind(gw.consec_ok_up as i64)
        .bind(gw.weight as i64)
        .bind(gw.dampening_secs as i64)
        .bind(gw.dscp_tag.map(|v| v as i64))
        .bind(gw.enabled as i64)
        .bind(gw.state.as_str())
        .bind(gw.last_rtt_ms)
        .bind(gw.last_jitter_ms)
        .bind(gw.last_loss_pct)
        .bind(gw.last_mos)
        .bind(gw.last_probe_ts.map(|t| t.to_rfc3339()))
        .bind(gw.created_at.to_rfc3339())
        .bind(gw.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(gw)
    }

    pub async fn update(&self, gw: Gateway) -> Result<Gateway> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"UPDATE multiwan_gateways SET
                name=?2, instance_id=?3, interface=?4, next_hop=?5, ip_version=?6,
                monitor_kind=?7, monitor_target=?8, monitor_port=?9, monitor_expect=?10,
                interval_ms=?11, timeout_ms=?12, loss_pct_down=?13, loss_pct_up=?14,
                latency_ms_down=?15, latency_ms_up=?16, consec_fail_down=?17, consec_ok_up=?18,
                weight=?19, dampening_secs=?20, dscp_tag=?21, enabled=?22, updated_at=?23
             WHERE id=?1"#,
        )
        .bind(gw.id.to_string())
        .bind(&gw.name)
        .bind(gw.instance_id.to_string())
        .bind(&gw.interface)
        .bind(&gw.next_hop)
        .bind(&gw.ip_version)
        .bind(&gw.monitor_kind)
        .bind(gw.monitor_target.as_deref())
        .bind(gw.monitor_port.map(|p| p as i64))
        .bind(gw.monitor_expect.as_deref())
        .bind(gw.interval_ms as i64)
        .bind(gw.timeout_ms as i64)
        .bind(gw.loss_pct_down)
        .bind(gw.loss_pct_up)
        .bind(gw.latency_ms_down.map(|v| v as i64))
        .bind(gw.latency_ms_up.map(|v| v as i64))
        .bind(gw.consec_fail_down as i64)
        .bind(gw.consec_ok_up as i64)
        .bind(gw.weight as i64)
        .bind(gw.dampening_secs as i64)
        .bind(gw.dscp_tag.map(|v| v as i64))
        .bind(gw.enabled as i64)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("gateway {} not found", gw.id)));
        }
        let mut updated = gw;
        updated.updated_at = now;
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        self.stop_monitor(id).await;
        let res = sqlx::query("DELETE FROM multiwan_gateways WHERE id=?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("gateway {id} not found")));
        }
        Ok(())
    }

    pub async fn list_events(&self, gw_id: Uuid, limit: i64) -> Result<Vec<GatewayEvent>> {
        let rows = sqlx::query(
            "SELECT id, gateway_id, ts, from_state, to_state, reason, probe_snapshot_json
             FROM multiwan_gateway_events WHERE gateway_id = ?1 ORDER BY ts DESC LIMIT ?2",
        )
        .bind(gw_id.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|r| GatewayEvent {
                id: r.get("id"),
                gateway_id: r
                    .get::<String, _>("gateway_id")
                    .parse()
                    .unwrap_or_default(),
                ts: r.get::<String, _>("ts").parse().unwrap_or_default(),
                from_state: r
                    .get::<Option<String>, _>("from_state")
                    .and_then(|s| GatewayState::parse(&s)),
                to_state: GatewayState::parse(&r.get::<String, _>("to_state"))
                    .unwrap_or(GatewayState::Unknown),
                reason: r.get("reason"),
                probe_snapshot_json: r.get("probe_snapshot_json"),
            })
            .collect())
    }

    /// Inject a synthetic probe outcome for tests.
    pub async fn inject_sample(&self, gw_id: Uuid, outcome: ProbeOutcome) -> Result<()> {
        let gw = self.get(gw_id).await?;
        let mut metrics_map = self.metrics.write().await;
        let m = metrics_map.entry(gw_id).or_default();
        m.ingest(&outcome, Utc::now());
        let new_state = evaluate_transition(
            gw.state,
            m,
            gw.consec_fail_down,
            gw.consec_ok_up,
            gw.loss_pct_down,
            gw.loss_pct_up,
        );
        let metrics_snapshot = m.clone();
        drop(metrics_map);
        self.persist_state(&gw, new_state, &outcome, &metrics_snapshot)
            .await?;
        Ok(())
    }

    async fn persist_state(
        &self,
        gw: &Gateway,
        new_state: GatewayState,
        outcome: &ProbeOutcome,
        metrics: &GatewayMetrics,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"UPDATE multiwan_gateways SET
                state=?2, last_rtt_ms=?3, last_jitter_ms=?4, last_loss_pct=?5,
                last_mos=?6, last_probe_ts=?7
             WHERE id=?1"#,
        )
        .bind(gw.id.to_string())
        .bind(new_state.as_str())
        .bind(metrics.last_rtt_ms)
        .bind(metrics.last_jitter_ms)
        .bind(metrics.recent_loss)
        .bind(metrics.last_mos)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        if new_state != gw.state {
            let snap = serde_json::json!({
                "rtt_ms": metrics.last_rtt_ms,
                "jitter_ms": metrics.last_jitter_ms,
                "loss_pct": metrics.recent_loss,
                "mos": metrics.last_mos,
                "consec_fail": metrics.consec_fail,
                "consec_ok": metrics.consec_ok,
            })
            .to_string();
            sqlx::query(
                "INSERT INTO multiwan_gateway_events (gateway_id, ts, from_state, to_state, reason, probe_snapshot_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(gw.id.to_string())
            .bind(now.to_rfc3339())
            .bind(gw.state.as_str())
            .bind(new_state.as_str())
            .bind(outcome.error.clone())
            .bind(&snap)
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;

            let event = GatewayEvent {
                id: 0,
                gateway_id: gw.id,
                ts: now,
                from_state: Some(gw.state),
                to_state: new_state,
                reason: outcome.error.clone(),
                probe_snapshot_json: Some(snap),
            };
            let _ = self.events_tx.send(event);
            tracing::info!(
                gw = %gw.name,
                from = ?gw.state,
                to = ?new_state,
                reason = ?outcome.error,
                "gateway transition"
            );
        }
        Ok(())
    }

    /// Spawn a background probe loop for one gateway.
    pub async fn start_monitor(self: &Arc<Self>, gw_id: Uuid) -> Result<()> {
        let gw = self.get(gw_id).await?;
        if !gw.enabled {
            return Ok(());
        }
        self.stop_monitor(gw_id).await;

        let engine = Arc::clone(self);
        let spec = ProbeSpec {
            kind: ProbeKind::parse(&gw.monitor_kind).unwrap_or(ProbeKind::Icmp),
            target: gw.monitor_target.clone().unwrap_or_else(|| gw.next_hop.clone()),
            port: gw.monitor_port,
            expect: gw.monitor_expect.clone(),
            timeout_ms: gw.timeout_ms,
        };
        let interval = std::time::Duration::from_millis(gw.interval_ms.max(100));

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let outcome = run_probe(&spec).await;
                if let Err(e) = engine.inject_sample(gw_id, outcome).await {
                    tracing::warn!(%gw_id, error = %e, "probe ingest failed");
                }
            }
        });

        self.monitors.lock().await.insert(gw_id, handle);
        Ok(())
    }

    pub async fn stop_monitor(&self, gw_id: Uuid) {
        if let Some(h) = self.monitors.lock().await.remove(&gw_id) {
            h.abort();
        }
    }

    /// Start monitors for all enabled gateways. Called by daemon at boot.
    pub async fn start_all(self: &Arc<Self>) -> Result<()> {
        let list = self.list().await?;
        for gw in list {
            if gw.enabled {
                let _ = self.start_monitor(gw.id).await;
            }
        }
        Ok(())
    }
}

fn row_to_gw(r: &sqlx::sqlite::SqliteRow) -> Gateway {
    Gateway {
        id: r.get::<String, _>("id").parse().unwrap_or_default(),
        name: r.get("name"),
        instance_id: r
            .get::<String, _>("instance_id")
            .parse()
            .unwrap_or_default(),
        interface: r.get("interface"),
        next_hop: r.get("next_hop"),
        ip_version: r.get("ip_version"),
        monitor_kind: r.get("monitor_kind"),
        monitor_target: r.get("monitor_target"),
        monitor_port: r.get::<Option<i64>, _>("monitor_port").map(|v| v as u16),
        monitor_expect: r.get("monitor_expect"),
        interval_ms: r.get::<i64, _>("interval_ms") as u64,
        timeout_ms: r.get::<i64, _>("timeout_ms") as u64,
        loss_pct_down: r.get("loss_pct_down"),
        loss_pct_up: r.get("loss_pct_up"),
        latency_ms_down: r
            .get::<Option<i64>, _>("latency_ms_down")
            .map(|v| v as u64),
        latency_ms_up: r.get::<Option<i64>, _>("latency_ms_up").map(|v| v as u64),
        consec_fail_down: r.get::<i64, _>("consec_fail_down") as u32,
        consec_ok_up: r.get::<i64, _>("consec_ok_up") as u32,
        weight: r.get::<i64, _>("weight") as u32,
        dampening_secs: r.get::<i64, _>("dampening_secs") as u32,
        dscp_tag: r.get::<Option<i64>, _>("dscp_tag").map(|v| v as u8),
        enabled: r.get::<i64, _>("enabled") != 0,
        state: GatewayState::parse(&r.get::<String, _>("state"))
            .unwrap_or(GatewayState::Unknown),
        last_rtt_ms: r.get("last_rtt_ms"),
        last_jitter_ms: r.get("last_jitter_ms"),
        last_loss_pct: r.get("last_loss_pct"),
        last_mos: r.get("last_mos"),
        last_probe_ts: r
            .get::<Option<String>, _>("last_probe_ts")
            .and_then(|s| s.parse().ok()),
        created_at: r
            .get::<String, _>("created_at")
            .parse()
            .unwrap_or_default(),
        updated_at: r
            .get::<String, _>("updated_at")
            .parse()
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiwan::InstanceEngine;
    use aifw_pf::PfMock;

    async fn setup() -> (Arc<GatewayEngine>, Uuid) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap();
        let pf = Arc::new(PfMock::new());
        pf.set_fib_count(4).await;
        let inst = InstanceEngine::new(pool.clone(), pf);
        inst.migrate().await.unwrap();
        let engine = Arc::new(GatewayEngine::new(pool));
        engine.migrate().await.unwrap();
        let default_id = aifw_common::DEFAULT_INSTANCE_ID;
        (engine, default_id)
    }

    fn make_gw(name: &str, instance_id: Uuid) -> Gateway {
        Gateway {
            id: Uuid::new_v4(),
            name: name.into(),
            instance_id,
            interface: "em0".into(),
            next_hop: "10.0.0.1".into(),
            ip_version: "v4".into(),
            monitor_kind: "icmp".into(),
            monitor_target: Some("10.0.0.1".into()),
            monitor_port: None,
            monitor_expect: None,
            interval_ms: 500,
            timeout_ms: 1000,
            loss_pct_down: 20.0,
            loss_pct_up: 5.0,
            latency_ms_down: None,
            latency_ms_up: None,
            consec_fail_down: 3,
            consec_ok_up: 5,
            weight: 1,
            dampening_secs: 10,
            dscp_tag: None,
            enabled: true,
            state: GatewayState::Unknown,
            last_rtt_ms: None,
            last_jitter_ms: None,
            last_loss_pct: None,
            last_mos: None,
            last_probe_ts: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn gateway_crud() {
        let (engine, inst) = setup().await;
        let gw = engine.add(make_gw("wan1", inst)).await.unwrap();
        let fetched = engine.get(gw.id).await.unwrap();
        assert_eq!(fetched.name, "wan1");
        let list = engine.list().await.unwrap();
        assert_eq!(list.len(), 1);
        engine.delete(gw.id).await.unwrap();
        assert!(engine.get(gw.id).await.is_err());
    }

    #[tokio::test]
    async fn transition_to_down_after_consec_failures() {
        let (engine, inst) = setup().await;
        let gw = engine.add(make_gw("wan1", inst)).await.unwrap();
        let mut rx = engine.subscribe();

        for _ in 0..3 {
            engine
                .inject_sample(
                    gw.id,
                    ProbeOutcome {
                        success: false,
                        rtt_ms: None,
                        error: Some("timeout".into()),
                    },
                )
                .await
                .unwrap();
        }

        // Drain transitions until we see Down (Unknown→Warning may fire first)
        let mut saw_down = false;
        while let Ok(ev) = rx.try_recv() {
            if ev.to_state == GatewayState::Down {
                saw_down = true;
            }
        }
        assert!(saw_down, "expected a transition to Down");
        let events = engine.list_events(gw.id, 10).await.unwrap();
        assert!(events.iter().any(|e| e.to_state == GatewayState::Down));
    }

    #[tokio::test]
    async fn transition_to_up_after_consec_successes() {
        let (engine, inst) = setup().await;
        let gw = engine.add(make_gw("wan1", inst)).await.unwrap();
        for _ in 0..5 {
            engine
                .inject_sample(
                    gw.id,
                    ProbeOutcome {
                        success: true,
                        rtt_ms: Some(10.0),
                        error: None,
                    },
                )
                .await
                .unwrap();
        }
        let updated = engine.get(gw.id).await.unwrap();
        assert_eq!(updated.state, GatewayState::Up);
    }

    #[test]
    fn evaluate_transition_strict_down() {
        let mut m = GatewayMetrics::default();
        m.consec_fail = 3;
        let s = evaluate_transition(GatewayState::Up, &m, 3, 5, 20.0, 5.0);
        assert_eq!(s, GatewayState::Down);
    }

    #[test]
    fn evaluate_transition_warning_on_loss() {
        let mut m = GatewayMetrics::default();
        m.consec_ok = 10;
        m.recent_loss = 8.0;
        let s = evaluate_transition(GatewayState::Down, &m, 3, 5, 20.0, 5.0);
        assert_eq!(s, GatewayState::Warning);
    }
}
