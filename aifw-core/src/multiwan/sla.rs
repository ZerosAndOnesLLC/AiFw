//! SLA aggregation — 1-minute buckets with 30-day retention.

use aifw_common::{AifwError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

/// One aggregated 1-minute bucket of probe statistics for a gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSample {
    /// Gateway the bucket belongs to
    pub gateway_id: Uuid,
    /// Start of the 1-minute aggregation bucket (UTC)
    pub bucket_ts: DateTime<Utc>,
    /// Number of probes aggregated into this bucket
    pub samples: u64,
    /// Mean round-trip time over the bucket, in milliseconds
    pub rtt_avg: Option<f64>,
    /// 95th-percentile round-trip time, in milliseconds
    pub rtt_p95: Option<f64>,
    /// 99th-percentile round-trip time, in milliseconds
    pub rtt_p99: Option<f64>,
    /// Mean jitter over the bucket, in milliseconds
    pub jitter_avg: Option<f64>,
    /// Packet loss over the bucket as a percentage (0–100)
    pub loss_pct: Option<f64>,
    /// Mean approximated MOS score (1.0–4.5) over the bucket
    pub mos_avg: Option<f64>,
    /// Seconds within the bucket the gateway was in the Up state
    pub up_seconds: u64,
}

/// Explicit column list for `multiwan_sla_samples` selects (schema order).
/// `SELECT *` triggers a sqlx-sqlite column-count panic (#348) that blocks
/// pruning, so every query names its columns. Must match the `CREATE TABLE`
/// in `migrate()` and every `.get(...)` in `window`.
const SLA_COLUMNS: &str = "gateway_id, bucket_ts, samples, rtt_avg, rtt_p95, rtt_p99, \
    jitter_avg, loss_pct, mos_avg, up_seconds";

/// SLA history engine: stores per-gateway 1-minute probe aggregates in
/// `multiwan_sla_samples` for windowed queries and retention pruning
pub struct SlaEngine {
    pool: SqlitePool,
}

impl SlaEngine {
    /// Create the engine over an existing SQLite pool (call `migrate` before use)
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the `multiwan_sla_samples` table if it doesn't exist
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_sla_samples (
                gateway_id TEXT NOT NULL,
                bucket_ts TEXT NOT NULL,
                samples INTEGER NOT NULL,
                rtt_avg REAL,
                rtt_p95 REAL,
                rtt_p99 REAL,
                jitter_avg REAL,
                loss_pct REAL,
                mos_avg REAL,
                up_seconds INTEGER NOT NULL,
                PRIMARY KEY (gateway_id, bucket_ts)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    /// Append a sample (called by gateway engine periodically).
    pub async fn record(&self, sample: &SlaSample) -> Result<()> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO multiwan_sla_samples
            (gateway_id, bucket_ts, samples, rtt_avg, rtt_p95, rtt_p99,
             jitter_avg, loss_pct, mos_avg, up_seconds)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"#,
        )
        .bind(sample.gateway_id.to_string())
        .bind(sample.bucket_ts.to_rfc3339())
        .bind(sample.samples as i64)
        .bind(sample.rtt_avg)
        .bind(sample.rtt_p95)
        .bind(sample.rtt_p99)
        .bind(sample.jitter_avg)
        .bind(sample.loss_pct)
        .bind(sample.mos_avg)
        .bind(sample.up_seconds as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    /// Retrieve samples for a gateway within a rolling window.
    pub async fn window(&self, gw_id: Uuid, hours: i64) -> Result<Vec<SlaSample>> {
        let since = (Utc::now() - Duration::hours(hours)).to_rfc3339();
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SLA_COLUMNS} FROM multiwan_sla_samples WHERE gateway_id = ?1 AND bucket_ts >= ?2
             ORDER BY bucket_ts ASC"
        )))
        .bind(gw_id.to_string())
        .bind(since)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows
            .iter()
            .map(|r| SlaSample {
                gateway_id: r.get::<String, _>("gateway_id").parse().unwrap_or_default(),
                bucket_ts: r.get::<String, _>("bucket_ts").parse().unwrap_or_default(),
                samples: r.get::<i64, _>("samples") as u64,
                rtt_avg: r.get("rtt_avg"),
                rtt_p95: r.get("rtt_p95"),
                rtt_p99: r.get("rtt_p99"),
                jitter_avg: r.get("jitter_avg"),
                loss_pct: r.get("loss_pct"),
                mos_avg: r.get("mos_avg"),
                up_seconds: r.get::<i64, _>("up_seconds") as u64,
            })
            .collect())
    }

    /// Remove samples older than `retention_days`.
    pub async fn prune(&self, retention_days: i64) -> Result<u64> {
        let cutoff = (Utc::now() - Duration::days(retention_days)).to_rfc3339();
        let res = sqlx::query("DELETE FROM multiwan_sla_samples WHERE bucket_ts < ?1")
            .bind(cutoff)
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }
}
