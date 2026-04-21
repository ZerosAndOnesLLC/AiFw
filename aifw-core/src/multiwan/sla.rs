//! SLA aggregation — 1-minute buckets with 30-day retention.

use aifw_common::{AifwError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSample {
    pub gateway_id: Uuid,
    pub bucket_ts: DateTime<Utc>,
    pub samples: u64,
    pub rtt_avg: Option<f64>,
    pub rtt_p95: Option<f64>,
    pub rtt_p99: Option<f64>,
    pub jitter_avg: Option<f64>,
    pub loss_pct: Option<f64>,
    pub mos_avg: Option<f64>,
    pub up_seconds: u64,
}

pub struct SlaEngine {
    pool: SqlitePool,
}

impl SlaEngine {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

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
        let rows = sqlx::query(
            "SELECT * FROM multiwan_sla_samples WHERE gateway_id = ?1 AND bucket_ts >= ?2
             ORDER BY bucket_ts ASC",
        )
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
