use aifw_common::ids::{AlertClassification, IdsAlert};
use chrono::{DateTime, Datelike, Duration, Utc};
use sqlx::SqlitePool;

use super::AlertOutput;
use crate::Result;

/// Sanity-check a wall-clock timestamp before persisting it. The IDS alert
/// pipeline takes `Utc::now()` at alert-create time; a system clock that's
/// briefly wrong (NTP skew, VM resume from snapshot, BIOS battery, etc.)
/// has produced rows dated year 9920 or 2012 in production. Clamp anything
/// far outside the plausible window to the insert-time clock so dashboards
/// don't get poisoned.
fn sanitize_alert_timestamp(ts: DateTime<Utc>) -> DateTime<Utc> {
    let now = Utc::now();
    let lower = now - Duration::days(365 * 5);
    let upper = now + Duration::hours(1);
    if ts < lower || ts > upper || !(2020..=2100).contains(&ts.year()) {
        tracing::warn!(
            original = %ts.to_rfc3339(),
            replaced_with = %now.to_rfc3339(),
            "ids alert had implausible timestamp; clamping to now"
        );
        now
    } else {
        ts
    }
}

/// SQLite alert storage — powers the UI alert viewer.
pub struct SqliteOutput {
    pool: SqlitePool,
}

impl SqliteOutput {
    /// Create a SQLite alert sink writing to the given pool's `ids_alerts`
    /// table (the table is created by the engine's migration).
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Query alerts with filtering, pagination, and ordering.
    pub async fn query_alerts(
        &self,
        severity: Option<u8>,
        src_ip: Option<&str>,
        signature_id: Option<u32>,
        acknowledged: Option<bool>,
        classification: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<IdsAlert>> {
        let mut conditions = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(sev) = severity {
            conditions.push("severity = ?");
            bind_values.push(sev.to_string());
        }
        if let Some(ip) = src_ip {
            conditions.push("src_ip = ?");
            bind_values.push(ip.to_string());
        }
        if let Some(sid) = signature_id {
            conditions.push("signature_id = ?");
            bind_values.push(sid.to_string());
        }
        if let Some(ack) = acknowledged {
            conditions.push("acknowledged = ?");
            bind_values.push(if ack { "1" } else { "0" }.to_string());
        }
        if let Some(cls) = classification {
            if cls == "reviewed" {
                // Special filter: any classification that is NOT unreviewed
                conditions.push("classification != 'unreviewed'");
            } else {
                conditions.push("classification = ?");
                bind_values.push(cls.to_string());
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        // SQLx tuple FromRow maxes out at 16 fields. We pack classification|notes
        // into field 13 (replacing flow_id which is rarely used) and shift.
        // PERF-H9: keep LIMIT/OFFSET as bind params so a single prepared
        // statement is cached regardless of the paging window.
        let sql = format!(
            "SELECT id, timestamp, signature_id, signature_msg, severity, src_ip, src_port, dst_ip, dst_port, protocol, action, rule_source, payload_excerpt, metadata, acknowledged, COALESCE(classification, 'unreviewed') || '|' || COALESCE(analyst_notes, '') FROM ids_alerts{where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        );

        let mut query = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<i64>,
                String,
                i64,
                String,
                Option<i64>,
                String,
                Option<i64>,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                bool,
                String,
            ),
        >(sqlx::AssertSqlSafe(sql));

        for val in &bind_values {
            query = query.bind(val);
        }
        query = query.bind(limit as i64).bind(offset as i64);

        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let src_ip = row.5.parse().ok()?;
                let dst_ip = row.7.parse().ok()?;
                Some(IdsAlert {
                    id: uuid::Uuid::parse_str(&row.0).ok()?,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&row.1)
                        .ok()?
                        .with_timezone(&chrono::Utc),
                    signature_id: row.2.map(|v| v as u32),
                    signature_msg: row.3,
                    severity: aifw_common::ids::IdsSeverity(row.4 as u8),
                    src_ip,
                    src_port: row.6.map(|v| v as u16),
                    dst_ip,
                    dst_port: row.8.map(|v| v as u16),
                    protocol: row.9,
                    action: aifw_common::ids::IdsAction::from_str(&row.10)
                        .unwrap_or(aifw_common::ids::IdsAction::Alert),
                    rule_source: aifw_common::ids::RuleSource::from_str(&row.11)
                        .unwrap_or(aifw_common::ids::RuleSource::Custom),
                    payload_excerpt: row.12,
                    metadata: row.13.and_then(|s| serde_json::from_str(&s).ok()),
                    acknowledged: row.14,
                    classification: row
                        .15
                        .split('|')
                        .next()
                        .and_then(AlertClassification::parse)
                        .unwrap_or_default(),
                    analyst_notes: {
                        let packed = &row.15;
                        packed.split_once('|').and_then(|(_, n)| {
                            if n.is_empty() {
                                None
                            } else {
                                Some(n.to_string())
                            }
                        })
                    },
                    flow_id: None,
                })
            })
            .collect())
    }

    /// Get a single alert by ID.
    pub async fn get_alert(&self, id: uuid::Uuid) -> Result<Option<IdsAlert>> {
        let row: Option<(String, String, Option<i64>, String, i64, String, Option<i64>, String, Option<i64>, String, String, String, Option<String>, Option<String>, bool, String)> =
            sqlx::query_as(
                "SELECT id, timestamp, signature_id, signature_msg, severity, src_ip, src_port, dst_ip, dst_port, protocol, action, rule_source, payload_excerpt, metadata, acknowledged, COALESCE(classification, 'unreviewed') || '|' || COALESCE(analyst_notes, '') FROM ids_alerts WHERE id = ?"
            )
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.and_then(|row| {
            let src_ip = row.5.parse().ok()?;
            let dst_ip = row.7.parse().ok()?;
            Some(IdsAlert {
                id: uuid::Uuid::parse_str(&row.0).ok()?,
                timestamp: chrono::DateTime::parse_from_rfc3339(&row.1)
                    .ok()?
                    .with_timezone(&chrono::Utc),
                signature_id: row.2.map(|v| v as u32),
                signature_msg: row.3,
                severity: aifw_common::ids::IdsSeverity(row.4 as u8),
                src_ip,
                src_port: row.6.map(|v| v as u16),
                dst_ip,
                dst_port: row.8.map(|v| v as u16),
                protocol: row.9,
                action: aifw_common::ids::IdsAction::from_str(&row.10)
                    .unwrap_or(aifw_common::ids::IdsAction::Alert),
                rule_source: aifw_common::ids::RuleSource::from_str(&row.11)
                    .unwrap_or(aifw_common::ids::RuleSource::Custom),
                flow_id: None,
                payload_excerpt: row.12,
                metadata: row.13.and_then(|s| serde_json::from_str(&s).ok()),
                acknowledged: row.14,
                classification: row
                    .15
                    .split('|')
                    .next()
                    .and_then(AlertClassification::parse)
                    .unwrap_or_default(),
                analyst_notes: {
                    let packed = &row.15;
                    packed.split_once('|').and_then(|(_, n)| {
                        if n.is_empty() {
                            None
                        } else {
                            Some(n.to_string())
                        }
                    })
                },
            })
        }))
    }

    /// Classify an alert (confirmed, false_positive, investigating, unreviewed).
    pub async fn classify(
        &self,
        id: uuid::Uuid,
        classification: AlertClassification,
        notes: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE ids_alerts SET classification = ?, analyst_notes = ?, acknowledged = 1 WHERE id = ?")
            .bind(classification.as_str())
            .bind(notes)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Acknowledge an alert.
    pub async fn acknowledge(&self, id: uuid::Uuid) -> Result<()> {
        sqlx::query("UPDATE ids_alerts SET acknowledged = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Purge alerts older than N days.
    pub async fn purge_old(&self, days: u32) -> Result<u64> {
        // PERF-M2: bind the modifier so every retention tick reuses one
        // cached prepared statement instead of compiling a fresh one.
        //
        // Batched (#616/#617): a stale appliance's first purge deletes
        // millions of rows, and a single DELETE holds the SQLite write
        // lock for the whole transaction — minutes on a multi-GB file,
        // which starved aifw-api's startup into a crash-loop on a live
        // box. Small batches with a yield between let other writers
        // interleave; the upgrade path must work without intervention.
        self.purge_batched(
            "DELETE FROM ids_alerts WHERE rowid IN \
             (SELECT rowid FROM ids_alerts WHERE timestamp < datetime('now', ?1) LIMIT ?2)",
            Some(format!("-{days} days")),
        )
        .await
    }

    /// Run a windowed DELETE repeatedly until it stops matching rows,
    /// sleeping briefly between batches so concurrent writers (api
    /// migrations, alert ingestion) are never starved for long.
    async fn purge_batched(&self, sql: &'static str, modifier: Option<String>) -> Result<u64> {
        const BATCH: i64 = 20_000;
        let mut total: u64 = 0;
        loop {
            let mut q = sqlx::query(sql);
            if let Some(ref m) = modifier {
                q = q.bind(m.clone());
            }
            let affected = q.bind(BATCH).execute(&self.pool).await?.rows_affected();
            total += affected;
            if (affected as i64) < BATCH {
                return Ok(total);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Reclaim disk space after mass deletions. A bare DELETE only frees
    /// pages to SQLite's freelist — an appliance in the field sat at a
    /// 2.9GB DB file holding 34 alert rows (#601). VACUUM rewrites the
    /// file; the TRUNCATE checkpoint shrinks the WAL that the rewrite
    /// itself streams through (without it the gigabytes just move into
    /// aifw.db-wal).
    pub async fn reclaim_space(&self) -> Result<()> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_all(&self.pool)
            .await?;
        Ok(())
    }

    /// Scrub rows whose `timestamp` column is implausible — system-clock skew
    /// at insert time has left rows dated year 9920 or 2012 on appliances in
    /// the field. The companion guard at insert time (`sanitize_alert_timestamp`)
    /// prevents new ones; this method removes the existing pollution.
    pub async fn purge_invalid_timestamps(&self) -> Result<u64> {
        // Batched for the same reason as purge_old: hundreds of thousands
        // of clock-skew rows in one DELETE monopolize the write lock.
        self.purge_batched(
            "DELETE FROM ids_alerts WHERE rowid IN \
             (SELECT rowid FROM ids_alerts \
              WHERE timestamp < '2020-01-01' \
                 OR timestamp > datetime('now', '+1 day') LIMIT ?1)",
            None,
        )
        .await
    }

    /// Get alert count by severity over the last 24 hours.
    ///
    /// The dashboard uses this to drive its current-state chart, so an
    /// unfiltered scan over millions of historical rows isn't what users
    /// actually want anyway. The 24h window is covered by `idx_ids_alerts_ts`
    /// (timestamp index) and keeps the query latency bounded regardless of
    /// total row count.
    pub async fn count_by_severity(&self) -> Result<Vec<(u8, i64)>> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT severity, count(*) FROM ids_alerts \
             WHERE timestamp >= datetime('now', '-1 day') \
             GROUP BY severity ORDER BY severity",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(s, c)| (s as u8, c)).collect())
    }

    /// Get top N alerting signatures over the last 24 hours.
    /// See `count_by_severity` for the rationale on the time window.
    pub async fn top_signatures(&self, limit: u32) -> Result<Vec<(String, i64)>> {
        // PERF-H9: bind LIMIT so this aggregate reuses one cached statement.
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT signature_msg, count(*) as cnt FROM ids_alerts \
             WHERE timestamp >= datetime('now', '-1 day') \
             GROUP BY signature_msg ORDER BY cnt DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Get top N source IPs over the last 24 hours.
    /// See `count_by_severity` for the rationale on the time window.
    pub async fn top_sources(&self, limit: u32) -> Result<Vec<(String, i64)>> {
        // PERF-H9: bind LIMIT so this aggregate reuses one cached statement.
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT src_ip, count(*) as cnt FROM ids_alerts \
             WHERE timestamp >= datetime('now', '-1 day') \
             GROUP BY src_ip ORDER BY cnt DESC LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[async_trait::async_trait]
impl AlertOutput for SqliteOutput {
    async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        let metadata_json = alert
            .metadata
            .as_ref()
            .and_then(|m| serde_json::to_string(m).ok());

        sqlx::query(
            "INSERT INTO ids_alerts (id, timestamp, signature_id, signature_msg, severity, src_ip, src_port, dst_ip, dst_port, protocol, action, rule_source, flow_id, payload_excerpt, metadata, acknowledged) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
        )
        .bind(alert.id.to_string())
        .bind(sanitize_alert_timestamp(alert.timestamp).to_rfc3339())
        .bind(alert.signature_id.map(|s| s as i64))
        .bind(&alert.signature_msg)
        .bind(alert.severity.0 as i64)
        .bind(alert.src_ip.to_string())
        .bind(alert.src_port.map(|p| p as i64))
        .bind(alert.dst_ip.to_string())
        .bind(alert.dst_port.map(|p| p as i64))
        .bind(&alert.protocol)
        .bind(alert.action.to_string())
        .bind(alert.rule_source.to_string())
        .bind(&alert.flow_id)
        .bind(&alert.payload_excerpt)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(()) // SQLite commits are immediate
    }

    fn name(&self) -> &str {
        "sqlite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

    async fn setup() -> SqliteOutput {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();
        SqliteOutput::new(pool)
    }

    fn test_alert() -> IdsAlert {
        IdsAlert::new(
            "Test alert".into(),
            IdsSeverity::HIGH,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "tcp",
            IdsAction::Alert,
            RuleSource::EtOpen,
        )
    }

    #[tokio::test]
    async fn test_emit_and_query() {
        let output = setup().await;

        let alert = test_alert();
        output.emit(&alert).await.unwrap();

        let alerts = output
            .query_alerts(None, None, None, None, None, 100, 0)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].signature_msg, "Test alert");
    }

    #[tokio::test]
    async fn test_acknowledge() {
        let output = setup().await;

        let alert = test_alert();
        let id = alert.id;
        output.emit(&alert).await.unwrap();

        output.acknowledge(id).await.unwrap();

        let loaded = output.get_alert(id).await.unwrap().unwrap();
        assert!(loaded.acknowledged);
    }

    #[tokio::test]
    async fn test_count_by_severity() {
        let output = setup().await;

        output.emit(&test_alert()).await.unwrap();
        let mut alert2 = test_alert();
        alert2.severity = IdsSeverity::CRITICAL;
        output.emit(&alert2).await.unwrap();

        let counts = output.count_by_severity().await.unwrap();
        assert!(!counts.is_empty());
    }

    #[test]
    fn sanitize_clamps_year_9920() {
        let bad = DateTime::parse_from_rfc3339("9920-03-27T04:49:13Z")
            .unwrap()
            .with_timezone(&Utc);
        let now = Utc::now();
        let fixed = sanitize_alert_timestamp(bad);
        assert!((fixed - now).num_seconds().abs() < 5);
    }

    #[test]
    fn sanitize_clamps_year_2012() {
        let bad = DateTime::parse_from_rfc3339("2012-04-06T04:29:12Z")
            .unwrap()
            .with_timezone(&Utc);
        let now = Utc::now();
        let fixed = sanitize_alert_timestamp(bad);
        assert!((fixed - now).num_seconds().abs() < 5);
    }

    #[test]
    fn sanitize_passes_current_time() {
        let now = Utc::now();
        let fixed = sanitize_alert_timestamp(now);
        assert_eq!(fixed, now);
    }

    #[test]
    fn sanitize_rejects_far_future() {
        let bad = Utc::now() + Duration::hours(24);
        let now = Utc::now();
        let fixed = sanitize_alert_timestamp(bad);
        assert!((fixed - now).num_seconds().abs() < 5);
    }
}
