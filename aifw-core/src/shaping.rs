use aifw_common::{
    Address, AifwError, Bandwidth, BandwidthUnit, Interface, PortRange, Protocol, QueueConfig,
    QueueStatus, QueueType, RateLimitRule, RateLimitStatus, Result, TrafficClass,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub struct ShapingEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl ShapingEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw".to_string(),
        }
    }

    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS queue_configs (
                id TEXT PRIMARY KEY,
                interface TEXT NOT NULL,
                queue_type TEXT NOT NULL,
                bandwidth_value INTEGER NOT NULL,
                bandwidth_unit TEXT NOT NULL,
                name TEXT NOT NULL,
                traffic_class TEXT NOT NULL,
                bandwidth_pct INTEGER,
                is_default INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS rate_limit_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                interface TEXT,
                protocol TEXT NOT NULL,
                src_addr TEXT NOT NULL,
                dst_addr TEXT NOT NULL,
                dst_port_start INTEGER,
                dst_port_end INTEGER,
                max_connections INTEGER NOT NULL,
                window_secs INTEGER NOT NULL,
                overload_table TEXT NOT NULL,
                flush_states INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // --- Queue operations ---

    pub async fn add_queue(&self, config: QueueConfig) -> Result<QueueConfig> {
        self.insert_queue(&config).await?;
        tracing::info!(id = %config.id, name = %config.name, "queue added");
        Ok(config)
    }

    pub async fn list_queues(&self) -> Result<Vec<QueueConfig>> {
        let rows =
            sqlx::query_as::<_, QueueRow>("SELECT * FROM queue_configs ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter().map(|r| r.into_queue()).collect()
    }

    pub async fn delete_queue(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM queue_configs WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("queue {id} not found")));
        }
        tracing::info!(%id, "queue deleted");
        Ok(())
    }

    pub async fn apply_queues(&self) -> Result<()> {
        let queues = self.list_queues().await?;
        let active: Vec<_> = queues
            .iter()
            .filter(|q| q.status == QueueStatus::Active)
            .collect();

        let mut pf_lines = Vec::new();
        // Group by interface — each needs a parent queue
        let mut interfaces_seen = std::collections::HashSet::new();
        for q in &active {
            if interfaces_seen.insert(q.interface.0.clone()) {
                pf_lines.push(q.to_pf_parent_queue());
            }
            pf_lines.push(q.to_pf_queue());
        }

        tracing::info!(count = pf_lines.len(), "applying queue configs to pf");
        self.pf
            .load_queues(&self.anchor, &pf_lines)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }

    // --- Rate limit operations ---

    pub async fn add_rate_limit(&self, rule: RateLimitRule) -> Result<RateLimitRule> {
        if rule.max_connections == 0 {
            return Err(AifwError::Validation(
                "max_connections must be > 0".to_string(),
            ));
        }
        if rule.window_secs == 0 {
            return Err(AifwError::Validation("window_secs must be > 0".to_string()));
        }
        if rule.overload_table.is_empty() {
            return Err(AifwError::Validation(
                "overload_table name required".to_string(),
            ));
        }
        self.insert_rate_limit(&rule).await?;
        tracing::info!(id = %rule.id, name = %rule.name, "rate limit rule added");
        Ok(rule)
    }

    pub async fn list_rate_limits(&self) -> Result<Vec<RateLimitRule>> {
        let rows = sqlx::query_as::<_, RateLimitRow>(
            "SELECT * FROM rate_limit_rules ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_rate_limit()).collect()
    }

    pub async fn delete_rate_limit(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM rate_limit_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("rate limit {id} not found")));
        }
        tracing::info!(%id, "rate limit rule deleted");
        Ok(())
    }

    /// Apply rate limit rules — generates pf tables, block rules, and pass rules with overload
    pub async fn apply_rate_limits(&self) -> Result<()> {
        let rules = self.list_rate_limits().await?;
        let active: Vec<_> = rules
            .iter()
            .filter(|r| r.status == RateLimitStatus::Active)
            .collect();

        let mut pf_lines = Vec::new();
        for r in &active {
            pf_lines.push(r.to_pf_table());
            pf_lines.push(r.to_pf_block_rule());
            pf_lines.push(r.to_pf_rule());
        }

        tracing::info!(count = active.len(), "applying rate limit rules to pf");
        // Rate limit rules go into the main rules anchor
        self.pf
            .load_rules(&format!("{}-ratelimit", self.anchor), &pf_lines)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }

    // --- DB helpers ---

    async fn insert_queue(&self, q: &QueueConfig) -> Result<()> {
        let bw_unit = match q.bandwidth.unit {
            BandwidthUnit::Bps => "bps",
            BandwidthUnit::Kbps => "kbps",
            BandwidthUnit::Mbps => "mbps",
            BandwidthUnit::Gbps => "gbps",
        };
        sqlx::query(
            r#"
            INSERT INTO queue_configs (id, interface, queue_type, bandwidth_value, bandwidth_unit,
                name, traffic_class, bandwidth_pct, is_default, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
        )
        .bind(q.id.to_string())
        .bind(&q.interface.0)
        .bind(q.queue_type.to_string())
        .bind(q.bandwidth.value as i64)
        .bind(bw_unit)
        .bind(&q.name)
        .bind(q.traffic_class.to_string())
        .bind(q.bandwidth_pct.map(|p| p as i64))
        .bind(q.default)
        .bind(match q.status {
            QueueStatus::Active => "active",
            QueueStatus::Disabled => "disabled",
        })
        .bind(q.created_at.to_rfc3339())
        .bind(q.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn insert_rate_limit(&self, r: &RateLimitRule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO rate_limit_rules (id, name, interface, protocol, src_addr, dst_addr,
                dst_port_start, dst_port_end, max_connections, window_secs,
                overload_table, flush_states, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
        )
        .bind(r.id.to_string())
        .bind(&r.name)
        .bind(r.interface.as_ref().map(|i| i.0.as_str()))
        .bind(r.protocol.to_string())
        .bind(r.src_addr.to_string())
        .bind(r.dst_addr.to_string())
        .bind(r.dst_port.as_ref().map(|p| p.start as i64))
        .bind(r.dst_port.as_ref().map(|p| p.end as i64))
        .bind(r.max_connections as i64)
        .bind(r.window_secs as i64)
        .bind(&r.overload_table)
        .bind(r.flush_states)
        .bind(match r.status {
            RateLimitStatus::Active => "active",
            RateLimitStatus::Disabled => "disabled",
        })
        .bind(r.created_at.to_rfc3339())
        .bind(r.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// --- Row types ---

#[derive(sqlx::FromRow)]
struct QueueRow {
    id: String,
    interface: String,
    queue_type: String,
    bandwidth_value: i64,
    bandwidth_unit: String,
    name: String,
    traffic_class: String,
    bandwidth_pct: Option<i64>,
    is_default: bool,
    status: String,
    created_at: String,
    updated_at: String,
}

impl QueueRow {
    fn into_queue(self) -> Result<QueueConfig> {
        let bw_unit = match self.bandwidth_unit.as_str() {
            "gbps" => BandwidthUnit::Gbps,
            "mbps" => BandwidthUnit::Mbps,
            "kbps" => BandwidthUnit::Kbps,
            _ => BandwidthUnit::Bps,
        };
        Ok(QueueConfig {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            interface: Interface(self.interface),
            queue_type: QueueType::parse(&self.queue_type)?,
            bandwidth: Bandwidth {
                value: self.bandwidth_value as u64,
                unit: bw_unit,
            },
            name: self.name,
            traffic_class: TrafficClass::parse(&self.traffic_class)?,
            bandwidth_pct: self.bandwidth_pct.map(|p| p as u8),
            default: self.is_default,
            status: match self.status.as_str() {
                "active" => QueueStatus::Active,
                _ => QueueStatus::Disabled,
            },
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct RateLimitRow {
    id: String,
    name: String,
    interface: Option<String>,
    protocol: String,
    src_addr: String,
    dst_addr: String,
    dst_port_start: Option<i64>,
    dst_port_end: Option<i64>,
    max_connections: i64,
    window_secs: i64,
    overload_table: String,
    flush_states: bool,
    status: String,
    created_at: String,
    updated_at: String,
}

impl RateLimitRow {
    fn into_rate_limit(self) -> Result<RateLimitRule> {
        Ok(RateLimitRule {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            name: self.name,
            interface: self.interface.map(Interface),
            protocol: Protocol::parse(&self.protocol)?,
            src_addr: Address::parse(&self.src_addr)?,
            dst_addr: Address::parse(&self.dst_addr)?,
            dst_port: match (self.dst_port_start, self.dst_port_end) {
                (Some(s), Some(e)) => Some(PortRange {
                    start: s as u16,
                    end: e as u16,
                }),
                _ => None,
            },
            max_connections: self.max_connections as u32,
            window_secs: self.window_secs as u32,
            overload_table: self.overload_table,
            flush_states: self.flush_states,
            status: match self.status.as_str() {
                "active" => RateLimitStatus::Active,
                _ => RateLimitStatus::Disabled,
            },
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
        })
    }
}
