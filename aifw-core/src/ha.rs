use aifw_common::{
    AifwError, CarpStatus, CarpVip, ClusterNode, ClusterRole, HealthCheck, HealthCheckType,
    Interface, NodeHealth, PfsyncConfig, Result,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub struct ClusterEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl ClusterEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw-ha".to_string(),
        }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS carp_vips (
                id TEXT PRIMARY KEY,
                vhid INTEGER NOT NULL,
                virtual_ip TEXT NOT NULL,
                prefix INTEGER NOT NULL,
                interface TEXT NOT NULL,
                advskew INTEGER NOT NULL DEFAULT 0,
                advbase INTEGER NOT NULL DEFAULT 1,
                password TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'init',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cluster_nodes (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL,
                role TEXT NOT NULL,
                health TEXT NOT NULL DEFAULT 'unknown',
                last_seen TEXT NOT NULL,
                config_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS health_checks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                check_type TEXT NOT NULL,
                interval_secs INTEGER NOT NULL DEFAULT 10,
                timeout_secs INTEGER NOT NULL DEFAULT 5,
                failures_before_down INTEGER NOT NULL DEFAULT 3,
                target TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS pfsync_config (
                id TEXT PRIMARY KEY,
                sync_interface TEXT NOT NULL,
                sync_peer TEXT,
                defer_mode INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ============================================================
    // CARP VIP management
    // ============================================================

    pub async fn add_carp_vip(&self, vip: CarpVip) -> Result<CarpVip> {
        if vip.vhid == 0 {
            return Err(AifwError::Validation("VHID must be > 0".to_string()));
        }
        if vip.password.is_empty() {
            return Err(AifwError::Validation("CARP password required".to_string()));
        }

        sqlx::query(
            r#"
            INSERT INTO carp_vips (id, vhid, virtual_ip, prefix, interface, advskew, advbase,
                password, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
        )
        .bind(vip.id.to_string())
        .bind(vip.vhid as i64)
        .bind(vip.virtual_ip.to_string())
        .bind(vip.prefix as i64)
        .bind(&vip.interface.0)
        .bind(vip.advskew as i64)
        .bind(vip.advbase as i64)
        .bind(&vip.password)
        .bind(vip.status.to_string())
        .bind(vip.created_at.to_rfc3339())
        .bind(vip.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %vip.id, vhid = vip.vhid, ip = %vip.virtual_ip, "CARP VIP added");
        Ok(vip)
    }

    pub async fn list_carp_vips(&self) -> Result<Vec<CarpVip>> {
        let rows = sqlx::query_as::<_, CarpVipRow>(
            "SELECT * FROM carp_vips ORDER BY vhid ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_vip()).collect()
    }

    pub async fn delete_carp_vip(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM carp_vips WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("CARP VIP {id} not found")));
        }
        Ok(())
    }

    // ============================================================
    // pfsync
    // ============================================================

    pub async fn set_pfsync(&self, config: PfsyncConfig) -> Result<PfsyncConfig> {
        // Replace any existing config
        sqlx::query("DELETE FROM pfsync_config").execute(&self.pool).await?;

        sqlx::query(
            "INSERT INTO pfsync_config (id, sync_interface, sync_peer, defer_mode, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(config.id.to_string())
        .bind(&config.sync_interface.0)
        .bind(config.sync_peer.map(|p| p.to_string()))
        .bind(config.defer)
        .bind(config.enabled)
        .bind(config.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(interface = %config.sync_interface, "pfsync configured");
        Ok(config)
    }

    pub async fn get_pfsync(&self) -> Result<Option<PfsyncConfig>> {
        let row = sqlx::query_as::<_, PfsyncRow>(
            "SELECT * FROM pfsync_config LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.into_config()).transpose()
    }

    // ============================================================
    // Cluster nodes
    // ============================================================

    pub async fn add_node(&self, node: ClusterNode) -> Result<ClusterNode> {
        if node.name.is_empty() {
            return Err(AifwError::Validation("node name required".to_string()));
        }

        sqlx::query(
            r#"
            INSERT INTO cluster_nodes (id, name, address, role, health, last_seen, config_version, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(node.id.to_string())
        .bind(&node.name)
        .bind(node.address.to_string())
        .bind(node.role.to_string())
        .bind(node.health.to_string())
        .bind(node.last_seen.to_rfc3339())
        .bind(node.config_version as i64)
        .bind(node.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(name = %node.name, role = %node.role, "cluster node added");
        Ok(node)
    }

    pub async fn list_nodes(&self) -> Result<Vec<ClusterNode>> {
        let rows = sqlx::query_as::<_, ClusterNodeRow>(
            "SELECT * FROM cluster_nodes ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_node()).collect()
    }

    pub async fn update_node_health(&self, id: Uuid, health: NodeHealth) -> Result<()> {
        sqlx::query("UPDATE cluster_nodes SET health = ?1, last_seen = ?2 WHERE id = ?3")
            .bind(health.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_node(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM cluster_nodes WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("cluster node {id} not found")));
        }
        Ok(())
    }

    // ============================================================
    // Health checks
    // ============================================================

    pub async fn add_health_check(&self, check: HealthCheck) -> Result<HealthCheck> {
        sqlx::query(
            r#"
            INSERT INTO health_checks (id, name, check_type, interval_secs, timeout_secs,
                failures_before_down, target, enabled, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(check.id.to_string())
        .bind(&check.name)
        .bind(check.check_type.to_string())
        .bind(check.interval_secs as i64)
        .bind(check.timeout_secs as i64)
        .bind(check.failures_before_down as i64)
        .bind(&check.target)
        .bind(check.enabled)
        .bind(check.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(name = %check.name, check_type = %check.check_type, "health check added");
        Ok(check)
    }

    pub async fn list_health_checks(&self) -> Result<Vec<HealthCheck>> {
        let rows = sqlx::query_as::<_, HealthCheckRow>(
            "SELECT * FROM health_checks ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_check()).collect()
    }

    pub async fn delete_health_check(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM health_checks WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("health check {id} not found")));
        }
        Ok(())
    }

    // ============================================================
    // Apply HA pf rules
    // ============================================================

    pub async fn apply_ha_rules(&self) -> Result<()> {
        let mut pf_rules = Vec::new();

        // CARP rules
        let vips = self.list_carp_vips().await?;
        for vip in &vips {
            pf_rules.extend(vip.to_pf_rules());
        }

        // pfsync rules
        if let Some(pfsync) = self.get_pfsync().await? {
            pf_rules.extend(pfsync.to_pf_rules());
        }

        if !pf_rules.is_empty() {
            tracing::info!(count = pf_rules.len(), "applying HA pf rules");
            self.pf
                .load_rules(&self.anchor, &pf_rules)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        }

        Ok(())
    }
}

// ============================================================
// Row types
// ============================================================

#[derive(sqlx::FromRow)]
struct CarpVipRow {
    id: String,
    vhid: i64,
    virtual_ip: String,
    prefix: i64,
    interface: String,
    advskew: i64,
    advbase: i64,
    password: String,
    status: String,
    created_at: String,
    updated_at: String,
}

impl CarpVipRow {
    fn into_vip(self) -> Result<CarpVip> {
        Ok(CarpVip {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            vhid: self.vhid as u8,
            virtual_ip: self.virtual_ip.parse().map_err(|e| AifwError::Database(format!("{e}")))?,
            prefix: self.prefix as u8,
            interface: Interface(self.interface),
            advskew: self.advskew as u8,
            advbase: self.advbase as u8,
            password: self.password,
            status: match self.status.as_str() {
                "master" => CarpStatus::Master,
                "backup" => CarpStatus::Backup,
                "disabled" => CarpStatus::Disabled,
                _ => CarpStatus::Init,
            },
            created_at: parse_dt(&self.created_at)?,
            updated_at: parse_dt(&self.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PfsyncRow {
    id: String,
    sync_interface: String,
    sync_peer: Option<String>,
    defer_mode: bool,
    enabled: bool,
    created_at: String,
}

impl PfsyncRow {
    fn into_config(self) -> Result<PfsyncConfig> {
        Ok(PfsyncConfig {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            sync_interface: Interface(self.sync_interface),
            sync_peer: self.sync_peer.map(|s| s.parse()).transpose().map_err(|e| AifwError::Database(format!("{e}")))?,
            defer: self.defer_mode,
            enabled: self.enabled,
            created_at: parse_dt(&self.created_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ClusterNodeRow {
    id: String,
    name: String,
    address: String,
    role: String,
    health: String,
    last_seen: String,
    config_version: i64,
    created_at: String,
}

impl ClusterNodeRow {
    fn into_node(self) -> Result<ClusterNode> {
        Ok(ClusterNode {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            address: self.address.parse().map_err(|e| AifwError::Database(format!("{e}")))?,
            role: ClusterRole::parse(&self.role)?,
            health: match self.health.as_str() {
                "healthy" => NodeHealth::Healthy,
                "degraded" => NodeHealth::Degraded,
                "unreachable" => NodeHealth::Unreachable,
                _ => NodeHealth::Unknown,
            },
            last_seen: parse_dt(&self.last_seen)?,
            config_version: self.config_version as u64,
            created_at: parse_dt(&self.created_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct HealthCheckRow {
    id: String,
    name: String,
    check_type: String,
    interval_secs: i64,
    timeout_secs: i64,
    failures_before_down: i64,
    target: String,
    enabled: bool,
    created_at: String,
}

impl HealthCheckRow {
    fn into_check(self) -> Result<HealthCheck> {
        Ok(HealthCheck {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            check_type: HealthCheckType::parse(&self.check_type)?,
            interval_secs: self.interval_secs as u32,
            timeout_secs: self.timeout_secs as u32,
            failures_before_down: self.failures_before_down as u32,
            target: self.target,
            enabled: self.enabled,
            created_at: parse_dt(&self.created_at)?,
        })
    }
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| AifwError::Database(format!("invalid date: {e}")))
}
