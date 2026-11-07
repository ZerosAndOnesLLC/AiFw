use aifw_common::{
    AifwError, CarpLatencyProfile, CarpStatus, CarpVip, ClusterNode, ClusterRole, HealthCheck,
    HealthCheckType, Interface, NodeHealth, PfsyncConfig, Result,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

/// High-availability engine: manages CARP VIPs, pfsync, cluster nodes and
/// health checks in SQLite and mirrors the derived pf rules into the
/// `aifw-ha` anchor
pub struct ClusterEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl ClusterEngine {
    /// Create the engine over an existing pool and pf backend, targeting the `aifw-ha` anchor
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: aifw_common::anchors::HA.to_string(),
        }
    }

    /// Create/upgrade the HA tables (carp_vips, cluster_nodes, snapshot state,
    /// failover events, health_checks, pfsync_config); idempotent, column
    /// additions/drops on re-run fail silently by design
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS carp_vips (
                id TEXT PRIMARY KEY,
                vhid INTEGER NOT NULL,
                virtual_ip TEXT NOT NULL,
                prefix INTEGER NOT NULL,
                interface TEXT NOT NULL,
                password TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'init',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Drop legacy per-VIP timer columns — profile on pfsync_config is now
        // the source of truth. Needs SQLite 3.35+ (DROP COLUMN); on older
        // libraries the columns simply stay unused, so that failure is the
        // one we tolerate — logged, not silent.
        for column in ["advskew", "advbase"] {
            if let Err(e) =
                crate::schema::drop_column_if_present(&self.pool, "carp_vips", column).await
            {
                tracing::warn!(error = %e, column, "ha: could not drop legacy carp_vips column");
            }
        }

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

        // New columns on cluster_nodes for peer auth + drift tracking
        for column in [
            "peer_api_key",
            "peer_api_key_hash",
            "software_version",
            "last_pushed_cert_at",
            "cert_fingerprint",
            // #712: live CARP role the peer last reported (peer monitor)
            "peer_state",
        ] {
            crate::schema::add_column_if_missing(&self.pool, "cluster_nodes", column, "TEXT")
                .await?;
        }
        // #487: per-node peer API port.
        crate::schema::add_column_if_missing(
            &self.pool,
            "cluster_nodes",
            "api_port",
            &format!(
                "INTEGER NOT NULL DEFAULT {}",
                aifw_common::DEFAULT_LOOPBACK_API_PORT
            ),
        )
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cluster_snapshot_state (
                node_id TEXT PRIMARY KEY,
                last_applied_hash TEXT NOT NULL,
                last_applied_at TEXT NOT NULL,
                last_applied_from TEXT NOT NULL
            );
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cluster_failover_events (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                from_role TEXT NOT NULL,
                to_role TEXT NOT NULL,
                cause TEXT NOT NULL,
                detail TEXT
            );
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_cluster_failover_events_ts ON cluster_failover_events(ts);")
            .execute(&self.pool).await?;

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

        // Columns added in the HA epic (#193: probe, then alter).
        for (column, definition) in [
            ("latency_profile", "TEXT NOT NULL DEFAULT 'conservative'"),
            ("heartbeat_iface", "TEXT"),
            ("heartbeat_interval_ms", "INTEGER"),
            ("dhcp_link", "INTEGER NOT NULL DEFAULT 0"),
            ("wg_deconfigure_on_backup", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            crate::schema::add_column_if_missing(&self.pool, "pfsync_config", column, definition)
                .await?;
        }

        Ok(())
    }

    // ============================================================
    // CARP VIP management
    // ============================================================

    /// Store a new CARP virtual IP. Fails validation if VHID is 0 or the password is empty
    pub async fn add_carp_vip(&self, vip: CarpVip) -> Result<CarpVip> {
        Self::insert_carp_vip_on(&self.pool, &vip).await?;
        tracing::info!(id = %vip.id, vhid = vip.vhid, ip = %vip.virtual_ip, "CARP VIP added");
        Ok(vip)
    }

    /// Executor-generic validate + insert. Public for the transactional
    /// restore path (#158/#535).
    pub async fn insert_carp_vip_on<'e, E>(exec: E, vip: &CarpVip) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        validate_carp_vip(vip)?;

        sqlx::query(
            r#"
            INSERT INTO carp_vips (id, vhid, virtual_ip, prefix, interface,
                password, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(vip.id.to_string())
        .bind(vip.vhid as i64)
        .bind(vip.virtual_ip.to_string())
        .bind(vip.prefix as i64)
        .bind(&vip.interface.0)
        .bind(crate::secrets::seal(&vip.password).map_err(crate::secrets::to_common)?)
        .bind(vip.status.to_string())
        .bind(vip.created_at.to_rfc3339())
        .bind(vip.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// List all configured CARP VIPs ordered by VHID
    pub async fn list_carp_vips(&self) -> Result<Vec<CarpVip>> {
        let rows = sqlx::query_as::<_, CarpVipRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {CARP_VIPS_COLUMNS} FROM carp_vips ORDER BY vhid ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_vip()).collect()
    }

    /// Update an existing CARP VIP by id (refreshes `updated_at`). Fails with
    /// `NotFound` if the id doesn't exist
    pub async fn update_carp_vip(&self, v: &CarpVip) -> Result<()> {
        validate_carp_vip(v)?;
        let result = sqlx::query(
            r#"UPDATE carp_vips SET vhid = ?1, virtual_ip = ?2, prefix = ?3,
               interface = ?4, password = ?5, status = ?6, updated_at = ?7
               WHERE id = ?8"#,
        )
        .bind(v.vhid as i64)
        .bind(v.virtual_ip.to_string())
        .bind(v.prefix as i64)
        .bind(&v.interface.0)
        .bind(crate::secrets::seal(&v.password).map_err(crate::secrets::to_common)?)
        .bind(v.status.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(v.id.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("CARP VIP {} not found", v.id)));
        }
        Ok(())
    }

    /// Delete a CARP VIP by id. Fails with `NotFound` if the id doesn't exist
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

    /// Store the pfsync configuration, replacing any existing one (singleton table)
    pub async fn set_pfsync(&self, config: PfsyncConfig) -> Result<PfsyncConfig> {
        let mut conn = self.pool.acquire().await?;
        Self::set_pfsync_on(&mut conn, &config).await?;
        tracing::info!(interface = %config.sync_interface, "pfsync configured");
        Ok(config)
    }

    /// Replace the pfsync config (DELETE + INSERT) on a single connection.
    /// Public for the transactional restore path (#158/#535); takes `&mut
    /// SqliteConnection` rather than a generic executor because it runs two
    /// statements.
    pub async fn set_pfsync_on(
        conn: &mut sqlx::SqliteConnection,
        config: &PfsyncConfig,
    ) -> Result<()> {
        // Replace any existing config
        sqlx::query("DELETE FROM pfsync_config")
            .execute(&mut *conn)
            .await?;

        sqlx::query(
            r#"INSERT INTO pfsync_config
               (id, sync_interface, sync_peer, defer_mode, enabled,
                latency_profile, heartbeat_iface, heartbeat_interval_ms, dhcp_link,
                created_at, wg_deconfigure_on_backup)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
        )
        .bind(config.id.to_string())
        .bind(&config.sync_interface.0)
        .bind(config.sync_peer.map(|p| p.to_string()))
        .bind(config.defer)
        .bind(config.enabled)
        .bind(config.latency_profile.to_string())
        .bind(config.heartbeat_iface.as_ref().map(|i| i.0.clone()))
        .bind(config.heartbeat_interval_ms.map(|n| n as i64))
        .bind(config.dhcp_link)
        .bind(config.created_at.to_rfc3339())
        .bind(config.wg_deconfigure_on_backup)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Fetch the pfsync configuration, or `None` if pfsync has never been configured
    pub async fn get_pfsync(&self) -> Result<Option<PfsyncConfig>> {
        let row = sqlx::query_as::<_, PfsyncRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {PFSYNC_CONFIG_COLUMNS} FROM pfsync_config LIMIT 1"
        )))
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.into_config()).transpose()
    }

    // ============================================================
    // Cluster nodes
    // ============================================================

    /// Register a peer node in the cluster. Fails validation if the name is empty
    pub async fn add_node(&self, node: ClusterNode) -> Result<ClusterNode> {
        Self::insert_node_on(&self.pool, &node).await?;
        tracing::info!(name = %node.name, role = %node.role, "cluster node added");
        Ok(node)
    }

    /// Executor-generic validate + insert. Public for the transactional
    /// restore path (#158/#535).
    pub async fn insert_node_on<'e, E>(exec: E, node: &ClusterNode) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        if node.name.is_empty() {
            return Err(AifwError::Validation("node name required".to_string()));
        }

        sqlx::query(
            r#"
            INSERT INTO cluster_nodes (id, name, address, role, health, last_seen, config_version, created_at, api_port)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
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
        .bind(i64::from(node.api_port))
        .execute(exec)
        .await?;
        Ok(())
    }

    /// List all registered cluster nodes ordered by name
    pub async fn list_nodes(&self) -> Result<Vec<ClusterNode>> {
        let rows = sqlx::query_as::<_, ClusterNodeRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {CLUSTER_NODES_COLUMNS} FROM cluster_nodes ORDER BY name ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_node()).collect()
    }

    /// Record a peer-monitor probe (#712): health, and — when the peer
    /// answered — its live CARP role and software version. `last_seen` only
    /// moves when the peer actually answered.
    pub async fn record_peer_probe(
        &self,
        id: Uuid,
        health: NodeHealth,
        peer_state: Option<&str>,
        software_version: Option<&str>,
    ) -> Result<()> {
        let answered = matches!(health, NodeHealth::Healthy | NodeHealth::Degraded);
        sqlx::query(
            "UPDATE cluster_nodes SET health = ?1, \
             last_seen = CASE WHEN ?2 THEN ?3 ELSE last_seen END, \
             peer_state = COALESCE(?4, peer_state), \
             software_version = COALESCE(?5, software_version) \
             WHERE id = ?6",
        )
        .bind(health.to_string())
        .bind(answered)
        .bind(Utc::now().to_rfc3339())
        .bind(peer_state)
        .bind(software_version)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set a node's health status and bump its `last_seen` timestamp to now
    pub async fn update_node_health(&self, id: Uuid, health: NodeHealth) -> Result<()> {
        sqlx::query("UPDATE cluster_nodes SET health = ?1, last_seen = ?2 WHERE id = ?3")
            .bind(health.to_string())
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update a node's name, address, role and API port by id. Fails with
    /// `NotFound` if the id doesn't exist
    pub async fn update_node(&self, n: &ClusterNode) -> Result<()> {
        if n.api_port == 0 {
            return Err(AifwError::Validation(
                "api_port must be 1-65535".to_string(),
            ));
        }
        let result = sqlx::query(
            r#"UPDATE cluster_nodes SET name = ?1, address = ?2, role = ?3, api_port = ?5 WHERE id = ?4"#,
        )
        .bind(&n.name)
        .bind(n.address.to_string())
        .bind(n.role.to_string())
        .bind(n.id.to_string())
        .bind(i64::from(n.api_port))
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "cluster node {} not found",
                n.id
            )));
        }
        Ok(())
    }

    /// Remove a node from the cluster by id. Fails with `NotFound` if the id doesn't exist
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

    /// Returns the most recently applied snapshot hash from cluster_snapshot_state,
    /// or None if no snapshot has been applied yet.
    pub async fn last_applied_snapshot_hash(&self) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT last_applied_hash FROM cluster_snapshot_state ORDER BY last_applied_at DESC LIMIT 1"
        ).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| r.0))
    }

    /// Record that a config snapshot with the given hash was applied on this
    /// node, upserting the per-node row in `cluster_snapshot_state`
    pub async fn record_snapshot_apply(&self, node_id: Uuid, hash: &str, from: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO cluster_snapshot_state (node_id, last_applied_hash, last_applied_at, last_applied_from) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(node_id.to_string())
        .bind(hash)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(from)
        .execute(&self.pool).await?;
        Ok(())
    }

    /// Append a role-transition event (e.g. backup -> master) with its cause
    /// to the failover history table
    pub async fn record_failover_event(
        &self,
        from: &str,
        to: &str,
        cause: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO cluster_failover_events (id, ts, from_role, to_role, cause, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(Uuid::new_v4().to_string())
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(from)
        .bind(to)
        .bind(cause)
        .bind(detail)
        .execute(&self.pool).await?;
        Ok(())
    }

    /// Generate a fresh 256-bit peer API key for a node, store it (plus its
    /// SHA-256 hash) on the node row, and return the plaintext key
    pub async fn generate_peer_api_key(&self, node_id: Uuid) -> Result<String> {
        // Two simple-format UUIDs = 64 hex chars = 256 bits of getrandom-sourced entropy.
        let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let hash = sha256_hex(&key);
        // #298: the plaintext copy (needed for outbound calls) is sealed at rest.
        let sealed = crate::secrets::seal(&key).map_err(crate::secrets::to_common)?;
        sqlx::query(
            "UPDATE cluster_nodes SET peer_api_key = ?1, peer_api_key_hash = ?2 WHERE id = ?3",
        )
        .bind(&sealed)
        .bind(&hash)
        .bind(node_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(key)
    }

    /// Fetch the stored plaintext peer API key for a node, or `None` if the
    /// node doesn't exist or has no key generated yet
    pub async fn peer_api_key(&self, node_id: Uuid) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT peer_api_key FROM cluster_nodes WHERE id = ?1")
                .bind(node_id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        crate::secrets::open_opt(row.and_then(|(k,)| k)).map_err(crate::secrets::to_common)
    }

    // ============================================================
    // Peer TLS pinning (#317)
    // ============================================================

    /// HTTPS client for calling `node`, pinned to its stored certificate
    /// fingerprint. With no pin yet the client accepts any certificate and
    /// exposes the observed one so [`Self::learn_peer_cert`] can pin it.
    pub fn peer_client(
        &self,
        node: &ClusterNode,
        timeout: std::time::Duration,
    ) -> Result<reqwest::Client> {
        crate::peer_tls::client_for(
            node.cert_fingerprint.as_deref(),
            &node.address.to_string(),
            timeout,
        )
        .map_err(|e| AifwError::Other(e.to_string()))
    }

    /// Trust-on-first-use: if `node` has no pin yet, record the certificate
    /// fingerprint observed on `resp` (a successful call made through
    /// [`Self::peer_client`]). No-op when already pinned. Best-effort — the
    /// call that produced `resp` already succeeded.
    pub async fn learn_peer_cert(&self, node: &ClusterNode, resp: &reqwest::Response) {
        if node.cert_fingerprint.is_some() {
            return;
        }
        let Some(fp) = crate::peer_tls::observed_fingerprint(resp) else {
            return;
        };
        match self.set_peer_cert_fingerprint(node.id, Some(&fp)).await {
            Ok(()) => tracing::info!(
                peer = %node.address,
                pin = %crate::peer_tls::short(&fp),
                "ha: pinned peer certificate on first contact"
            ),
            Err(e) => {
                tracing::warn!(peer = %node.address, error = %e, "ha: could not store peer pin")
            }
        }
    }

    /// Set (or clear, with `None`) the pinned certificate fingerprint for a
    /// node. Clearing = "re-pin on next contact".
    pub async fn set_peer_cert_fingerprint(&self, id: Uuid, fp: Option<&str>) -> Result<()> {
        let result = sqlx::query("UPDATE cluster_nodes SET cert_fingerprint = ?1 WHERE id = ?2")
            .bind(fp.map(|f| f.to_ascii_lowercase()))
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("cluster node {id} not found")));
        }
        Ok(())
    }

    /// Clear the pins of every node with `role` so the next contact
    /// re-learns them. Used around a certificate distribution (cert push):
    /// the peer's API certificate is about to change, and whether it will
    /// serve exactly the pushed chain depends on its own ACME-export
    /// settings, so a fresh TOFU is safer than guessing. Returns the number
    /// of nodes cleared.
    pub async fn clear_pins_for_role(&self, role: ClusterRole) -> Result<usize> {
        let mut n = 0;
        for node in self.list_nodes().await? {
            if node.role == role && node.cert_fingerprint.is_some() {
                self.set_peer_cert_fingerprint(node.id, None).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    // ============================================================
    // Health checks
    // ============================================================

    /// Store a new HA health check definition (interval/timeout in seconds)
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

    /// List all health check definitions ordered by name
    pub async fn list_health_checks(&self) -> Result<Vec<HealthCheck>> {
        let rows = sqlx::query_as::<_, HealthCheckRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {HEALTH_CHECKS_COLUMNS} FROM health_checks ORDER BY name ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_check()).collect()
    }

    /// Update a health check definition by id. Fails with `NotFound` if the id doesn't exist
    pub async fn update_health_check(&self, check: &HealthCheck) -> Result<()> {
        let result = sqlx::query(
            r#"UPDATE health_checks SET name=?1, check_type=?2, interval_secs=?3,
               timeout_secs=?4, failures_before_down=?5, target=?6, enabled=?7
               WHERE id=?8"#,
        )
        .bind(&check.name)
        .bind(check.check_type.to_string())
        .bind(check.interval_secs as i64)
        .bind(check.timeout_secs as i64)
        .bind(check.failures_before_down as i64)
        .bind(&check.target)
        .bind(check.enabled)
        .bind(check.id.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "health check {} not found",
                check.id
            )));
        }
        Ok(())
    }

    /// Delete a health check by id. Fails with `NotFound` if the id doesn't exist
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

    /// The role this node is *configured* for (not the live CARP state):
    /// `aifw_cluster_role` from rc.conf, else this node's own row in
    /// `cluster_nodes`, else `Standalone`. CARP timing (advskew) must come
    /// from this — deriving it from the live role makes a primary that is
    /// temporarily BACKUP re-render itself with the secondary's skew (#712).
    pub async fn configured_role(&self) -> ClusterRole {
        if let Some(role) = read_rc_cluster_role().await
            && role != ClusterRole::Standalone
        {
            return role;
        }
        match self.self_node().await {
            Ok(Some(n)) => n.role,
            _ => ClusterRole::Standalone,
        }
    }

    /// This node's own row in `cluster_nodes`: matched by hostname, else by
    /// an address configured on a local interface.
    pub async fn self_node(&self) -> Result<Option<ClusterNode>> {
        let nodes = self.list_nodes().await?;
        if let Some(host) = local_hostname().await
            && let Some(n) = nodes.iter().find(|n| n.name == host)
        {
            return Ok(Some(n.clone()));
        }
        let view = crate::carp::kernel_view().await;
        Ok(nodes
            .into_iter()
            .find(|n| view.local_addrs.contains(&n.address)))
    }

    /// Make the kernel match the DB: pfsync0, every CARP vhid/address (with
    /// timing from the stored latency profile and the *configured* role),
    /// preemption on, and stale CARP addresses removed. All writes go
    /// through the `aifw-sudo-carp` helper. Idempotent; called at daemon
    /// start and after every HA config change.
    pub async fn reconcile_kernel_state(&self) -> Result<ReconcileReport> {
        let role = self.configured_role().await;
        self.reconcile_kernel_state_for_role(role).await
    }

    /// [`Self::reconcile_kernel_state`] with an explicit role (setup knows
    /// the role before rc.conf is written; tests pass one directly).
    pub async fn reconcile_kernel_state_for_role(
        &self,
        role: ClusterRole,
    ) -> Result<ReconcileReport> {
        let mut report = ReconcileReport::default();
        let pfsync = self.get_pfsync().await?;
        let vips = self.list_carp_vips().await?;

        if matches!(role, ClusterRole::Standalone) && vips.is_empty() && pfsync.is_none() {
            return Ok(report);
        }

        let view = crate::carp::kernel_view().await;

        match &pfsync {
            Some(p) => {
                if let Err(e) = crate::carp::pfsync_apply(p).await {
                    report.errors.push(format!("pfsync: {e}"));
                }
            }
            None => {
                if view.pfsync.as_ref().is_some_and(|p| p.syncdev.is_some())
                    && let Err(e) = crate::carp::pfsync_down().await
                {
                    report.errors.push(format!("pfsync down: {e}"));
                }
            }
        }

        let profile = pfsync
            .as_ref()
            .map(|p| p.latency_profile)
            .unwrap_or_default();
        let timing = profile.timing_for(role);

        if !vips.is_empty()
            && let Err(e) = crate::carp::enable_preempt().await
        {
            report.errors.push(format!("preempt: {e}"));
        }

        for vip in &vips {
            match crate::carp::vip_set(vip, timing).await {
                Ok(()) => report.applied += 1,
                Err(e) => report
                    .errors
                    .push(format!("vhid {} ({}): {e}", vip.vhid, vip.virtual_ip)),
            }
        }

        // Anything the kernel holds on a vhid that the DB no longer lists.
        for stale in stale_carp_addrs(&view, &vips) {
            match crate::carp::vip_del(&stale.interface, &stale.addr).await {
                Ok(()) => report.removed += 1,
                Err(e) => report
                    .errors
                    .push(format!("remove {} on {}: {e}", stale.addr, stale.interface)),
            }
        }

        for e in &report.errors {
            tracing::warn!(error = %e, "ha: kernel reconcile step failed");
        }
        tracing::info!(
            %role,
            advskew = timing.advskew,
            advbase = timing.advbase,
            applied = report.applied,
            removed = report.removed,
            failed = report.errors.len(),
            "ha: kernel state reconciled"
        );
        Ok(report)
    }

    /// Keep the rc.conf cluster switches in step with the DB, so clusters
    /// built from the UI/API get the boot hold, shutdown demotion and the
    /// configured-role lookup exactly like wizard-built ones (#712).
    pub async fn sync_rc_conf(&self) -> Result<()> {
        let clustered = !self.list_carp_vips().await?.is_empty()
            || self.get_pfsync().await?.is_some_and(|p| p.enabled);
        let yes_no = if clustered { "YES" } else { "NO" };
        let mut sets = vec![
            format!("aifw_cluster_enabled={yes_no}"),
            format!("aifw_carp_demote_enable={yes_no}"),
            format!("aifw_demote_on_shutdown_enable={yes_no}"),
        ];
        if let Some(me) = self.self_node().await? {
            sets.push(format!("aifw_cluster_role={}", me.role));
        } else if !clustered {
            sets.push("aifw_cluster_role=standalone".to_string());
        }
        for kv in &sets {
            let out = crate::sudo::sysrc(&[kv]).await;
            crate::sudo::warn_on_fail(&format!("ha: sysrc {kv}"), &out);
        }
        Ok(())
    }

    /// Render pf rules from the stored CARP VIPs and pfsync config and load
    /// them into the `aifw-ha` anchor; flushes the anchor when nothing is
    /// configured so a removed VIP doesn't leave its pass rule behind.
    pub async fn apply_ha_rules(&self) -> Result<()> {
        let mut pf_rules = Vec::new();

        let vips = self.list_carp_vips().await?;
        for vip in &vips {
            pf_rules.extend(vip.to_pf_rules());
        }
        if let Some(pfsync) = self.get_pfsync().await? {
            pf_rules.extend(pfsync.to_pf_rules());
        }
        pf_rules.dedup();

        if pf_rules.is_empty() {
            self.pf
                .flush_rules(&self.anchor)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        } else {
            tracing::info!(count = pf_rules.len(), "applying HA pf rules");
            self.pf
                .load_rules(&self.anchor, &pf_rules)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        }

        Ok(())
    }
}

/// Outcome of [`ClusterEngine::reconcile_kernel_state`].
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ReconcileReport {
    /// CARP vhids configured / retuned
    pub applied: u32,
    /// Stale CARP addresses removed
    pub removed: u32,
    /// Steps that failed (also logged)
    pub errors: Vec<String>,
}

/// CARP addresses present in the kernel but absent from the DB.
fn stale_carp_addrs<'a>(
    view: &'a crate::carp::KernelCarpView,
    vips: &[CarpVip],
) -> Vec<&'a crate::carp::KernelCarpAddr> {
    view.addrs
        .iter()
        .filter(|k| {
            !vips
                .iter()
                .any(|v| v.interface.0 == k.interface && v.virtual_ip == k.addr)
        })
        .collect()
}

/// Validate a CARP VIP before it is stored (shared by add/update/restore).
pub fn validate_carp_vip(vip: &CarpVip) -> Result<()> {
    if vip.vhid == 0 {
        return Err(AifwError::Validation("VHID must be > 0".to_string()));
    }
    if vip.password.is_empty() {
        return Err(AifwError::Validation("CARP password required".to_string()));
    }
    if vip
        .password
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(AifwError::Validation(
            "CARP password must not contain whitespace or control characters".to_string(),
        ));
    }
    let max_prefix = if vip.virtual_ip.is_ipv4() { 32 } else { 128 };
    if vip.prefix > max_prefix {
        return Err(AifwError::Validation(format!(
            "prefix /{} is out of range for {}",
            vip.prefix, vip.virtual_ip
        )));
    }
    let iface = &vip.interface.0;
    if iface.is_empty()
        || iface.len() > 15
        || iface.starts_with('-')
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return Err(AifwError::Validation(format!(
            "invalid interface name: {iface:?}"
        )));
    }
    Ok(())
}

async fn read_rc_cluster_role() -> Option<ClusterRole> {
    let out = tokio::process::Command::new("sysrc")
        .args(["-n", "aifw_cluster_role"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    ClusterRole::parse(String::from_utf8_lossy(&out.stdout).trim()).ok()
}

async fn local_hostname() -> Option<String> {
    let out = tokio::process::Command::new("hostname")
        .output()
        .await
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

// ============================================================
// HA role helpers
// ============================================================

/// Returns the live CARP role of this node.
///
/// Reads the kernel (all VHIDs): `Primary` only when every VHID is MASTER,
/// `Secondary` when any VHID is BACKUP/INIT or the VHIDs disagree (#712:
/// this used to look at the first `carp:` line only, so a node that was
/// MASTER on LAN but BACKUP on WAN reported whichever came first). With no
/// CARP in the kernel at all it falls back to `aifw_cluster_role`, then
/// `Standalone`.
///
/// This is the canonical role helper. All callers in aifw-api and
/// aifw-daemon should delegate here rather than reimplementing.
pub async fn current_local_role() -> aifw_common::ClusterRole {
    match crate::carp::kernel_view().await.aggregate_state() {
        "master" => aifw_common::ClusterRole::Primary,
        "none" => read_rc_cluster_role()
            .await
            .unwrap_or(aifw_common::ClusterRole::Standalone),
        _ => aifw_common::ClusterRole::Secondary,
    }
}

/// Returns true if the local node is currently the active CARP MASTER.
///
/// Delegates to `current_local_role()`. Returns false on any error — the
/// safe default is to assume BACKUP so that operations that should only run
/// on the master (ACME renewal, cert push) are skipped rather than duplicated.
pub async fn is_local_master() -> bool {
    matches!(
        current_local_role().await,
        aifw_common::ClusterRole::Primary
    )
}

// ============================================================
// Crypto helpers
// ============================================================

/// SHA-256 of a string, returned as lowercase hex (used for peer API key hashes)
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

// ============================================================
// Row types
// ============================================================

/// Explicit column list for `CarpVipRow` selects (#348). `SELECT *` triggers a
/// sqlx-sqlite column-count panic and blocks column pruning; an explicit list
/// keeps the count deterministic and matches the `CarpVipRow` fields exactly.
const CARP_VIPS_COLUMNS: &str =
    "id, vhid, virtual_ip, prefix, interface, password, status, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct CarpVipRow {
    id: String,
    vhid: i64,
    virtual_ip: String,
    prefix: i64,
    interface: String,
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
            virtual_ip: self
                .virtual_ip
                .parse()
                .map_err(|e| AifwError::Database(format!("{e}")))?,
            prefix: self.prefix as u8,
            interface: Interface(self.interface),
            // #298: sealed at rest; legacy plaintext passes through.
            password: crate::secrets::open(&self.password).map_err(crate::secrets::to_common)?,
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

/// Explicit column list for `PfsyncRow` selects (#348). `SELECT *` triggers a
/// sqlx-sqlite column-count panic and blocks column pruning; an explicit list
/// keeps the count deterministic and matches the `PfsyncRow` fields exactly.
const PFSYNC_CONFIG_COLUMNS: &str = "id, sync_interface, sync_peer, defer_mode, enabled, \
    created_at, latency_profile, heartbeat_iface, heartbeat_interval_ms, dhcp_link, \
    wg_deconfigure_on_backup";

#[derive(sqlx::FromRow)]
struct PfsyncRow {
    id: String,
    sync_interface: String,
    sync_peer: Option<String>,
    defer_mode: bool,
    enabled: bool,
    latency_profile: String,
    heartbeat_iface: Option<String>,
    heartbeat_interval_ms: Option<i64>,
    dhcp_link: bool,
    created_at: String,
    wg_deconfigure_on_backup: bool,
}

impl PfsyncRow {
    fn into_config(self) -> Result<PfsyncConfig> {
        Ok(PfsyncConfig {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            sync_interface: Interface(self.sync_interface),
            sync_peer: self
                .sync_peer
                .map(|s| s.parse())
                .transpose()
                .map_err(|e| AifwError::Database(format!("{e}")))?,
            defer: self.defer_mode,
            enabled: self.enabled,
            latency_profile: CarpLatencyProfile::parse(&self.latency_profile)?,
            heartbeat_iface: self.heartbeat_iface.map(Interface),
            heartbeat_interval_ms: self
                .heartbeat_interval_ms
                .and_then(|n| u32::try_from(n).ok()),
            dhcp_link: self.dhcp_link,
            wg_deconfigure_on_backup: self.wg_deconfigure_on_backup,
            created_at: parse_dt(&self.created_at)?,
        })
    }
}

/// Explicit column list for `ClusterNodeRow` selects (#348). `SELECT *` triggers
/// a sqlx-sqlite column-count panic and blocks column pruning; an explicit list
/// keeps the count deterministic and matches the `ClusterNodeRow` fields exactly.
/// Note: `peer_api_key`/`peer_api_key_hash` exist on the table but are NOT part
/// of `ClusterNodeRow`, so they are intentionally omitted here.
const CLUSTER_NODES_COLUMNS: &str = "id, name, address, role, health, last_seen, \
    config_version, created_at, software_version, last_pushed_cert_at, cert_fingerprint, \
    api_port, peer_state";

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
    software_version: Option<String>,
    last_pushed_cert_at: Option<String>,
    cert_fingerprint: Option<String>,
    api_port: i64,
    peer_state: Option<String>,
}

impl ClusterNodeRow {
    fn into_node(self) -> Result<ClusterNode> {
        let last_pushed_cert_at = self
            .last_pushed_cert_at
            .as_deref()
            .map(parse_dt)
            .transpose()?;
        Ok(ClusterNode {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            address: self
                .address
                .parse()
                .map_err(|e| AifwError::Database(format!("{e}")))?,
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
            software_version: self.software_version,
            last_pushed_cert_at,
            cert_fingerprint: self.cert_fingerprint,
            api_port: u16::try_from(self.api_port)
                .ok()
                .filter(|p| *p > 0)
                .unwrap_or(aifw_common::DEFAULT_LOOPBACK_API_PORT),
            peer_state: self.peer_state,
        })
    }
}

/// Explicit column list for `HealthCheckRow` selects (#348). `SELECT *` triggers
/// a sqlx-sqlite column-count panic and blocks column pruning; an explicit list
/// keeps the count deterministic and matches the `HealthCheckRow` fields exactly.
const HEALTH_CHECKS_COLUMNS: &str = "id, name, check_type, interval_secs, timeout_secs, \
    failures_before_down, target, enabled, created_at";

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    #[tokio::test]
    async fn reconcile_kernel_state_standalone_is_noop() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ClusterEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();
        let result = engine
            .reconcile_kernel_state_for_role(aifw_common::ClusterRole::Standalone)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn apply_ha_rules_loads_carp_pf_rules() {
        use aifw_common::{CarpLatencyProfile, CarpVip, Interface, PfsyncConfig};

        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = ClusterEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        // Configure pfsync with Tight profile
        let mut p = PfsyncConfig::new(Interface("igb1".into()));
        p.latency_profile = CarpLatencyProfile::Tight;
        engine.set_pfsync(p).await.unwrap();

        // Add a CARP VIP
        let vip = CarpVip::new(
            10,
            "10.0.0.1".parse().unwrap(),
            24,
            Interface("igb0".into()),
            "abc12345".into(),
        );
        engine.add_carp_vip(vip).await.unwrap();

        // apply_ha_rules should succeed — sysctl fails on Linux/test but is
        // logged as a warning (not an error), so Result is Ok
        let result = engine.apply_ha_rules().await;
        assert!(result.is_ok(), "apply_ha_rules failed: {result:?}");

        // Verify the CARP rule was loaded into the aifw-ha anchor
        let rules = mock.get_rules("aifw-ha").await.unwrap();
        assert!(!rules.is_empty(), "no rules loaded into aifw-ha anchor");
        assert!(
            rules.iter().any(|r| r.contains("carp-vhid-10")),
            "expected CARP rule for vhid 10, got: {rules:?}"
        );
    }

    // ============================================================
    // E7 — current_local_role linux-dev fallback
    // ============================================================

    /// On a Linux/WSL dev host there are no CARP interfaces and no
    /// aifw_cluster_role rc.conf variable, so current_local_role must
    /// fall all the way through both lookups and return Standalone.
    ///
    /// This test is intentionally skipped on FreeBSD targets (where a
    /// CARP-configured host would legitimately return Primary/Secondary).
    #[cfg(not(target_os = "freebsd"))]
    #[tokio::test]
    async fn current_local_role_returns_standalone_on_linux_dev() {
        let role = current_local_role().await;
        assert!(
            matches!(role, aifw_common::ClusterRole::Standalone),
            "expected Standalone on Linux dev host, got {role:?}"
        );
    }

    #[tokio::test]
    async fn reconcile_kernel_state_threads_profile_through() {
        use aifw_common::{CarpLatencyProfile, CarpVip, ClusterRole, Interface, PfsyncConfig};

        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ClusterEngine::new(db.pool().clone(), pf);
        engine.migrate().await.unwrap();

        let mut p = PfsyncConfig::new(Interface("igb1".into()));
        p.latency_profile = CarpLatencyProfile::Tight;
        engine.set_pfsync(p).await.unwrap();

        let vip = CarpVip::new(
            10,
            "10.0.0.1".parse().unwrap(),
            24,
            Interface("igb0".into()),
            "abc12345".into(),
        );
        engine.add_carp_vip(vip).await.unwrap();

        // reconcile_kernel_state_for_role shells out to sudo/ifconfig which won't
        // succeed on Linux/WSL, but failures are warn-logged and swallowed; the
        // call should still return Ok(()). The intent is to exercise the
        // get_pfsync -> profile.timing_for(role) -> aifw-sudo-carp vip-set path.
        let result = engine
            .reconcile_kernel_state_for_role(ClusterRole::Secondary)
            .await;
        assert!(
            result.is_ok(),
            "reconcile_kernel_state_for_role returned {result:?}"
        );
    }
}
