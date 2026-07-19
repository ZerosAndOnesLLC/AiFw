use aifw_common::{
    Action, AdaptiveTimeouts, Address, AifwError, Direction, Interface, PortRange, Protocol,
    Result, Rule, RuleMatch, RuleStatus, StateOptions, StatePolicy, StateTracking,
};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

/// SQLite handle for the firewall database. Wraps the shared [`SqlitePool`]
/// and owns the filter-rule (`rules` table) persistence helpers; other
/// engines create their own tables against the same pool via their
/// `migrate()` methods.
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (creating if missing) the SQLite database at `path` with WAL
    /// journaling and tuned pragmas (64 MB cache, 256 MiB mmap), restrict
    /// the file to mode 0600, and run migrations. Production path is
    /// `/var/db/aifw/aifw.db`.
    pub async fn new(path: &Path) -> Result<Self> {
        use sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};

        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL + synchronous=NORMAL lets many readers + one writer run
            // concurrently without blocking the dashboard / metrics loops.
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5))
            // PERF-H1: default cache is 2 MB and mmap is off, so aggregate
            // queries over multi-GB tables (e.g. ids_alerts on /ids/stats)
            // fault in from disk. Run per-connection on connect.
            .pragma("cache_size", "-65536") // ~64 MB page cache (negative = KiB)
            .pragma("mmap_size", "268435456") // 256 MiB memory-mapped reads
            .pragma("temp_store", "MEMORY"); // sorts/temp b-trees stay in RAM

        let pool = SqlitePoolOptions::new()
            .max_connections(20)
            .min_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(opts)
            .await?;

        // Restrict DB file permissions to owner-only (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Wrap an existing [`SqlitePool`] without opening a new connection or
    /// running migrations. Used by engines (e.g. [`crate::RuleEngine`]) that
    /// take a shared pool for constructor consistency but still need the
    /// typed `Database` query helpers.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Open a fresh in-memory SQLite database (single connection) and run
    /// migrations. Used by tests.
    pub async fn new_in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        // QUAL-C6: run versioned migrations first. New schema changes go
        // through aifw-core/migrations/NNNN_*.sql; the in-place
        // `CREATE TABLE IF NOT EXISTS` below stays for engines that
        // haven't been folded into the versioned framework yet.
        crate::migrations::run(&self.pool)
            .await
            .map_err(|e| AifwError::Database(format!("sqlx migrate: {e}")))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                priority INTEGER NOT NULL DEFAULT 100,
                action TEXT NOT NULL,
                direction TEXT NOT NULL,
                interface TEXT,
                protocol TEXT NOT NULL,
                src_addr TEXT NOT NULL,
                src_port_start INTEGER,
                src_port_end INTEGER,
                dst_addr TEXT NOT NULL,
                dst_port_start INTEGER,
                dst_port_end INTEGER,
                log INTEGER NOT NULL DEFAULT 0,
                quick INTEGER NOT NULL DEFAULT 1,
                label TEXT,
                state_tracking TEXT NOT NULL DEFAULT 'keep_state',
                state_policy TEXT,
                adaptive_start INTEGER,
                adaptive_end INTEGER,
                timeout_tcp INTEGER,
                timeout_udp INTEGER,
                timeout_icmp INTEGER,
                status TEXT NOT NULL DEFAULT 'active',
                schedule_id TEXT,
                gateway TEXT,
                ip_version TEXT NOT NULL DEFAULT 'both',
                src_invert INTEGER NOT NULL DEFAULT 0,
                dst_invert INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Idempotent ALTERs for pre-existing tables. SQLite has no IF NOT
        // EXISTS for ADD COLUMN; ignore the duplicate-column error.
        for stmt in [
            "ALTER TABLE rules ADD COLUMN ip_version TEXT NOT NULL DEFAULT 'both'",
            "ALTER TABLE rules ADD COLUMN src_invert INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE rules ADD COLUMN dst_invert INTEGER NOT NULL DEFAULT 0",
            // Policy-routing gateway reference (#540)
            "ALTER TABLE rules ADD COLUMN gateway TEXT",
        ] {
            let _ = sqlx::query(stmt).execute(&self.pool).await;
        }

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);")
            .execute(&self.pool)
            .await?;

        // Schedules referenced by rules.schedule_id. Same DDL as the
        // aifw-api auth migration — duplicated here so the daemon and core
        // tests can evaluate schedules on a DB the API never migrated (#537).
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                time_ranges TEXT NOT NULL,
                days_of_week TEXT NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Audit log table
        let audit_log = crate::audit::AuditLog::new(self.pool.clone());
        audit_log.migrate().await?;

        // NAT rules table
        let nat_engine = crate::nat::NatEngine::new(
            self.pool.clone(),
            std::sync::Arc::from(aifw_pf::create_backend()),
        );
        nat_engine.migrate().await?;

        Ok(())
    }

    /// Insert a filter rule into the `rules` table
    pub async fn insert_rule(&self, rule: &Rule) -> Result<()> {
        Self::insert_rule_on(&self.pool, rule).await
    }

    /// Executor-generic variant so engines can run the insert inside a
    /// transaction alongside its audit row (PERF-H6 #350).
    pub(crate) async fn insert_rule_on<'e, E>(exec: E, rule: &Rule) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query(
            r#"
            INSERT INTO rules (id, priority, action, direction, interface, protocol,
                src_addr, src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end,
                log, quick, label, state_tracking, state_policy, adaptive_start, adaptive_end,
                timeout_tcp, timeout_udp, timeout_icmp, status, created_at, updated_at, schedule_id,
                ip_version, src_invert, dst_invert, gateway)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                    ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.priority)
        .bind(rule.action.as_db_str())
        .bind(format!("{:?}", rule.direction).to_lowercase())
        .bind(rule.interface.as_ref().map(|i| i.0.clone()))
        .bind(rule.protocol.to_string())
        .bind(rule.rule_match.src_addr.to_string())
        .bind(rule.rule_match.src_port.as_ref().map(|p| p.start as i64))
        .bind(rule.rule_match.src_port.as_ref().map(|p| p.end as i64))
        .bind(rule.rule_match.dst_addr.to_string())
        .bind(rule.rule_match.dst_port.as_ref().map(|p| p.start as i64))
        .bind(rule.rule_match.dst_port.as_ref().map(|p| p.end as i64))
        .bind(rule.log)
        .bind(rule.quick)
        .bind(rule.label.as_deref())
        .bind(state_tracking_to_str(&rule.state_options.tracking))
        .bind(rule.state_options.policy.as_ref().map(|p| match p {
            StatePolicy::IfBound => "if_bound",
            StatePolicy::Floating => "floating",
        }))
        .bind(
            rule.state_options
                .adaptive_timeouts
                .as_ref()
                .map(|a| a.start as i64),
        )
        .bind(
            rule.state_options
                .adaptive_timeouts
                .as_ref()
                .map(|a| a.end as i64),
        )
        .bind(rule.state_options.timeout_tcp.map(|t| t as i64))
        .bind(rule.state_options.timeout_udp.map(|t| t as i64))
        .bind(rule.state_options.timeout_icmp.map(|t| t as i64))
        .bind(match rule.status {
            RuleStatus::Active => "active",
            RuleStatus::Disabled => "disabled",
        })
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .bind(rule.schedule_id.as_deref())
        .bind(format!("{:?}", rule.ip_version).to_lowercase())
        .bind(rule.src_invert)
        .bind(rule.dst_invert)
        .bind(rule.gateway.as_deref())
        .execute(exec)
        .await?;

        Ok(())
    }

    /// Fetch a filter rule by id; `Ok(None)` when it doesn't exist
    pub async fn get_rule(&self, id: Uuid) -> Result<Option<Rule>> {
        let row = sqlx::query_as::<_, RuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {RULE_COLUMNS} FROM rules WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_rule()).transpose()
    }

    /// All filter rules ordered by priority, then creation time
    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, RuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {RULE_COLUMNS} FROM rules ORDER BY priority ASC, created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    /// Filter rules with status `active`, ordered by priority then creation time
    pub async fn list_active_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, RuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {RULE_COLUMNS} FROM rules \
             WHERE status = 'active' ORDER BY priority ASC, created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    /// Load all schedules parsed into evaluation specs, keyed by id (#537).
    /// Unparseable rows are skipped with a warning — rules referencing them
    /// then fail open exactly like a dangling reference.
    pub async fn list_schedule_specs(
        &self,
    ) -> Result<std::collections::HashMap<String, aifw_common::schedule::ScheduleSpec>> {
        let rows = sqlx::query_as::<_, (String, String, String, bool)>(
            "SELECT id, time_ranges, days_of_week, enabled FROM schedules",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut map = std::collections::HashMap::with_capacity(rows.len());
        for (id, ranges, days, enabled) in rows {
            match aifw_common::schedule::ScheduleSpec::parse(&ranges, &days, enabled) {
                Some(spec) => {
                    map.insert(id, spec);
                }
                None => tracing::warn!(
                    schedule_id = %id,
                    "unparseable schedule row; referencing rules stay active"
                ),
            }
        }
        Ok(map)
    }

    /// Resolve multiwan gateways to (interface, next_hop, state) keyed by id,
    /// for rule policy routing (#540). Returns an empty map when the multiwan
    /// tables don't exist yet (fresh DB before the gateway engine migrated) —
    /// rules referencing a gateway then fall back to default routing.
    pub async fn list_gateway_routes(
        &self,
    ) -> std::collections::HashMap<String, (String, String, String)> {
        let rows = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT id, interface, next_hop, state FROM multiwan_gateways",
        )
        .fetch_all(&self.pool)
        .await;
        match rows {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, iface, hop, state)| (id, (iface, hop, state)))
                .collect(),
            Err(e) => {
                tracing::debug!(error = %e, "gateway route lookup unavailable; rules fall back to default routing");
                std::collections::HashMap::new()
            }
        }
    }

    /// Whether any rule references a policy-routing gateway (#540); used by
    /// the daemon to skip rule reloads on gateway transitions nobody routes
    /// through.
    pub async fn has_gateway_rules(&self) -> Result<bool> {
        let n = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM rules WHERE gateway IS NOT NULL AND gateway != '')",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(n == 1)
    }

    /// Update a filter rule in place (refreshing `updated_at`). Fails with
    /// `NotFound` if the id doesn't exist
    pub async fn update_rule(&self, rule: &Rule) -> Result<()> {
        Self::update_rule_on(&self.pool, rule).await
    }

    /// Executor-generic variant so engines can run the update inside a
    /// transaction alongside its audit row (PERF-H6 #350).
    pub(crate) async fn update_rule_on<'e, E>(exec: E, rule: &Rule) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let result = sqlx::query(
            r#"
            UPDATE rules SET priority = ?2, action = ?3, direction = ?4, interface = ?5,
                protocol = ?6, src_addr = ?7, src_port_start = ?8, src_port_end = ?9,
                dst_addr = ?10, dst_port_start = ?11, dst_port_end = ?12,
                log = ?13, quick = ?14, label = ?15,
                state_tracking = ?16, state_policy = ?17,
                adaptive_start = ?18, adaptive_end = ?19,
                timeout_tcp = ?20, timeout_udp = ?21, timeout_icmp = ?22,
                status = ?23, updated_at = ?24, schedule_id = ?25,
                ip_version = ?26, src_invert = ?27, dst_invert = ?28, gateway = ?29
            WHERE id = ?1
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.priority)
        .bind(rule.action.as_db_str())
        .bind(format!("{:?}", rule.direction).to_lowercase())
        .bind(rule.interface.as_ref().map(|i| i.0.clone()))
        .bind(rule.protocol.to_string())
        .bind(rule.rule_match.src_addr.to_string())
        .bind(rule.rule_match.src_port.as_ref().map(|p| p.start as i64))
        .bind(rule.rule_match.src_port.as_ref().map(|p| p.end as i64))
        .bind(rule.rule_match.dst_addr.to_string())
        .bind(rule.rule_match.dst_port.as_ref().map(|p| p.start as i64))
        .bind(rule.rule_match.dst_port.as_ref().map(|p| p.end as i64))
        .bind(rule.log)
        .bind(rule.quick)
        .bind(rule.label.as_deref())
        .bind(state_tracking_to_str(&rule.state_options.tracking))
        .bind(rule.state_options.policy.as_ref().map(|p| match p {
            StatePolicy::IfBound => "if_bound",
            StatePolicy::Floating => "floating",
        }))
        .bind(
            rule.state_options
                .adaptive_timeouts
                .as_ref()
                .map(|a| a.start as i64),
        )
        .bind(
            rule.state_options
                .adaptive_timeouts
                .as_ref()
                .map(|a| a.end as i64),
        )
        .bind(rule.state_options.timeout_tcp.map(|t| t as i64))
        .bind(rule.state_options.timeout_udp.map(|t| t as i64))
        .bind(rule.state_options.timeout_icmp.map(|t| t as i64))
        .bind(match rule.status {
            RuleStatus::Active => "active",
            RuleStatus::Disabled => "disabled",
        })
        .bind(Utc::now().to_rfc3339())
        .bind(rule.schedule_id.as_deref())
        .bind(format!("{:?}", rule.ip_version).to_lowercase())
        .bind(rule.src_invert)
        .bind(rule.dst_invert)
        .bind(rule.gateway.as_deref())
        .execute(exec)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("rule {} not found", rule.id)));
        }
        Ok(())
    }

    /// Delete a filter rule by id. Fails with `NotFound` if it doesn't exist
    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        Self::delete_rule_on(&self.pool, id).await
    }

    /// Executor-generic variant so engines can run the delete inside a
    /// transaction alongside its audit row (PERF-H6 #350).
    pub(crate) async fn delete_rule_on<'e, E>(exec: E, id: Uuid) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let result = sqlx::query("DELETE FROM rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(exec)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("rule {id} not found")));
        }
        Ok(())
    }

    /// The underlying shared [`SqlitePool`]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
mod pragma_tests {
    use super::*;

    // PERF-H1 regression: the file-based pool must ship the tuned pragmas so
    // aggregate scans over large tables don't fall back to disk. In-memory
    // DBs don't exercise this path, so use a real temp file.
    #[tokio::test]
    async fn file_pool_applies_perf_pragmas() {
        let path = std::env::temp_dir().join(format!("aifw-pragma-{}.db", Uuid::new_v4()));
        let db = Database::new(&path).await.unwrap();

        let cache_size: i64 = sqlx::query_scalar("PRAGMA cache_size")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(cache_size, -65536, "cache_size pragma not applied");

        let temp_store: i64 = sqlx::query_scalar("PRAGMA temp_store")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(temp_store, 2, "temp_store should be MEMORY (2)");

        let mmap_size: i64 = sqlx::query_scalar("PRAGMA mmap_size")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(mmap_size, 268435456, "mmap_size pragma not applied");

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}

fn state_tracking_to_str(t: &StateTracking) -> &'static str {
    match t {
        StateTracking::None => "none",
        StateTracking::KeepState => "keep_state",
        StateTracking::ModulateState => "modulate_state",
        StateTracking::SynproxyState => "synproxy_state",
    }
}

fn parse_state_tracking(s: &str) -> StateTracking {
    match s {
        "none" => StateTracking::None,
        "modulate_state" => StateTracking::ModulateState,
        "synproxy_state" => StateTracking::SynproxyState,
        _ => StateTracking::KeepState,
    }
}

fn parse_state_policy(s: &str) -> StatePolicy {
    match s {
        "floating" => StatePolicy::Floating,
        _ => StatePolicy::IfBound,
    }
}

/// Explicit column list for `RuleRow` selects. The `rules` table has had
/// multiple ALTER TABLE migrations adding columns; using `SELECT *` here
/// has triggered a sqlx-sqlite panic (#273) when the prepared statement's
/// column count and the cached column metadata disagreed during shutdown.
/// Explicit columns keep the count deterministic regardless of migration
/// order.
const RULE_COLUMNS: &str = "id, priority, action, direction, interface, protocol, \
    src_addr, src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end, \
    log, quick, label, state_tracking, state_policy, adaptive_start, adaptive_end, \
    timeout_tcp, timeout_udp, timeout_icmp, status, created_at, updated_at, \
    schedule_id, ip_version, src_invert, dst_invert, gateway";

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: String,
    priority: i32,
    action: String,
    direction: String,
    interface: Option<String>,
    protocol: String,
    src_addr: String,
    src_port_start: Option<i64>,
    src_port_end: Option<i64>,
    dst_addr: String,
    dst_port_start: Option<i64>,
    dst_port_end: Option<i64>,
    log: bool,
    quick: bool,
    label: Option<String>,
    state_tracking: String,
    state_policy: Option<String>,
    adaptive_start: Option<i64>,
    adaptive_end: Option<i64>,
    timeout_tcp: Option<i64>,
    timeout_udp: Option<i64>,
    timeout_icmp: Option<i64>,
    status: String,
    created_at: String,
    updated_at: String,
    schedule_id: Option<String>,
    ip_version: String,
    src_invert: bool,
    dst_invert: bool,
    gateway: Option<String>,
}

impl RuleRow {
    fn into_rule(self) -> Result<Rule> {
        let parse_action = |s: &str| -> Result<Action> {
            Action::parse_db(s).ok_or_else(|| AifwError::Database(format!("unknown action: {s}")))
        };

        let parse_direction = |s: &str| -> Result<Direction> {
            match s {
                "in" => Ok(Direction::In),
                "out" => Ok(Direction::Out),
                "any" => Ok(Direction::Any),
                _ => Err(AifwError::Database(format!("unknown direction: {s}"))),
            }
        };

        let parse_port_range = |start: Option<i64>, end: Option<i64>| -> Option<PortRange> {
            match (start, end) {
                (Some(s), Some(e)) => Some(PortRange {
                    start: s as u16,
                    end: e as u16,
                }),
                _ => None,
            }
        };

        Ok(Rule {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            priority: self.priority,
            action: parse_action(&self.action)?,
            direction: parse_direction(&self.direction)?,
            interface: self.interface.map(Interface),
            protocol: Protocol::parse(&self.protocol)?,
            rule_match: RuleMatch {
                src_addr: Address::parse(&self.src_addr)?,
                src_port: parse_port_range(self.src_port_start, self.src_port_end),
                dst_addr: Address::parse(&self.dst_addr)?,
                dst_port: parse_port_range(self.dst_port_start, self.dst_port_end),
            },
            ip_version: aifw_common::IpVersion::parse(&self.ip_version).unwrap_or_default(),
            src_invert: self.src_invert,
            dst_invert: self.dst_invert,
            log: self.log,
            quick: self.quick,
            label: self.label,
            description: None,
            gateway: self.gateway,
            state_options: StateOptions {
                tracking: parse_state_tracking(&self.state_tracking),
                policy: self.state_policy.as_deref().map(parse_state_policy),
                adaptive_timeouts: match (self.adaptive_start, self.adaptive_end) {
                    (Some(s), Some(e)) => Some(AdaptiveTimeouts {
                        start: s as u32,
                        end: e as u32,
                    }),
                    _ => None,
                },
                timeout_tcp: self.timeout_tcp.map(|t| t as u32),
                timeout_udp: self.timeout_udp.map(|t| t as u32),
                timeout_icmp: self.timeout_icmp.map(|t| t as u32),
            },
            status: match self.status.as_str() {
                "active" => RuleStatus::Active,
                _ => RuleStatus::Disabled,
            },
            schedule_id: self.schedule_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
        })
    }
}
