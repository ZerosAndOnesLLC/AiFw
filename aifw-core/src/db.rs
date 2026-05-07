use aifw_common::{
    Action, AdaptiveTimeouts, Address, AifwError, Direction, Interface, PortRange, Protocol,
    Result, Rule, RuleMatch, RuleStatus, StateOptions, StatePolicy, StateTracking,
};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &Path) -> Result<Self> {
        use sqlx::sqlite::{SqliteJournalMode, SqliteSynchronous};

        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // WAL + synchronous=NORMAL lets many readers + one writer run
            // concurrently without blocking the dashboard / metrics loops.
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5));

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
        ] {
            let _ = sqlx::query(stmt).execute(&self.pool).await;
        }

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);")
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

    pub async fn insert_rule(&self, rule: &Rule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO rules (id, priority, action, direction, interface, protocol,
                src_addr, src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end,
                log, quick, label, state_tracking, state_policy, adaptive_start, adaptive_end,
                timeout_tcp, timeout_udp, timeout_icmp, status, created_at, updated_at, schedule_id,
                ip_version, src_invert, dst_invert)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                    ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.priority)
        .bind(format!("{:?}", rule.action).to_lowercase())
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
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<Option<Rule>> {
        let row = sqlx::query_as::<_, RuleRow>("SELECT * FROM rules WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.into_rule()).transpose()
    }

    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            "SELECT * FROM rules ORDER BY priority ASC, created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    pub async fn list_active_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, RuleRow>(
            "SELECT * FROM rules WHERE status = 'active' ORDER BY priority ASC, created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    pub async fn update_rule(&self, rule: &Rule) -> Result<()> {
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
                ip_version = ?26, src_invert = ?27, dst_invert = ?28
            WHERE id = ?1
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.priority)
        .bind(format!("{:?}", rule.action).to_lowercase())
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
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("rule {} not found", rule.id)));
        }
        Ok(())
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("rule {id} not found")));
        }
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
}

impl RuleRow {
    fn into_rule(self) -> Result<Rule> {
        let parse_action = |s: &str| -> Result<Action> {
            match s {
                "pass" => Ok(Action::Pass),
                "block" => Ok(Action::Block),
                "blockdrop" => Ok(Action::BlockDrop),
                "blockreturn" => Ok(Action::BlockReturn),
                _ => Err(AifwError::Database(format!("unknown action: {s}"))),
            }
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
            ip_version: aifw_common::IpVersion::parse(&self.ip_version)
                .unwrap_or_default(),
            src_invert: self.src_invert,
            dst_invert: self.dst_invert,
            log: self.log,
            quick: self.quick,
            label: self.label,
            description: None,
            gateway: None,
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
