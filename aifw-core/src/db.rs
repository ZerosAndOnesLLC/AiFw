use aifw_common::{
    Action, Address, AifwError, Direction, Interface, PortRange, Protocol, Result, Rule, RuleMatch,
    RuleStatus,
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
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

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
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority);",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status);",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn insert_rule(&self, rule: &Rule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO rules (id, priority, action, direction, interface, protocol,
                src_addr, src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end,
                log, quick, label, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
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
        .bind(match rule.status {
            RuleStatus::Active => "active",
            RuleStatus::Disabled => "disabled",
        })
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<Option<Rule>> {
        let row = sqlx::query_as::<_, RuleRow>(
            "SELECT * FROM rules WHERE id = ?1",
        )
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
                log = ?13, quick = ?14, label = ?15, status = ?16, updated_at = ?17
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
        .bind(match rule.status {
            RuleStatus::Active => "active",
            RuleStatus::Disabled => "disabled",
        })
        .bind(Utc::now().to_rfc3339())
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
    status: String,
    created_at: String,
    updated_at: String,
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
            log: self.log,
            quick: self.quick,
            label: self.label,
            status: match self.status.as_str() {
                "active" => RuleStatus::Active,
                _ => RuleStatus::Disabled,
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
