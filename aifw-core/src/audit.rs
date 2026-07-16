use aifw_common::{AifwError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

/// A single row in the audit trail recording who changed what and when
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique id of this audit entry
    pub id: Uuid,
    /// When the action happened (UTC)
    pub timestamp: DateTime<Utc>,
    /// What kind of change was recorded
    pub action: AuditAction,
    /// Firewall rule the action touched, if it was rule-scoped
    pub rule_id: Option<Uuid>,
    /// Free-form human-readable description of the change
    pub details: String,
    /// Origin of the change (e.g. API user, CLI, daemon)
    pub source: String,
}

/// Kind of event recorded in the audit log; serialized as snake_case wire/DB values
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A firewall rule was created
    RuleAdded,
    /// A firewall rule was deleted
    RuleRemoved,
    /// An existing firewall rule was modified
    RuleUpdated,
    /// The rule set was pushed into the pf anchor
    RulesApplied,
    /// All rules were flushed from the pf anchor
    RulesFlushed,
    /// The aifw daemon started
    DaemonStarted,
    /// The aifw daemon stopped
    DaemonStopped,
    /// A non-rule configuration change (also the fallback when parsing unknown action strings)
    ConfigChanged,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAction::RuleAdded => write!(f, "rule_added"),
            AuditAction::RuleRemoved => write!(f, "rule_removed"),
            AuditAction::RuleUpdated => write!(f, "rule_updated"),
            AuditAction::RulesApplied => write!(f, "rules_applied"),
            AuditAction::RulesFlushed => write!(f, "rules_flushed"),
            AuditAction::DaemonStarted => write!(f, "daemon_started"),
            AuditAction::DaemonStopped => write!(f, "daemon_stopped"),
            AuditAction::ConfigChanged => write!(f, "config_changed"),
        }
    }
}

impl AuditAction {
    fn parse(s: &str) -> Self {
        match s {
            "rule_added" => AuditAction::RuleAdded,
            "rule_removed" => AuditAction::RuleRemoved,
            "rule_updated" => AuditAction::RuleUpdated,
            "rules_applied" => AuditAction::RulesApplied,
            "rules_flushed" => AuditAction::RulesFlushed,
            "daemon_started" => AuditAction::DaemonStarted,
            "daemon_stopped" => AuditAction::DaemonStopped,
            "config_changed" => AuditAction::ConfigChanged,
            _ => AuditAction::ConfigChanged,
        }
    }
}

/// SQLite-backed audit trail; every rule/config/daemon event lands in the `audit_log` table
pub struct AuditLog {
    pool: SqlitePool,
}

impl AuditLog {
    /// Create an audit log handle over an existing SQLite pool (call `migrate` before use)
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the `audit_log` table and its timestamp/action indexes if they don't exist
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT,
                details TEXT NOT NULL,
                source TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Insert a new audit entry (timestamped now) into the log and return it
    pub async fn log(
        &self,
        action: AuditAction,
        rule_id: Option<Uuid>,
        details: &str,
        source: &str,
    ) -> Result<AuditEntry> {
        Self::log_on(&self.pool, action, rule_id, details, source).await
    }

    /// Insert an audit entry on an arbitrary executor. Lets engines pair the
    /// audit row with its mutation in a single transaction (PERF-H6 #350) so
    /// a rule change costs one commit instead of two, and the audit trail
    /// can never diverge from the mutated table.
    pub async fn log_on<'e, E>(
        exec: E,
        action: AuditAction,
        rule_id: Option<Uuid>,
        details: &str,
        source: &str,
    ) -> Result<AuditEntry>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action,
            rule_id,
            details: details.to_string(),
            source: source.to_string(),
        };

        sqlx::query(
            r#"
            INSERT INTO audit_log (id, timestamp, action, rule_id, details, source)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(entry.id.to_string())
        .bind(entry.timestamp.to_rfc3339())
        .bind(entry.action.to_string())
        .bind(entry.rule_id.map(|id| id.to_string()))
        .bind(&entry.details)
        .bind(&entry.source)
        .execute(exec)
        .await?;

        Ok(entry)
    }

    /// Fetch the most recent audit entries, newest first, capped at `limit` rows
    pub async fn list(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {AUDIT_LOG_COLUMNS} FROM audit_log ORDER BY timestamp DESC LIMIT ?1"
        )))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    /// Fetch all audit entries for one firewall rule, newest first
    pub async fn list_for_rule(&self, rule_id: Uuid) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {AUDIT_LOG_COLUMNS} FROM audit_log WHERE rule_id = ?1 ORDER BY timestamp DESC"
        )))
        .bind(rule_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    /// Fetch the most recent audit entries of one action kind, newest first, capped at `limit`
    pub async fn list_by_action(&self, action: AuditAction, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {AUDIT_LOG_COLUMNS} FROM audit_log WHERE action = ?1 ORDER BY timestamp DESC LIMIT ?2"
        )))
        .bind(action.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    /// Total number of entries in the audit log
    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }
}

/// Explicit column list for `AuditRow` selects (#348). Avoids `SELECT *`,
/// which triggers a sqlx-sqlite column-count panic and blocks column pruning.
const AUDIT_LOG_COLUMNS: &str = "id, timestamp, action, rule_id, details, source";

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    timestamp: String,
    action: String,
    rule_id: Option<String>,
    details: String,
    source: String,
}

impl AuditRow {
    fn into_entry(self) -> Result<AuditEntry> {
        Ok(AuditEntry {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            timestamp: DateTime::parse_from_rfc3339(&self.timestamp)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
            action: AuditAction::parse(&self.action),
            rule_id: self
                .rule_id
                .map(|s| {
                    Uuid::parse_str(&s)
                        .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))
                })
                .transpose()?,
            details: self.details,
            source: self.source,
        })
    }
}
