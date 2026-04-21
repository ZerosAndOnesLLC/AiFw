use aifw_common::{AifwError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub rule_id: Option<Uuid>,
    pub details: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    RuleAdded,
    RuleRemoved,
    RuleUpdated,
    RulesApplied,
    RulesFlushed,
    DaemonStarted,
    DaemonStopped,
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

pub struct AuditLog {
    pool: SqlitePool,
}

impl AuditLog {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

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

    pub async fn log(
        &self,
        action: AuditAction,
        rule_id: Option<Uuid>,
        details: &str,
        source: &str,
    ) -> Result<AuditEntry> {
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
        .execute(&self.pool)
        .await?;

        Ok(entry)
    }

    pub async fn list(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    pub async fn list_for_rule(&self, rule_id: Uuid) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT * FROM audit_log WHERE rule_id = ?1 ORDER BY timestamp DESC",
        )
        .bind(rule_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    pub async fn list_by_action(&self, action: AuditAction, limit: i64) -> Result<Vec<AuditEntry>> {
        let rows = sqlx::query_as::<_, AuditRow>(
            "SELECT * FROM audit_log WHERE action = ?1 ORDER BY timestamp DESC LIMIT ?2",
        )
        .bind(action.to_string())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0)
    }
}

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
