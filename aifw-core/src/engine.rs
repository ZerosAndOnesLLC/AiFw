use aifw_common::{AifwError, Result, Rule, RuleStatus};
use aifw_pf::PfBackend;
use sqlx::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{AuditAction, AuditLog};
use crate::db::Database;
use crate::validation::validate_rule;

const DEFAULT_ANCHOR: &str = "aifw";

/// Filter-rule engine: persists [`Rule`]s in the SQLite `rules` table and
/// renders active ones into pf syntax loaded into the `aifw` anchor
/// (override via [`Self::with_anchor`]). Every mutation commits its audit
/// row in the same transaction.
pub struct RuleEngine {
    db: Database,
    pf: Arc<dyn PfBackend>,
    audit: AuditLog,
    anchor: String,
    /// Extra rules injected by other engines (e.g. VPN pass rules) that must
    /// appear in the aifw anchor before the default block rule.
    extra_rules: tokio::sync::RwLock<Vec<String>>,
}

impl RuleEngine {
    /// Build a rule engine over the shared pool and pf backend, targeting
    /// the default `aifw` anchor
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        let audit = AuditLog::new(pool.clone());
        let db = Database::from_pool(pool);
        Self {
            db,
            pf,
            audit,
            anchor: DEFAULT_ANCHOR.to_string(),
            extra_rules: tokio::sync::RwLock::new(Vec::new()),
        }
    }

    /// Replace the target pf anchor (builder style)
    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    /// Validate and insert a rule; the rule row and its audit entry commit
    /// in one transaction. pf is untouched until [`Self::apply_rules`].
    /// Fails on validation or DB errors.
    pub async fn add_rule(&self, rule: Rule) -> Result<Rule> {
        validate_rule(&rule)?;
        let pf_syntax = rule.to_pf_rule(&self.anchor);
        // PERF-H6 (#350): mutation + audit row commit together — one fsync
        // instead of two per rule change.
        let mut tx = self.db.pool().begin().await?;
        Database::insert_rule_on(&mut *tx, &rule).await?;
        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleAdded,
            Some(rule.id),
            &format!("pf: {pf_syntax}"),
            "engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(id = %rule.id, label = ?rule.label, "rule added");
        Ok(rule)
    }

    /// Fetch a rule by id. Fails with `NotFound` if it doesn't exist
    pub async fn get_rule(&self, id: Uuid) -> Result<Rule> {
        self.db
            .get_rule(id)
            .await?
            .ok_or_else(|| AifwError::NotFound(format!("rule {id} not found")))
    }

    /// All rules ordered by priority, then creation time
    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        self.db.list_rules().await
    }

    /// Validate and update a rule; the update and its audit entry commit in
    /// one transaction. Fails with `NotFound` for an unknown id. pf is
    /// untouched until [`Self::apply_rules`].
    pub async fn update_rule(&self, rule: Rule) -> Result<()> {
        validate_rule(&rule)?;
        let mut tx = self.db.pool().begin().await?;
        Database::update_rule_on(&mut *tx, &rule).await?;
        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleUpdated,
            Some(rule.id),
            &format!("pf: {}", rule.to_pf_rule(&self.anchor)),
            "engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(id = %rule.id, "rule updated");
        Ok(())
    }

    /// Delete a rule; the delete and its audit entry commit in one
    /// transaction. Fails with `NotFound` for an unknown id
    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        let mut tx = self.db.pool().begin().await?;
        Database::delete_rule_on(&mut *tx, id).await?;
        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleRemoved,
            Some(id),
            "rule deleted",
            "engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(%id, "rule deleted");
        Ok(())
    }

    /// Set extra rules (e.g. VPN WAN pass rules) to be injected into the anchor
    /// before the default block rule on the next `apply_rules` call.
    pub async fn set_extra_rules(&self, rules: Vec<String>) {
        *self.extra_rules.write().await = rules;
    }

    /// Generate pf rules from active rules and load them into the pf anchor.
    /// Extra rules (from VPN, etc.) are inserted just before any block rule
    /// so they aren't shadowed by a `block quick` default.
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.db.list_active_rules().await?;
        let mut pf_rules = Vec::new();
        for rule in rules.iter().filter(|r| r.status == RuleStatus::Active) {
            if let Some(schedule_id) = &rule.schedule_id
                && !schedule_active(self.db.pool(), schedule_id, chrono::Local::now()).await?
            {
                continue;
            }
            pf_rules.push(rule.to_pf_rule(&self.anchor));
        }

        // Inject extra rules (VPN pass rules, etc.) before the first block rule
        let extras = self.extra_rules.read().await;
        if !extras.is_empty() {
            if let Some(pos) = pf_rules.iter().position(|r| r.starts_with("block ")) {
                for (i, extra) in extras.iter().enumerate() {
                    pf_rules.insert(pos + i, extra.clone());
                }
            } else {
                pf_rules.extend(extras.iter().cloned());
            }
        }

        tracing::info!(
            anchor = %self.anchor,
            count = pf_rules.len(),
            "applying rules to pf"
        );

        self.pf
            .load_rules(&self.anchor, &pf_rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        self.audit
            .log(
                AuditAction::RulesApplied,
                None,
                &format!("{} rules applied to anchor {}", pf_rules.len(), self.anchor),
                "engine",
            )
            .await?;

        Ok(())
    }

    /// Flush all rules from the pf anchor
    pub async fn flush_rules(&self) -> Result<()> {
        self.pf
            .flush_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        self.audit
            .log(
                AuditAction::RulesFlushed,
                None,
                &format!("flushed anchor {}", self.anchor),
                "engine",
            )
            .await?;
        tracing::info!(anchor = %self.anchor, "flushed pf rules");
        Ok(())
    }

    /// The engine's audit log handle
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// The underlying pf backend
    pub fn pf(&self) -> &dyn PfBackend {
        self.pf.as_ref()
    }

    /// The underlying database handle
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// The pf anchor this engine loads rules into
    pub fn anchor(&self) -> &str {
        &self.anchor
    }
}

async fn schedule_active(
    pool: &sqlx::SqlitePool,
    id: &str,
    now: chrono::DateTime<chrono::Local>,
) -> Result<bool> {
    use chrono::{Datelike, Timelike};
    let row: Option<(String, String, bool)> =
        sqlx::query_as("SELECT time_ranges, days_of_week, enabled FROM schedules WHERE id = ?1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let Some((ranges, days, true)) = row else {
        return Ok(false);
    };
    let day = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
        [now.weekday().num_days_from_monday() as usize];
    if !days.split(',').any(|d| d.trim() == day) {
        return Ok(false);
    }
    let minute = now.hour() * 60 + now.minute();
    Ok(ranges.split(',').any(|range| {
        let Some((start, end)) = range.trim().split_once('-') else {
            return false;
        };
        let parse = |s: &str| {
            s.split_once(':')
                .and_then(|(h, m)| Some(h.parse::<u32>().ok()? * 60 + m.parse::<u32>().ok()?))
        };
        match (parse(start), parse(end)) {
            (Some(a), Some(b)) if a <= b => minute >= a && minute < b,
            (Some(a), Some(b)) => minute >= a || minute < b,
            _ => false,
        }
    }))
}
