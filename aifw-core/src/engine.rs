use aifw_common::{AifwError, Result, Rule, RuleStatus};
use aifw_pf::PfBackend;
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{AuditAction, AuditLog};
use crate::db::Database;
use crate::validation::validate_rule;

const DEFAULT_ANCHOR: &str = "aifw";

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
    pub fn new(db: Database, pf: Arc<dyn PfBackend>) -> Self {
        let audit = AuditLog::new(db.pool().clone());
        Self {
            db,
            pf,
            audit,
            anchor: DEFAULT_ANCHOR.to_string(),
            extra_rules: tokio::sync::RwLock::new(Vec::new()),
        }
    }

    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    pub async fn add_rule(&self, rule: Rule) -> Result<Rule> {
        validate_rule(&rule)?;
        self.db.insert_rule(&rule).await?;
        let pf_syntax = rule.to_pf_rule(&self.anchor);
        self.audit
            .log(
                AuditAction::RuleAdded,
                Some(rule.id),
                &format!("pf: {pf_syntax}"),
                "engine",
            )
            .await?;
        tracing::info!(id = %rule.id, label = ?rule.label, "rule added");
        Ok(rule)
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<Rule> {
        self.db
            .get_rule(id)
            .await?
            .ok_or_else(|| AifwError::NotFound(format!("rule {id} not found")))
    }

    pub async fn list_rules(&self) -> Result<Vec<Rule>> {
        self.db.list_rules().await
    }

    pub async fn update_rule(&self, rule: Rule) -> Result<()> {
        validate_rule(&rule)?;
        self.db.update_rule(&rule).await?;
        self.audit
            .log(
                AuditAction::RuleUpdated,
                Some(rule.id),
                &format!("pf: {}", rule.to_pf_rule(&self.anchor)),
                "engine",
            )
            .await?;
        tracing::info!(id = %rule.id, "rule updated");
        Ok(())
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        self.db.delete_rule(id).await?;
        self.audit
            .log(AuditAction::RuleRemoved, Some(id), "rule deleted", "engine")
            .await?;
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
        let mut pf_rules: Vec<String> = rules
            .iter()
            .filter(|r| r.status == RuleStatus::Active)
            .map(|r| r.to_pf_rule(&self.anchor))
            .collect();

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

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn pf(&self) -> &dyn PfBackend {
        self.pf.as_ref()
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn anchor(&self) -> &str {
        &self.anchor
    }
}
