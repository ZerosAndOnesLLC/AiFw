use aifw_common::{AifwError, Result, Rule, RuleStatus};
use aifw_pf::PfBackend;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
use crate::validation::validate_rule;

const DEFAULT_ANCHOR: &str = "aifw";

pub struct RuleEngine {
    db: Database,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl RuleEngine {
    pub fn new(db: Database, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            db,
            pf,
            anchor: DEFAULT_ANCHOR.to_string(),
        }
    }

    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    pub async fn add_rule(&self, rule: Rule) -> Result<Rule> {
        validate_rule(&rule)?;
        self.db.insert_rule(&rule).await?;
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
        tracing::info!(id = %rule.id, "rule updated");
        Ok(())
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        self.db.delete_rule(id).await?;
        tracing::info!(%id, "rule deleted");
        Ok(())
    }

    /// Generate pf rules from active rules and load them into the pf anchor
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.db.list_active_rules().await?;
        let pf_rules: Vec<String> = rules
            .iter()
            .filter(|r| r.status == RuleStatus::Active)
            .map(|r| r.to_pf_rule(&self.anchor))
            .collect();

        tracing::info!(
            anchor = %self.anchor,
            count = pf_rules.len(),
            "applying rules to pf"
        );

        self.pf
            .load_rules(&self.anchor, &pf_rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }

    /// Flush all rules from the pf anchor
    pub async fn flush_rules(&self) -> Result<()> {
        self.pf
            .flush_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        tracing::info!(anchor = %self.anchor, "flushed pf rules");
        Ok(())
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
