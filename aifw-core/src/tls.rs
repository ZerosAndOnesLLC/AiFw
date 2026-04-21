use aifw_common::{
    AifwError, MitmProxyConfig, Result, SniAction, SniRule, SniRuleStatus, TlsPolicy, TlsVersion,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

pub struct TlsEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
    policy: TlsPolicy,
    mitm_config: MitmProxyConfig,
}

impl TlsEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw-tls".to_string(),
            policy: TlsPolicy::default(),
            mitm_config: MitmProxyConfig::default(),
        }
    }

    pub fn with_policy(mut self, policy: TlsPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_mitm_config(mut self, config: MitmProxyConfig) -> Self {
        self.mitm_config = config;
        self
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sni_rules (
                id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL,
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
            r#"
            CREATE TABLE IF NOT EXISTS ja3_blocklist (
                hash TEXT PRIMARY KEY,
                description TEXT,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // --- SNI rules ---

    pub async fn add_sni_rule(&self, rule: SniRule) -> Result<SniRule> {
        if rule.pattern.is_empty() {
            return Err(AifwError::Validation("SNI pattern required".to_string()));
        }

        sqlx::query(
            "INSERT INTO sni_rules (id, pattern, action, label, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(rule.id.to_string())
        .bind(&rule.pattern)
        .bind(rule.action.to_string())
        .bind(rule.label.as_deref())
        .bind(match rule.status { SniRuleStatus::Active => "active", SniRuleStatus::Disabled => "disabled" })
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %rule.id, pattern = %rule.pattern, action = %rule.action, "SNI rule added");
        Ok(rule)
    }

    pub async fn list_sni_rules(&self) -> Result<Vec<SniRule>> {
        let rows = sqlx::query_as::<_, SniRuleRow>("SELECT * FROM sni_rules ORDER BY pattern ASC")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    pub async fn delete_sni_rule(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM sni_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("SNI rule {id} not found")));
        }
        Ok(())
    }

    /// Check a hostname against all active SNI rules
    pub async fn check_sni(&self, hostname: &str) -> Option<SniAction> {
        let rules = self.list_sni_rules().await.ok()?;
        for rule in &rules {
            if rule.status == SniRuleStatus::Active && rule.matches(hostname) {
                return Some(rule.action);
            }
        }
        None
    }

    // --- JA3 blocklist ---

    pub async fn add_ja3_block(&self, hash: &str, description: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO ja3_blocklist (hash, description, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(hash)
        .bind(description)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        tracing::info!(hash, "JA3 hash blocked");
        Ok(())
    }

    pub async fn remove_ja3_block(&self, hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM ja3_blocklist WHERE hash = ?1")
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_ja3_blocks(&self) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query_as::<_, (String, String, String)>(
            "SELECT hash, description, created_at FROM ja3_blocklist ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn is_ja3_blocked(&self, hash: &str) -> bool {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM ja3_blocklist WHERE hash = ?1")
            .bind(hash)
            .fetch_one(&self.pool)
            .await
            .map(|r| r.0 > 0)
            .unwrap_or(false)
    }

    // --- Policy ---

    pub fn policy(&self) -> &TlsPolicy {
        &self.policy
    }

    pub fn mitm_config(&self) -> &MitmProxyConfig {
        &self.mitm_config
    }

    // --- Apply to pf ---

    pub async fn apply_rules(&self) -> Result<()> {
        let mut pf_lines = Vec::new();

        // TLS version enforcement — block deprecated versions
        // This works by blocking known deprecated cipher suites at the firewall level
        // Real enforcement happens in the TLS proxy / inspection layer
        if self.policy.min_version > TlsVersion::Ssl30 {
            pf_lines.push(format!(
                "# TLS policy: minimum version {} — enforce in proxy",
                self.policy.min_version
            ));
        }

        // MITM proxy RDR rules
        pf_lines.extend(self.mitm_config.to_pf_rdr_rules());

        if !pf_lines.is_empty() {
            tracing::info!(count = pf_lines.len(), "applying TLS pf rules");
            self.pf
                .load_rules(&self.anchor, &pf_lines)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        }

        Ok(())
    }
}

// --- Row types ---

#[derive(sqlx::FromRow)]
struct SniRuleRow {
    id: String,
    pattern: String,
    action: String,
    label: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

impl SniRuleRow {
    fn into_rule(self) -> Result<SniRule> {
        Ok(SniRule {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            pattern: self.pattern,
            action: SniAction::parse(&self.action)?,
            label: self.label,
            status: match self.status.as_str() {
                "active" => SniRuleStatus::Active,
                _ => SniRuleStatus::Disabled,
            },
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map_err(|e| AifwError::Database(format!("{e}")))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map_err(|e| AifwError::Database(format!("{e}")))?
                .with_timezone(&Utc),
        })
    }
}
