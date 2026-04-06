use aifw_common::ids::{IdsRule, IdsRuleset, IdsSeverity, RuleFormat, RuleSource};
use chrono::Utc;
use sqlx::SqlitePool;
use tokio::process::Command;
use uuid::Uuid;

use super::RuleDatabase;
use crate::Result;

/// Manages ruleset downloads, storage, and compilation.
pub struct RulesetManager {
    pool: SqlitePool,
}

impl RulesetManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// List all configured rulesets.
    pub async fn list_rulesets(&self) -> Result<Vec<IdsRuleset>> {
        let rows: Vec<(String, String, Option<String>, String, bool, bool, i64, Option<String>, i64, String)> =
            sqlx::query_as(
                "SELECT id, name, source_url, rule_format, enabled, auto_update, update_interval_hours, last_updated, rule_count, created_at FROM ids_rulesets ORDER BY name"
            )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|(id, name, url, fmt, enabled, auto_update, interval, last, count, created)| {
                IdsRuleset {
                    id: Uuid::parse_str(&id).unwrap_or_default(),
                    name,
                    source_url: url,
                    rule_format: RuleFormat::from_str(&fmt).unwrap_or(RuleFormat::Suricata),
                    enabled,
                    auto_update,
                    update_interval_hours: interval as u32,
                    last_updated: last.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                    rule_count: count as u32,
                    created_at: chrono::DateTime::parse_from_rfc3339(&created).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
                }
            })
            .collect())
    }

    /// Add a new ruleset.
    pub async fn add_ruleset(&self, ruleset: &IdsRuleset) -> Result<()> {
        sqlx::query(
            "INSERT INTO ids_rulesets (id, name, source_url, rule_format, enabled, auto_update, update_interval_hours, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(ruleset.id.to_string())
        .bind(&ruleset.name)
        .bind(&ruleset.source_url)
        .bind(ruleset.rule_format.to_string())
        .bind(ruleset.enabled)
        .bind(ruleset.auto_update)
        .bind(ruleset.update_interval_hours as i64)
        .bind(ruleset.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update a ruleset's configuration.
    pub async fn update_ruleset(&self, ruleset: &IdsRuleset) -> Result<()> {
        sqlx::query(
            "UPDATE ids_rulesets SET name = ?, source_url = ?, enabled = ?, auto_update = ?, update_interval_hours = ? WHERE id = ?"
        )
        .bind(&ruleset.name)
        .bind(&ruleset.source_url)
        .bind(ruleset.enabled)
        .bind(ruleset.auto_update)
        .bind(ruleset.update_interval_hours as i64)
        .bind(ruleset.id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete a ruleset and its rules.
    pub async fn delete_ruleset(&self, id: Uuid) -> Result<()> {
        let id_str = id.to_string();
        sqlx::query("DELETE FROM ids_rules WHERE ruleset_id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM ids_rulesets WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store parsed rules for a ruleset.
    pub async fn store_rules(&self, ruleset_id: Uuid, rules: &[IdsRule]) -> Result<()> {
        let rs_id = ruleset_id.to_string();

        // Delete existing rules for this ruleset
        sqlx::query("DELETE FROM ids_rules WHERE ruleset_id = ?")
            .bind(&rs_id)
            .execute(&self.pool)
            .await?;

        // Batch insert
        for rule in rules {
            sqlx::query(
                "INSERT INTO ids_rules (id, ruleset_id, sid, rule_text, msg, severity, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))"
            )
            .bind(rule.id.to_string())
            .bind(&rs_id)
            .bind(rule.sid.map(|s| s as i64))
            .bind(&rule.rule_text)
            .bind(&rule.msg)
            .bind(rule.severity.0 as i64)
            .bind(rule.enabled)
            .execute(&self.pool)
            .await?;
        }

        // Update ruleset rule count and last_updated
        sqlx::query(
            "UPDATE ids_rulesets SET rule_count = ?, last_updated = ? WHERE id = ?",
        )
        .bind(rules.len() as i64)
        .bind(Utc::now().to_rfc3339())
        .bind(&rs_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Download rules from a ruleset's source_url, parse, and store them.
    /// Returns the number of rules stored.
    pub async fn download_and_store_rules(&self, ruleset: &IdsRuleset) -> Result<usize> {
        let url = ruleset.source_url.as_deref().ok_or_else(|| {
            crate::IdsError::Config("Ruleset has no source URL".into())
        })?;

        tracing::info!(url, ruleset = %ruleset.name, "downloading ruleset");

        // Download to temp file using fetch (FreeBSD) or curl
        let tmp = format!("/tmp/aifw-ids-{}.rules", ruleset.id);
        let downloaded = if let Ok(o) = Command::new("fetch")
            .args(["-qo", &tmp, url])
            .output().await
        {
            o.status.success()
        } else {
            false
        };

        if !downloaded {
            let output = Command::new("curl")
                .args(["-sL", "-o", &tmp, url])
                .output().await
                .map_err(|e| crate::IdsError::Config(format!("download failed: {e}")))?;
            if !output.status.success() {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(crate::IdsError::Config(format!(
                    "download failed: {}", String::from_utf8_lossy(&output.stderr)
                )));
            }
        }

        // Read and parse
        let content = tokio::fs::read_to_string(&tmp).await
            .map_err(|e| crate::IdsError::Io(e))?;
        let _ = tokio::fs::remove_file(&tmp).await;

        // Parse each line as a Suricata rule
        let mut rules = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Extract SID and msg from the rule text
            let sid = extract_sid(trimmed);
            let msg = extract_msg(trimmed);
            let severity = if trimmed.contains("priority:1") { IdsSeverity::CRITICAL }
                else if trimmed.contains("priority:2") { IdsSeverity::HIGH }
                else if trimmed.contains("priority:3") { IdsSeverity::MEDIUM }
                else { IdsSeverity::INFO };

            rules.push(IdsRule {
                id: Uuid::new_v4(),
                ruleset_id: ruleset.id,
                sid,
                rule_text: trimmed.to_string(),
                msg,
                severity,
                enabled: true,
                action_override: None,
                hit_count: 0,
                last_hit: None,
                created_at: Utc::now(),
            });
        }

        let count = rules.len();
        tracing::info!(count, ruleset = %ruleset.name, "parsed rules from download");

        if count > 0 {
            self.store_rules(ruleset.id, &rules).await?;
        }

        Ok(count)
    }

    /// List rules for a specific ruleset.
    pub async fn list_rules(
        &self,
        ruleset_id: Option<Uuid>,
        enabled_only: bool,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<IdsRule>> {
        let mut sql = String::from(
            "SELECT id, ruleset_id, sid, rule_text, msg, severity, enabled, action_override, hit_count, last_hit, created_at FROM ids_rules WHERE 1=1"
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(rs_id) = ruleset_id {
            sql.push_str(" AND ruleset_id = ?");
            binds.push(rs_id.to_string());
        }
        if enabled_only {
            sql.push_str(" AND enabled = 1 AND ruleset_id IN (SELECT id FROM ids_rulesets WHERE enabled = 1)");
        }
        sql.push_str(" ORDER BY sid ASC, created_at ASC");
        sql.push_str(&format!(" LIMIT {limit} OFFSET {offset}"));

        let mut query = sqlx::query_as::<_, (String, String, Option<i64>, String, Option<String>, i64, bool, Option<String>, i64, Option<String>, String)>(&sql);

        for bind in &binds {
            query = query.bind(bind);
        }

        let rows = query.fetch_all(&self.pool).await?;

        Ok(rows
            .into_iter()
            .map(|(id, rs_id, sid, text, msg, sev, enabled, action_override, hits, last_hit, created)| {
                IdsRule {
                    id: Uuid::parse_str(&id).unwrap_or_default(),
                    ruleset_id: Uuid::parse_str(&rs_id).unwrap_or_default(),
                    sid: sid.map(|s| s as u32),
                    rule_text: text,
                    msg,
                    severity: IdsSeverity(sev as u8),
                    enabled,
                    action_override: action_override.and_then(|s| aifw_common::ids::IdsAction::from_str(&s)),
                    hit_count: hits as u64,
                    last_hit: last_hit.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                    created_at: chrono::DateTime::parse_from_rfc3339(&created).ok().map(|d| d.with_timezone(&Utc)).unwrap_or_else(Utc::now),
                }
            })
            .collect())
    }

    /// Toggle a rule's enabled status.
    pub async fn toggle_rule(&self, rule_id: Uuid, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE ids_rules SET enabled = ? WHERE id = ?")
            .bind(enabled)
            .bind(rule_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Override a rule's action.
    pub async fn override_rule_action(
        &self,
        rule_id: Uuid,
        action: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE ids_rules SET action_override = ? WHERE id = ?")
            .bind(action)
            .bind(rule_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record a hit for a rule.
    pub async fn record_hit(&self, sid: u32) -> Result<()> {
        sqlx::query(
            "UPDATE ids_rules SET hit_count = hit_count + 1, last_hit = datetime('now') WHERE sid = ?"
        )
        .bind(sid as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load all enabled rules from the database and compile them into the RuleDatabase.
    pub async fn compile_rules(&self, rule_db: &RuleDatabase) -> Result<usize> {
        let rules = self.list_rules(None, true, 100_000, 0).await?;
        let mut compiled = Vec::new();

        for rule in &rules {
            let source = self.guess_source(&rule.ruleset_id).await;
            match self.detect_format(&rule.rule_text) {
                RuleFormat::Suricata => {
                    if let Ok(cr) = super::suricata::parse_rule(&rule.rule_text, source) {
                        compiled.push(cr);
                    }
                }
                RuleFormat::Sigma => {
                    if let Ok(cr) = super::sigma::parse_sigma_rule(&rule.rule_text, source) {
                        compiled.push(cr);
                    }
                }
                RuleFormat::Yara => {
                    let yara_rules = super::yara::parse_yara_rules(&rule.rule_text, source);
                    compiled.extend(yara_rules);
                }
            }
        }

        let count = compiled.len();
        rule_db.load_rules(compiled);
        tracing::info!(count, "rules compiled and loaded");
        Ok(count)
    }

    fn detect_format(&self, text: &str) -> RuleFormat {
        let trimmed = text.trim();
        if trimmed.starts_with("alert ")
            || trimmed.starts_with("drop ")
            || trimmed.starts_with("reject ")
            || trimmed.starts_with("pass ")
        {
            RuleFormat::Suricata
        } else if trimmed.starts_with("title:") || trimmed.starts_with("id:") || trimmed.contains("detection:") {
            RuleFormat::Sigma
        } else if trimmed.starts_with("rule ") || trimmed.starts_with("private rule ") {
            RuleFormat::Yara
        } else {
            RuleFormat::Suricata // default assumption
        }
    }

    async fn guess_source(&self, ruleset_id: &Uuid) -> RuleSource {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT rule_format FROM ids_rulesets WHERE id = ?"
        )
        .bind(ruleset_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();

        match row {
            Some((fmt,)) => match fmt.as_str() {
                "sigma" => RuleSource::Sigma,
                "yara" => RuleSource::Yara,
                _ => RuleSource::EtOpen,
            },
            None => RuleSource::Custom,
        }
    }
}

fn extract_sid(rule: &str) -> Option<u32> {
    rule.find("sid:")
        .and_then(|pos| {
            let rest = &rule[pos + 4..];
            rest.split(';').next()?.trim().parse().ok()
        })
}

fn extract_msg(rule: &str) -> Option<String> {
    rule.find("msg:\"")
        .and_then(|pos| {
            let rest = &rule[pos + 5..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_ruleset_crud() {
        let pool = test_pool().await;
        let mgr = RulesetManager::new(pool);

        let rs = IdsRuleset {
            id: Uuid::new_v4(),
            name: "ET Open".into(),
            source_url: Some("https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules".into()),
            rule_format: RuleFormat::Suricata,
            enabled: true,
            auto_update: true,
            update_interval_hours: 24,
            last_updated: None,
            rule_count: 0,
            created_at: Utc::now(),
        };

        let before = mgr.list_rulesets().await.unwrap().len();
        mgr.add_ruleset(&rs).await.unwrap();
        let list = mgr.list_rulesets().await.unwrap();
        assert_eq!(list.len(), before + 1);
        assert!(list.iter().any(|r| r.name == "ET Open"));

        mgr.delete_ruleset(rs.id).await.unwrap();
        let list = mgr.list_rulesets().await.unwrap();
        assert_eq!(list.len(), before);
    }

    #[tokio::test]
    async fn test_store_and_list_rules() {
        let pool = test_pool().await;
        let mgr = RulesetManager::new(pool);

        let rs_id = Uuid::new_v4();
        let rs = IdsRuleset {
            id: rs_id,
            name: "Custom".into(),
            source_url: None,
            rule_format: RuleFormat::Suricata,
            enabled: true,
            auto_update: false,
            update_interval_hours: 0,
            last_updated: None,
            rule_count: 0,
            created_at: Utc::now(),
        };
        mgr.add_ruleset(&rs).await.unwrap();

        let rules = vec![
            IdsRule {
                id: Uuid::new_v4(),
                ruleset_id: rs_id,
                sid: Some(1001),
                rule_text: r#"alert tcp any any -> any any (msg:"Test"; content:"test"; sid:1001;)"#.into(),
                msg: Some("Test".into()),
                severity: IdsSeverity::MEDIUM,
                enabled: true,
                action_override: None,
                hit_count: 0,
                last_hit: None,
                created_at: Utc::now(),
            },
        ];

        mgr.store_rules(rs_id, &rules).await.unwrap();
        let loaded = mgr.list_rules(Some(rs_id), true, 100, 0).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sid, Some(1001));
    }
}
