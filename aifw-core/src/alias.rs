use aifw_common::{Alias, AliasType, AifwError, Result};
use aifw_pf::PfBackend;
use chrono::Utc;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

/// Reserved table names that aliases cannot use.
const RESERVED_NAMES: &[&str] = &["bruteforce", "ai_blocked"];

pub struct AliasEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
}

impl AliasEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self { pool, pf }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS aliases (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                alias_type TEXT NOT NULL,
                entries TEXT NOT NULL DEFAULT '[]',
                description TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        "#)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<Alias>> {
        let rows = sqlx::query("SELECT id, name, alias_type, entries, description, enabled, created_at, updated_at FROM aliases ORDER BY name ASC")
            .fetch_all(&self.pool).await.map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(rows.iter().map(|r| {
            let entries_json: String = r.get("entries");
            let entries: Vec<String> = serde_json::from_str(&entries_json).unwrap_or_default();
            let alias_type_str: String = r.get("alias_type");
            Alias {
                id: r.get::<String, _>("id").parse().unwrap_or_default(),
                name: r.get("name"),
                alias_type: AliasType::parse(&alias_type_str).unwrap_or(AliasType::Host),
                entries,
                description: r.get("description"),
                enabled: r.get("enabled"),
                created_at: r.get::<String, _>("created_at").parse().unwrap_or_default(),
                updated_at: r.get::<String, _>("updated_at").parse().unwrap_or_default(),
            }
        }).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<Alias> {
        let aliases = self.list().await?;
        aliases.into_iter().find(|a| a.id == id)
            .ok_or_else(|| AifwError::NotFound(format!("alias {} not found", id)))
    }

    pub async fn add(&self, alias: Alias) -> Result<Alias> {
        self.validate_name(&alias.name)?;
        let entries_json = serde_json::to_string(&alias.entries)
            .map_err(|e| AifwError::Validation(e.to_string()))?;

        sqlx::query("INSERT INTO aliases (id, name, alias_type, entries, description, enabled, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")
            .bind(alias.id.to_string()).bind(&alias.name).bind(alias.alias_type.as_str())
            .bind(&entries_json).bind(alias.description.as_deref())
            .bind(alias.enabled).bind(alias.created_at.to_rfc3339()).bind(alias.updated_at.to_rfc3339())
            .execute(&self.pool).await.map_err(|e| AifwError::Database(e.to_string()))?;

        if alias.enabled {
            self.sync_to_pf(&alias).await?;
        }

        tracing::info!(name = %alias.name, alias_type = %alias.alias_type, entries = alias.entries.len(), "alias created");
        Ok(alias)
    }

    pub async fn update(&self, alias: Alias) -> Result<Alias> {
        self.validate_name(&alias.name)?;
        let entries_json = serde_json::to_string(&alias.entries)
            .map_err(|e| AifwError::Validation(e.to_string()))?;
        let now = Utc::now().to_rfc3339();

        let result = sqlx::query("UPDATE aliases SET name=?2, alias_type=?3, entries=?4, description=?5, enabled=?6, updated_at=?7 WHERE id=?1")
            .bind(alias.id.to_string()).bind(&alias.name).bind(alias.alias_type.as_str())
            .bind(&entries_json).bind(alias.description.as_deref())
            .bind(alias.enabled).bind(&now)
            .execute(&self.pool).await.map_err(|e| AifwError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("alias {} not found", alias.id)));
        }

        // Flush and re-sync pf table
        let _ = self.pf.flush_table(&alias.name).await;
        if alias.enabled {
            self.sync_to_pf(&alias).await?;
        }

        tracing::info!(name = %alias.name, "alias updated");
        Ok(alias)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let alias = self.get(id).await?;
        let _ = self.pf.flush_table(&alias.name).await;

        sqlx::query("DELETE FROM aliases WHERE id=?1")
            .bind(id.to_string())
            .execute(&self.pool).await.map_err(|e| AifwError::Database(e.to_string()))?;

        tracing::info!(name = %alias.name, "alias deleted");
        Ok(())
    }

    /// Sync all enabled aliases to pf tables. Called during reload.
    pub async fn sync_all(&self) -> Result<()> {
        let aliases = self.list().await?;
        let mut synced = 0;
        for alias in &aliases {
            if alias.enabled {
                let _ = self.pf.flush_table(&alias.name).await;
                if let Err(e) = self.sync_to_pf(alias).await {
                    tracing::warn!(name = %alias.name, error = %e, "failed to sync alias to pf");
                } else {
                    synced += 1;
                }
            }
        }
        if synced > 0 {
            tracing::info!(count = synced, "aliases synced to pf tables");
        }
        Ok(())
    }

    /// Sync a single alias to its pf table.
    async fn sync_to_pf(&self, alias: &Alias) -> Result<()> {
        match alias.alias_type {
            AliasType::Host | AliasType::Network => {
                for entry in &alias.entries {
                    let entry = entry.trim();
                    if entry.is_empty() { continue; }
                    // For networks like "10.0.0.0/8", pf tables accept CIDR
                    // For hosts like "1.2.3.4", parse as IP
                    if let Some((ip_str, _prefix)) = entry.split_once('/') {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let _ = self.pf.add_table_entry(&alias.name, ip).await;
                        }
                    } else if let Ok(ip) = entry.parse::<IpAddr>() {
                        let _ = self.pf.add_table_entry(&alias.name, ip).await;
                    }
                }
            }
            AliasType::UrlTable => {
                // Fetch URL and load IPs into table
                for url in &alias.entries {
                    if let Ok(output) = tokio::process::Command::new("curl")
                        .args(["-sf", "--max-time", "30", url.trim()])
                        .output().await
                        && output.status.success() {
                            let body = String::from_utf8_lossy(&output.stdout);
                            for line in body.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') { continue; }
                                let ip_str = line.split_whitespace().next().unwrap_or("");
                                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                    let _ = self.pf.add_table_entry(&alias.name, ip).await;
                                }
                            }
                        }
                }
            }
            AliasType::Port => {
                // Port aliases are not pf tables — they're expanded inline in rules.
                // Nothing to sync to pf.
            }
        }
        Ok(())
    }

    fn validate_name(&self, name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 31 {
            return Err(AifwError::Validation("Alias name must be 1-31 characters".into()));
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(AifwError::Validation("Alias name must be alphanumeric (with _ and -)".into()));
        }
        if RESERVED_NAMES.contains(&name) {
            return Err(AifwError::Validation(format!("Name '{}' is reserved", name)));
        }
        Ok(())
    }
}
