use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;

use crate::config::FirewallConfig;

/// A stored config version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    pub version: i64,
    pub hash: String,
    pub applied: bool,
    pub applied_at: Option<String>,
    pub rolled_back: bool,
    pub created_by: String,
    pub created_at: String,
    pub comment: Option<String>,
    pub resource_count: usize,
}

/// Manages versioned firewall configuration
pub struct ConfigManager {
    pool: SqlitePool,
    config_dir: String,
}

impl ConfigManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            config_dir: "/usr/local/etc/aifw".to_string(),
        }
    }

    pub fn with_config_dir(mut self, dir: String) -> Self {
        self.config_dir = dir;
        self
    }

    pub async fn migrate(&self) -> Result<(), String> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS config_versions (
                version INTEGER PRIMARY KEY AUTOINCREMENT,
                config_json TEXT NOT NULL,
                hash TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0,
                applied_at TEXT,
                rolled_back INTEGER NOT NULL DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                comment TEXT
            )"#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| format!("migration error: {e}"))?;

        Ok(())
    }

    /// Save a new config version. Does NOT apply it yet.
    pub async fn save_version(
        &self,
        config: &FirewallConfig,
        created_by: &str,
        comment: Option<&str>,
    ) -> Result<i64, String> {
        let json = config.to_json();
        let hash = config.hash();
        let now = Utc::now().to_rfc3339();

        let result = sqlx::query(
            r#"INSERT INTO config_versions (config_json, hash, applied, created_by, created_at, comment)
               VALUES (?1, ?2, 0, ?3, ?4, ?5)"#,
        )
        .bind(&json)
        .bind(&hash)
        .bind(created_by)
        .bind(&now)
        .bind(comment)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("save error: {e}"))?;

        Ok(result.last_insert_rowid())
    }

    /// Mark a version as applied (after successful pf apply)
    pub async fn mark_applied(&self, version: i64) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();

        // Unmark any previously applied version
        sqlx::query("UPDATE config_versions SET applied = 0 WHERE applied = 1")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("db error: {e}"))?;

        sqlx::query("UPDATE config_versions SET applied = 1, applied_at = ?1 WHERE version = ?2")
            .bind(&now)
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("db error: {e}"))?;

        Ok(())
    }

    /// Atomic save + apply. If apply_fn fails, auto-rollback (version stays unapplied).
    pub async fn save_and_apply<F, Fut>(
        &self,
        config: &FirewallConfig,
        created_by: &str,
        comment: Option<&str>,
        apply_fn: F,
    ) -> Result<i64, String>
    where
        F: FnOnce(FirewallConfig) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let version = self.save_version(config, created_by, comment).await?;

        // Try to apply
        match apply_fn(config.clone()).await {
            Ok(()) => {
                self.mark_applied(version).await?;
                // Write flat file backup
                self.write_flat_file(config, version).await;
                tracing::info!(version, "config v{version} applied successfully");
                Ok(version)
            }
            Err(e) => {
                tracing::error!(version, error = %e, "config v{version} apply failed — not applied");
                Err(format!("apply failed (v{version} saved but not applied): {e}"))
            }
        }
    }

    /// Get the currently active (applied) config
    pub async fn get_active(&self) -> Result<Option<(i64, FirewallConfig)>, String> {
        let row = sqlx::query_as::<_, (i64, String)>(
            "SELECT version, config_json FROM config_versions WHERE applied = 1 ORDER BY version DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;

        match row {
            Some((version, json)) => {
                let config = FirewallConfig::from_json(&json)?;
                Ok(Some((version, config)))
            }
            None => Ok(None),
        }
    }

    /// Get a specific version
    pub async fn get_version(&self, version: i64) -> Result<FirewallConfig, String> {
        let (json,) = sqlx::query_as::<_, (String,)>(
            "SELECT config_json FROM config_versions WHERE version = ?1",
        )
        .bind(version)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("version {version} not found: {e}"))?;

        FirewallConfig::from_json(&json)
    }

    /// Rollback to a specific version
    pub async fn rollback<F, Fut>(
        &self,
        version: i64,
        apply_fn: F,
    ) -> Result<(), String>
    where
        F: FnOnce(FirewallConfig) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let config = self.get_version(version).await?;

        // Mark current as rolled back
        sqlx::query("UPDATE config_versions SET rolled_back = 1 WHERE applied = 1")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("db error: {e}"))?;

        // Apply the target version
        apply_fn(config.clone()).await?;
        self.mark_applied(version).await?;
        self.write_flat_file(&config, version).await;

        tracing::info!(version, "rolled back to config v{version}");
        Ok(())
    }

    /// List version history
    pub async fn history(&self, limit: i64) -> Result<Vec<ConfigVersion>, String> {
        let rows = sqlx::query_as::<_, (i64, String, bool, Option<String>, bool, String, String, Option<String>)>(
            r#"SELECT version, hash, applied, applied_at, rolled_back, created_by, created_at, comment
               FROM config_versions ORDER BY version DESC LIMIT ?1"#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;

        let mut versions = Vec::new();
        for (version, hash, applied, applied_at, rolled_back, created_by, created_at, comment) in rows {
            // Get resource count from the config JSON
            let rc = sqlx::query_as::<_, (String,)>(
                "SELECT config_json FROM config_versions WHERE version = ?1",
            )
            .bind(version)
            .fetch_one(&self.pool)
            .await
            .ok()
            .and_then(|(json,)| FirewallConfig::from_json(&json).ok())
            .map(|c| c.resource_count())
            .unwrap_or(0);

            versions.push(ConfigVersion {
                version,
                hash,
                applied,
                applied_at,
                rolled_back,
                created_by,
                created_at,
                comment,
                resource_count: rc,
            });
        }

        Ok(versions)
    }

    /// Diff two versions — returns (added, removed, changed) field paths
    pub async fn diff(&self, v1: i64, v2: i64) -> Result<ConfigDiff, String> {
        let c1 = self.get_version(v1).await?;
        let c2 = self.get_version(v2).await?;

        Ok(ConfigDiff {
            v1,
            v2,
            v1_hash: c1.hash(),
            v2_hash: c2.hash(),
            rules_diff: Diff {
                added: c2.rules.len().saturating_sub(c1.rules.len()),
                removed: c1.rules.len().saturating_sub(c2.rules.len()),
                v1_count: c1.rules.len(),
                v2_count: c2.rules.len(),
            },
            nat_diff: Diff {
                added: c2.nat.len().saturating_sub(c1.nat.len()),
                removed: c1.nat.len().saturating_sub(c2.nat.len()),
                v1_count: c1.nat.len(),
                v2_count: c2.nat.len(),
            },
            total_v1: c1.resource_count(),
            total_v2: c2.resource_count(),
            identical: c1.hash() == c2.hash(),
        })
    }

    /// Total number of stored versions
    pub async fn version_count(&self) -> Result<i64, String> {
        let (count,) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM config_versions")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("db error: {e}"))?;
        Ok(count)
    }

    /// Write the config as a flat JSON file + backup
    async fn write_flat_file(&self, config: &FirewallConfig, version: i64) {
        let json = config.to_json();

        // Main config file
        let main_path = format!("{}/config.json", self.config_dir);
        if let Err(e) = std::fs::create_dir_all(&self.config_dir) {
            tracing::warn!("failed to create config dir: {e}");
            return;
        }
        if let Err(e) = std::fs::write(&main_path, &json) {
            tracing::warn!("failed to write config.json: {e}");
        }

        // Backup
        let backup_dir = format!("{}/backup", self.config_dir);
        let _ = std::fs::create_dir_all(&backup_dir);
        let ts = Utc::now().format("%Y%m%d-%H%M%S");
        let backup_path = format!("{backup_dir}/config-v{version}-{ts}.json");
        let _ = std::fs::write(&backup_path, &json);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDiff {
    pub v1: i64,
    pub v2: i64,
    pub v1_hash: String,
    pub v2_hash: String,
    pub rules_diff: Diff,
    pub nat_diff: Diff,
    pub total_v1: usize,
    pub total_v2: usize,
    pub identical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub added: usize,
    pub removed: usize,
    pub v1_count: usize,
    pub v2_count: usize,
}
