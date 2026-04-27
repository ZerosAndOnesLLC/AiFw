use std::sync::RwLock;

use aifw_common::ids::{IdsConfig, IdsMode};
use sqlx::SqlitePool;

use crate::Result;

/// Runtime configuration for the IDS engine.
/// Wraps `IdsConfig` with thread-safe interior mutability for hot-reload.
pub struct RuntimeConfig {
    inner: RwLock<IdsConfig>,
}

impl RuntimeConfig {
    /// Load configuration from the database, falling back to defaults.
    pub async fn load(pool: &SqlitePool) -> Result<Self> {
        let cfg = Self::read_from_db(pool).await?;
        Ok(Self {
            inner: RwLock::new(cfg),
        })
    }

    /// Get a snapshot of the current configuration.
    pub fn config(&self) -> IdsConfig {
        self.inner.read().unwrap().clone()
    }

    /// Update configuration in memory.
    pub fn update(&self, cfg: IdsConfig) {
        *self.inner.write().unwrap() = cfg;
    }

    /// Load configuration from the database.
    pub async fn load_from_db(&self, pool: &SqlitePool) -> Result<IdsConfig> {
        let cfg = Self::read_from_db(pool).await?;
        self.update(cfg.clone());
        Ok(cfg)
    }

    /// Save configuration to the database. Values are clamped to safe
    /// upper bounds so a malformed `SetConfig` (whether from a buggy UI
    /// or hostile API client) cannot poison the DB into an OOM-on-restart
    /// loop.
    pub async fn save_to_db(&self, pool: &SqlitePool, cfg: &IdsConfig) -> Result<()> {
        let clamped = Self::clamp(cfg);
        Self::write_to_db(pool, &clamped).await?;
        self.update(clamped);
        Ok(())
    }

    /// Clamp config fields that, if oversized, would crash the daemon on
    /// next restart. Mirrored at engine init time as a defence in depth
    /// for rows already on disk from older versions.
    fn clamp(cfg: &IdsConfig) -> IdsConfig {
        // Caps chosen so the worst-case engine init still fits comfortably
        // in a 4 GB appliance: 1M flow rows ≈ a few hundred MB of HashMap,
        // 4 MB stream depth × 1M flows would be 4 TB so the *product* is
        // still bounded by flow_table_size.
        const MAX_FLOW_TABLE_SIZE: u32 = 1_000_000;
        const MAX_STREAM_DEPTH_KB: u32 = 4096; // 4 MB
        const MAX_WORKER_COUNT: u32 = 64;
        const MAX_REASSEMBLY_BUDGET_MB: u32 = 4096; // 4 GB cap; default 256

        let mut out = cfg.clone();
        if let Some(v) = out.flow_table_size {
            out.flow_table_size = Some(v.min(MAX_FLOW_TABLE_SIZE));
        }
        if let Some(v) = out.flow_stream_depth_kb {
            out.flow_stream_depth_kb = Some(v.min(MAX_STREAM_DEPTH_KB));
        }
        if let Some(v) = out.stream_depth {
            out.stream_depth = Some(v.min(MAX_STREAM_DEPTH_KB));
        }
        if let Some(v) = out.worker_count {
            out.worker_count = Some(v.min(MAX_WORKER_COUNT));
        }
        if let Some(v) = out.flow_reassembly_budget_mb {
            out.flow_reassembly_budget_mb = Some(v.min(MAX_REASSEMBLY_BUDGET_MB));
        }
        out
    }

    /// Network variable expansion: resolve `$HOME_NET`, `$EXTERNAL_NET`, etc.
    pub fn expand_var(&self, var: &str) -> Vec<String> {
        let cfg = self.inner.read().unwrap();
        match var {
            "$HOME_NET" | "HOME_NET" => cfg.home_net.clone(),
            "$EXTERNAL_NET" | "EXTERNAL_NET" => {
                // If external_net contains "!$HOME_NET", expand it
                if cfg.external_net.iter().any(|s| s.contains("$HOME_NET")) {
                    // Return negated home_net
                    cfg.home_net.iter().map(|s| format!("!{s}")).collect()
                } else {
                    cfg.external_net.clone()
                }
            }
            _ => vec![var.to_string()],
        }
    }

    async fn read_from_db(pool: &SqlitePool) -> Result<IdsConfig> {
        let mut cfg = IdsConfig::default();

        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM ids_config")
            .fetch_all(pool)
            .await?;

        for (key, value) in rows {
            match key.as_str() {
                "mode" => {
                    cfg.mode = match value.as_str() {
                        "ids" => IdsMode::Ids,
                        "ips" => IdsMode::Ips,
                        _ => IdsMode::Disabled,
                    };
                }
                "home_net" => {
                    cfg.home_net = serde_json::from_str(&value).unwrap_or_default();
                }
                "external_net" => {
                    cfg.external_net = serde_json::from_str(&value).unwrap_or_default();
                }
                "interfaces" => {
                    cfg.interfaces = serde_json::from_str(&value).unwrap_or_default();
                }
                "alert_retention_days" => {
                    cfg.alert_retention_days = value.parse().unwrap_or(30);
                }
                "eve_log_enabled" => {
                    cfg.eve_log_enabled = value == "true" || value == "1";
                }
                "eve_log_path" => {
                    cfg.eve_log_path = Some(value);
                }
                "syslog_target" => {
                    cfg.syslog_target = Some(value);
                }
                "worker_count" => {
                    cfg.worker_count = value.parse().ok();
                }
                "flow_table_size" => {
                    cfg.flow_table_size = value.parse().ok();
                }
                "stream_depth" => {
                    cfg.stream_depth = value.parse().ok();
                }
                "flow_stream_depth_kb" => {
                    cfg.flow_stream_depth_kb = value.parse().ok();
                }
                "flow_reassembly_budget_mb" => {
                    cfg.flow_reassembly_budget_mb = value.parse().ok();
                }
                _ => {}
            }
        }

        Ok(cfg)
    }

    async fn write_to_db(pool: &SqlitePool, cfg: &IdsConfig) -> Result<()> {
        let pairs: Vec<(&str, String)> = vec![
            ("mode", cfg.mode.to_string()),
            (
                "home_net",
                serde_json::to_string(&cfg.home_net).unwrap_or_default(),
            ),
            (
                "external_net",
                serde_json::to_string(&cfg.external_net).unwrap_or_default(),
            ),
            (
                "interfaces",
                serde_json::to_string(&cfg.interfaces).unwrap_or_default(),
            ),
            ("alert_retention_days", cfg.alert_retention_days.to_string()),
            ("eve_log_enabled", cfg.eve_log_enabled.to_string()),
        ];

        for (key, value) in &pairs {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES (?, ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?;
        }

        if let Some(ref path) = cfg.eve_log_path {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('eve_log_path', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(path)
            .execute(pool)
            .await?;
        }

        if let Some(ref target) = cfg.syslog_target {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('syslog_target', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(target)
            .execute(pool)
            .await?;
        }

        if let Some(wc) = cfg.worker_count {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('worker_count', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(wc.to_string())
            .execute(pool)
            .await?;
        }

        if let Some(fts) = cfg.flow_table_size {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('flow_table_size', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(fts.to_string())
            .execute(pool)
            .await?;
        }

        if let Some(sd) = cfg.stream_depth {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('stream_depth', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(sd.to_string())
            .execute(pool)
            .await?;
        }

        if let Some(v) = cfg.flow_stream_depth_kb {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('flow_stream_depth_kb', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(v.to_string())
            .execute(pool)
            .await?;
        }

        if let Some(v) = cfg.flow_reassembly_budget_mb {
            sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('flow_reassembly_budget_mb', ?, datetime('now'))
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .bind(v.to_string())
            .execute(pool)
            .await?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeConfig")
            .field("config", &self.config())
            .finish()
    }
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
    async fn test_config_defaults() {
        let pool = test_pool().await;
        let config = RuntimeConfig::load(&pool).await.unwrap();
        let cfg = config.config();
        assert_eq!(cfg.mode, IdsMode::Disabled);
        assert!(!cfg.home_net.is_empty());
    }

    #[tokio::test]
    async fn test_config_roundtrip() {
        let pool = test_pool().await;
        let config = RuntimeConfig::load(&pool).await.unwrap();

        let mut cfg = config.config();
        cfg.mode = IdsMode::Ids;
        cfg.alert_retention_days = 7;
        config.save_to_db(&pool, &cfg).await.unwrap();

        let loaded = config.load_from_db(&pool).await.unwrap();
        assert_eq!(loaded.mode, IdsMode::Ids);
        assert_eq!(loaded.alert_retention_days, 7);
    }

    #[tokio::test]
    async fn test_var_expansion() {
        let pool = test_pool().await;
        let config = RuntimeConfig::load(&pool).await.unwrap();

        let home = config.expand_var("$HOME_NET");
        assert!(home.contains(&"10.0.0.0/8".to_string()));

        let ext = config.expand_var("$EXTERNAL_NET");
        assert!(ext.iter().any(|s| s.starts_with('!')));
    }
}
