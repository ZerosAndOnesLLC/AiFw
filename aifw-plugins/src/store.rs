//! Persistence for plugin configuration (`plugin_config`). The table is
//! the source of truth: the API, CLI, config restore and cluster sync all
//! write here, and the manager's reconcile loop applies changes by
//! comparing `updated_at` with what it last applied.

use serde_json::{Map, Value};
use sqlx::SqlitePool;

use crate::error::{PluginError, Result};
use crate::manager::SettingsPatch;
use crate::plugin::Plugin;

/// One plugin's persisted configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoredConfig {
    /// Operator wants the plugin running
    pub enabled: bool,
    /// Non-secret settings the operator set (defaults not included)
    pub values: Map<String, Value>,
    /// Secret settings, plaintext in memory (sealed at rest)
    pub secrets: Map<String, Value>,
    /// Change marker; `None` when no row exists
    pub updated_at: Option<String>,
}

impl StoredConfig {
    /// Merge `patch` (`null` = reset / clear), validate against `plugin`'s
    /// schema — and, when enabled, its cross-field checks — and keep the
    /// normalized result. On error `self` is unchanged.
    pub fn apply_patch(&mut self, plugin: &dyn Plugin, patch: SettingsPatch) -> Result<()> {
        let schema = plugin.settings_schema();
        let mut values = self.values.clone();
        let mut secrets = self.secrets.clone();
        merge(&mut values, patch.values);
        merge(&mut secrets, patch.secrets);
        let (values, secrets) = crate::schema::normalize(&schema, &values, &secrets)?;
        if self.enabled {
            plugin.validate_settings(&crate::schema::effective(&schema, &values, &secrets))?;
        }
        self.values = values;
        self.secrets = secrets;
        Ok(())
    }

    /// Flip the enabled flag. Enabling runs the plugin's cross-field checks
    /// first so a plugin that can't start says why instead of failing later.
    pub fn set_enabled(&mut self, plugin: &dyn Plugin, enabled: bool) -> Result<()> {
        if enabled {
            let schema = plugin.settings_schema();
            plugin.validate_settings(&crate::schema::effective(
                &schema,
                &self.values,
                &self.secrets,
            ))?;
        }
        self.enabled = enabled;
        Ok(())
    }
}

fn merge(target: &mut Map<String, Value>, patch: Map<String, Value>) {
    for (k, v) in patch {
        if v.is_null() {
            target.remove(&k);
        } else {
            target.insert(k, v);
        }
    }
}

/// Names of plugins removed from AiFw; their rows are deleted on migrate.
const RETIRED: &[&str] = &[
    "custom-logger",
    "logging",
    "ip-reputation",
    "ip_reputation",
    "webhook-notifier",
    "webhook",
];

/// Read/write access to `plugin_config`.
#[derive(Clone)]
pub struct PluginStore {
    pool: SqlitePool,
}

fn parse_map(s: Option<String>) -> Map<String, Value> {
    s.and_then(|s| serde_json::from_str::<Map<String, Value>>(&s).ok())
        .unwrap_or_default()
}

fn now_marker() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

impl PluginStore {
    /// Store over `pool`.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Bring `plugin_config` up to date on installs that predate the
    /// versioned migration (adds `secrets` / `updated_at`) and drop rows of
    /// retired plugins. Requires `aifw_core::migrations::run` first.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS plugin_config \
             (name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, settings TEXT)",
        )
        .execute(&self.pool)
        .await?;
        aifw_core::schema::add_column_if_missing(&self.pool, "plugin_config", "secrets", "TEXT")
            .await?;
        aifw_core::schema::add_column_if_missing(&self.pool, "plugin_config", "updated_at", "TEXT")
            .await?;
        for name in RETIRED {
            sqlx::query("DELETE FROM plugin_config WHERE name = ?1")
                .bind(name)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Load a plugin's config (default when no row exists).
    pub async fn load(&self, name: &str) -> Result<StoredConfig> {
        let row: Option<(i64, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT enabled, settings, secrets, updated_at FROM plugin_config WHERE name = ?1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        let Some((enabled, settings, secrets, updated_at)) = row else {
            return Ok(StoredConfig::default());
        };
        let secrets = match secrets {
            Some(s) if !s.is_empty() => parse_map(Some(aifw_core::secrets::open(&s)?)),
            _ => Map::new(),
        };
        Ok(StoredConfig {
            enabled: enabled != 0,
            values: parse_map(settings),
            secrets,
            // Rows written before updated_at existed still need a marker so
            // a later write is seen as a change.
            updated_at: Some(updated_at.unwrap_or_default()),
        })
    }

    /// Current change marker for `name` (cheap reconcile check).
    pub async fn updated_at(&self, name: &str) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT updated_at FROM plugin_config WHERE name = ?1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(u,)| u.unwrap_or_default()))
    }

    /// Persist `cfg` for `name` and return the new change marker.
    pub async fn save(&self, name: &str, cfg: &StoredConfig) -> Result<String> {
        save_on(&self.pool, name, cfg).await
    }

    /// Delete `name`'s row (reset to defaults, disabled).
    pub async fn reset(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM plugin_config WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Persist `cfg` on any executor (pool or an open transaction — config
/// restore writes inside its own transaction). Secrets are sealed.
pub async fn save_on<'e, E>(exec: E, name: &str, cfg: &StoredConfig) -> Result<String>
where
    E: sqlx::SqliteExecutor<'e>,
{
    let values =
        serde_json::to_string(&cfg.values).map_err(|e| PluginError::Store(e.to_string()))?;
    let secrets = if cfg.secrets.is_empty() {
        None
    } else {
        let plain =
            serde_json::to_string(&cfg.secrets).map_err(|e| PluginError::Store(e.to_string()))?;
        Some(aifw_core::secrets::seal(&plain)?)
    };
    let marker = now_marker();
    sqlx::query(
        "INSERT INTO plugin_config (name, enabled, settings, secrets, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled, \
         settings = excluded.settings, secrets = excluded.secrets, \
         updated_at = excluded.updated_at",
    )
    .bind(name)
    .bind(cfg.enabled as i64)
    .bind(values)
    .bind(secrets)
    .bind(&marker)
    .execute(exec)
    .await?;
    Ok(marker)
}

/// Every built-in plugin's stored configuration as config-snapshot entries
/// (secrets in plaintext — export paths redact or wrap them). Plugins with
/// no row are omitted.
pub async fn export_entries(
    pool: &SqlitePool,
) -> Result<Vec<aifw_core::config::PluginConfigEntry>> {
    let store = PluginStore::new(pool.clone());
    let mut out = Vec::new();
    for f in crate::registry::factories() {
        let name = f().info().name;
        let cfg = store.load(&name).await?;
        if cfg.updated_at.is_none() {
            continue;
        }
        out.push(aifw_core::config::PluginConfigEntry {
            name,
            enabled: cfg.enabled,
            settings: cfg.values,
            secrets: cfg
                .secrets
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect(),
        });
    }
    Ok(out)
}

/// Replace all plugin configuration with `entries` inside the caller's
/// transaction (config restore). Entries for plugins this build doesn't
/// ship, or whose settings no longer fit the plugin's schema, are skipped;
/// the returned warnings say which and why.
pub async fn restore_on(
    conn: &mut sqlx::SqliteConnection,
    entries: &[aifw_core::config::PluginConfigEntry],
) -> Result<Vec<String>> {
    sqlx::query("DELETE FROM plugin_config")
        .execute(&mut *conn)
        .await?;
    let mut warnings = Vec::new();
    for e in entries {
        let Some(plugin) = crate::registry::instantiate(&e.name) else {
            warnings.push(format!(
                "plugin '{}' is not part of this build; skipped",
                e.name
            ));
            continue;
        };
        let secrets: Map<String, Value> = e
            .secrets
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let (values, secrets) =
            match crate::schema::normalize(&plugin.settings_schema(), &e.settings, &secrets) {
                Ok(v) => v,
                Err(err) => {
                    warnings.push(format!("plugin '{}' settings skipped: {err}", e.name));
                    continue;
                }
            };
        let cfg = StoredConfig {
            enabled: e.enabled,
            values,
            secrets,
            updated_at: None,
        };
        save_on(&mut *conn, &e.name, &cfg).await?;
    }
    Ok(warnings)
}
