use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::task::AbortHandle;

use crate::error::{PluginError, Result};
use crate::rules::{RuleSink, check_table_name};

/// Entries kept in each plugin's activity log.
const LOG_CAPACITY: usize = 500;

/// Severity of a plugin activity-log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Routine activity
    Info,
    /// Something degraded but the plugin carries on
    Warn,
    /// A failure the operator should look at
    Error,
}

/// One entry in a plugin's activity log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// When it happened
    pub ts: DateTime<Utc>,
    /// Severity
    pub level: LogLevel,
    /// Message
    pub message: String,
}

struct Inner {
    name: String,
    pf: Arc<dyn PfBackend>,
    pool: SqlitePool,
    rules: Arc<RuleSink>,
    logs: Mutex<VecDeque<LogEntry>>,
    tasks: Mutex<Vec<AbortHandle>>,
    tables: Mutex<BTreeSet<String>>,
}

/// The handle a plugin uses to interact with AiFw. One per plugin; it
/// outlives individual start/stop cycles so the activity log survives
/// restarts.
///
/// Everything here is scoped to the plugin: pf access is limited to
/// `plugin_*` tables and `block`/`match` rules in the plugin anchor, the
/// key/value store is namespaced by plugin name, and spawned tasks are
/// cancelled when the plugin stops.
#[derive(Clone)]
pub struct PluginContext {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means a panic happened mid-update of a log
    // buffer or handle list; the data is still usable.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl PluginContext {
    /// Context for plugin `name`.
    pub fn new(name: &str, pf: Arc<dyn PfBackend>, pool: SqlitePool, rules: Arc<RuleSink>) -> Self {
        Self {
            inner: Arc::new(Inner {
                name: name.to_string(),
                pf,
                pool,
                rules,
                logs: Mutex::new(VecDeque::with_capacity(LOG_CAPACITY)),
                tasks: Mutex::new(Vec::new()),
                tables: Mutex::new(BTreeSet::new()),
            }),
        }
    }

    /// The plugin's name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Database handle, for plugins that need to read AiFw state.
    pub fn pool(&self) -> &SqlitePool {
        &self.inner.pool
    }

    // ---- activity log -------------------------------------------------

    /// Append to the plugin's activity log (shown in the UI) and to the
    /// service log.
    pub fn log(&self, level: LogLevel, message: impl Into<String>) {
        let message = message.into();
        match level {
            LogLevel::Info => tracing::info!(plugin = %self.inner.name, "{message}"),
            LogLevel::Warn => tracing::warn!(plugin = %self.inner.name, "{message}"),
            LogLevel::Error => tracing::error!(plugin = %self.inner.name, "{message}"),
        }
        let mut logs = lock(&self.inner.logs);
        if logs.len() == LOG_CAPACITY {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            ts: Utc::now(),
            level,
            message,
        });
    }

    /// Shorthand for `log(LogLevel::Info, ..)`.
    pub fn info(&self, message: impl Into<String>) {
        self.log(LogLevel::Info, message);
    }

    /// Shorthand for `log(LogLevel::Warn, ..)`.
    pub fn warn(&self, message: impl Into<String>) {
        self.log(LogLevel::Warn, message);
    }

    /// Shorthand for `log(LogLevel::Error, ..)`.
    pub fn error(&self, message: impl Into<String>) {
        self.log(LogLevel::Error, message);
    }

    /// Newest-first log entries at or above `min_level`, at most `limit`.
    pub fn recent_logs(&self, limit: usize, min_level: LogLevel) -> Vec<LogEntry> {
        lock(&self.inner.logs)
            .iter()
            .rev()
            .filter(|e| e.level >= min_level)
            .take(limit)
            .cloned()
            .collect()
    }

    // ---- key/value store ----------------------------------------------

    /// Read a value from the plugin's persistent store.
    pub async fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT value FROM plugin_kv WHERE plugin = ?1 AND key = ?2")
                .bind(&self.inner.name)
                .bind(key)
                .fetch_optional(&self.inner.pool)
                .await?,
        )
    }

    /// Write a value to the plugin's persistent store.
    pub async fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO plugin_kv (plugin, key, value, updated_at) \
             VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ','now')) \
             ON CONFLICT(plugin, key) DO UPDATE SET value = excluded.value, \
             updated_at = excluded.updated_at",
        )
        .bind(&self.inner.name)
        .bind(key)
        .bind(value)
        .execute(&self.inner.pool)
        .await?;
        Ok(())
    }

    /// Delete a value from the plugin's persistent store.
    pub async fn kv_delete(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM plugin_kv WHERE plugin = ?1 AND key = ?2")
            .bind(&self.inner.name)
            .bind(key)
            .execute(&self.inner.pool)
            .await?;
        Ok(())
    }

    /// Read and deserialize a JSON value. A value that no longer parses
    /// (format changed between versions) reads as `None`.
    pub async fn kv_get_json<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        Ok(self
            .kv_get(key)
            .await?
            .and_then(|s| serde_json::from_str(&s).ok()))
    }

    /// Serialize and write a JSON value.
    pub async fn kv_set_json<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let s = serde_json::to_string(value).map_err(|e| PluginError::Store(e.to_string()))?;
        self.kv_set(key, &s).await
    }

    // ---- background tasks ---------------------------------------------

    /// Run `fut` in the background. It is aborted when the plugin stops; a
    /// panic is caught and recorded in the activity log.
    pub fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let task = tokio::spawn(fut);
        let abort = task.abort_handle();
        let ctx = self.clone();
        tokio::spawn(async move {
            if let Err(e) = task.await
                && e.is_panic()
            {
                ctx.error("background task panicked");
            }
        });
        let mut tasks = lock(&self.inner.tasks);
        tasks.retain(|t| !t.is_finished());
        tasks.push(abort);
    }

    /// Abort every task started with [`PluginContext::spawn`].
    pub(crate) fn abort_tasks(&self) {
        for t in lock(&self.inner.tasks).drain(..) {
            t.abort();
        }
    }

    // ---- pf tables ------------------------------------------------------

    fn touch(&self, table: &str) -> Result<()> {
        check_table_name(table)?;
        lock(&self.inner.tables).insert(table.to_string());
        Ok(())
    }

    /// Add an address to a `plugin_*` table.
    pub async fn add_to_table(&self, table: &str, ip: IpAddr) -> Result<()> {
        self.touch(table)?;
        self.inner
            .pf
            .add_table_entry(table, ip)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Remove an address from a `plugin_*` table.
    pub async fn remove_from_table(&self, table: &str, ip: IpAddr) -> Result<()> {
        self.touch(table)?;
        self.inner
            .pf
            .remove_table_entry(table, ip)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Atomically replace a `plugin_*` table's contents.
    pub async fn replace_table(&self, table: &str, entries: &[(IpAddr, u8)]) -> Result<()> {
        self.touch(table)?;
        self.inner
            .pf
            .replace_table_entries(table, entries)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Empty a `plugin_*` table.
    pub async fn flush_table(&self, table: &str) -> Result<()> {
        self.touch(table)?;
        self.inner
            .pf
            .flush_table(table)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Number of entries in a `plugin_*` table.
    pub async fn table_len(&self, table: &str) -> Result<usize> {
        check_table_name(table)?;
        self.inner
            .pf
            .get_table_entries(table)
            .await
            .map(|e| e.len())
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Flush every table this plugin touched (manager cleanup on stop).
    pub(crate) async fn flush_touched_tables(&self) {
        let tables: Vec<String> = lock(&self.inner.tables).iter().cloned().collect();
        for t in tables {
            if let Err(e) = self.inner.pf.flush_table(&t).await {
                tracing::warn!(plugin = %self.inner.name, table = %t, error = %e, "plugin table flush failed");
            }
        }
    }

    // ---- pf rules -------------------------------------------------------

    /// Replace this plugin's rules in the plugin anchor. Only `block` and
    /// `match` rules referencing `plugin_*` tables are accepted.
    pub async fn set_rules(&self, rules: Vec<String>) -> Result<()> {
        self.inner.rules.set(&self.inner.name, rules).await
    }

    /// Remove this plugin's rules from the plugin anchor.
    pub async fn clear_rules(&self) -> Result<()> {
        self.inner.rules.set(&self.inner.name, Vec::new()).await
    }

    /// This plugin's current rules.
    pub async fn rules(&self) -> Vec<String> {
        self.inner.rules.rules_of(&self.inner.name).await
    }
}
