use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// KV key under which the tables a plugin touched are remembered, so a
/// disable that happens while the API is down (CLI) still empties them.
const TABLES_KEY: &str = "__tables";

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
    /// False between stop and the next start: late hook replies and tasks
    /// from a stopped run may not touch pf or spawn work.
    active: AtomicBool,
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
                active: AtomicBool::new(true),
            }),
        }
    }

    /// A context over a fresh in-memory database and a mock pf backend,
    /// for plugin tests. Keep the returned [`TestContext`] alive for the
    /// duration of the test; it owns the database.
    pub async fn for_tests(name: &str) -> TestContext {
        let db = aifw_core::Database::new_in_memory()
            .await
            .expect("in-memory SQLite always opens");
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let pool = db.pool().clone();
        let rules = Arc::new(RuleSink::new(pf.clone(), aifw_common::anchors::PLUGINS));
        TestContext {
            ctx: Self::new(name, pf.clone(), pool.clone(), rules),
            pf,
            pool,
            _db: db,
        }
    }

    /// Mark the context live (manager, on start). Clears the stopped flag
    /// set by [`PluginContext::deactivate`].
    pub(crate) fn activate(&self) {
        self.inner.active.store(true, Ordering::Release);
    }

    /// Refuse further pf writes and spawns (manager, on stop). A hook
    /// reply or task that outlives its run can no longer leave anything
    /// behind.
    pub(crate) fn deactivate(&self) {
        self.inner.active.store(false, Ordering::Release);
    }

    fn ensure_active(&self) -> Result<()> {
        if self.inner.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PluginError::Plugin("plugin is stopped".into()))
        }
    }

    /// The plugin's name.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// The AiFw database. Plugins that need to read firewall state (rules,
    /// aliases, IDS alerts) use this. Nothing stops a plugin from writing
    /// through it either — the pf, KV, log and HTTP helpers are the
    /// supported surface, and in-tree plugins are expected to stay on it.
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

    /// Keys in the plugin's store that start with `prefix` (`""` for all),
    /// sorted. Lets a plugin prune state it no longer needs.
    pub async fn kv_keys(&self, prefix: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT key FROM plugin_kv WHERE plugin = ?1 AND key >= ?2 ORDER BY key",
        )
        .bind(&self.inner.name)
        .bind(prefix)
        .fetch_all(&self.inner.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(k,)| k)
            .filter(|k| k.starts_with(prefix) && k != TABLES_KEY)
            .collect())
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
    /// panic is caught and recorded in the activity log. After the plugin
    /// has stopped, `fut` is dropped unrun.
    pub fn spawn<F>(&self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.ensure_active().is_err() {
            tracing::debug!(plugin = %self.inner.name, "plugins: spawn after stop ignored");
            return;
        }
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

    /// Record that the plugin uses `table` (and persist the list, so a
    /// disable while the API is down can still empty it).
    async fn touch(&self, table: &str) -> Result<()> {
        check_table_name(table)?;
        self.ensure_active()?;
        let list: Option<Vec<String>> = {
            let mut tables = lock(&self.inner.tables);
            tables
                .insert(table.to_string())
                .then(|| tables.iter().cloned().collect())
        };
        if let Some(list) = list
            && let Err(e) = self.kv_set_json(TABLES_KEY, &list).await
        {
            tracing::warn!(plugin = %self.inner.name, error = %e, "plugins: could not persist table list");
        }
        Ok(())
    }

    /// Add an address to a `plugin_*` table.
    pub async fn add_to_table(&self, table: &str, ip: IpAddr) -> Result<()> {
        self.touch(table).await?;
        self.inner
            .pf
            .add_table_entry(table, ip)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Remove an address from a `plugin_*` table.
    pub async fn remove_from_table(&self, table: &str, ip: IpAddr) -> Result<()> {
        self.touch(table).await?;
        self.inner
            .pf
            .remove_table_entry(table, ip)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Atomically replace a `plugin_*` table's contents.
    pub async fn replace_table(&self, table: &str, entries: &[(IpAddr, u8)]) -> Result<()> {
        self.touch(table).await?;
        self.inner
            .pf
            .replace_table_entries(table, entries)
            .await
            .map_err(|e| PluginError::Table(e.to_string()))
    }

    /// Empty a `plugin_*` table.
    pub async fn flush_table(&self, table: &str) -> Result<()> {
        self.touch(table).await?;
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

    /// Flush every table this plugin touched — in this run or, per the
    /// persisted list, in an earlier one — and forget them (manager
    /// cleanup on stop).
    pub(crate) async fn flush_touched_tables(&self) {
        let mut tables: BTreeSet<String> = std::mem::take(&mut *lock(&self.inner.tables));
        match self.kv_get_json::<Vec<String>>(TABLES_KEY).await {
            Ok(Some(persisted)) => tables.extend(persisted),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(plugin = %self.inner.name, error = %e, "plugins: could not read table list")
            }
        }
        for t in &tables {
            if check_table_name(t).is_err() {
                continue;
            }
            if let Err(e) = self.inner.pf.flush_table(t).await {
                tracing::warn!(plugin = %self.inner.name, table = %t, error = %e, "plugin table flush failed");
            }
        }
        if !tables.is_empty()
            && let Err(e) = self.kv_delete(TABLES_KEY).await
        {
            tracing::warn!(plugin = %self.inner.name, error = %e, "plugins: could not clear table list");
        }
    }

    // ---- pf rules -------------------------------------------------------

    /// Replace this plugin's rules in the plugin anchor. Only `block` and
    /// `match` rules referencing `plugin_*` tables are accepted; see
    /// [`crate::rules::check_rule`].
    pub async fn set_rules(&self, rules: Vec<String>) -> Result<()> {
        self.ensure_active()?;
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

/// What [`PluginContext::for_tests`] hands a test: the context plus the
/// mock pf and database behind it, for assertions.
pub struct TestContext {
    /// The plugin's context
    pub ctx: PluginContext,
    /// The mock pf backend the context writes to
    pub pf: Arc<dyn PfBackend>,
    /// The database pool (plugin_kv lives here)
    pub pool: SqlitePool,
    _db: aifw_core::Database,
}
