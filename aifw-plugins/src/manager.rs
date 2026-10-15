use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use sqlx::SqlitePool;
use tokio::task::JoinSet;

use crate::context::{LogEntry, LogLevel, PluginContext};
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::plugin::{ActionInfo, Plugin, PluginInfo, PluginInstance, PluginState};
use crate::registry;
use crate::rules::RuleSink;
use crate::schema::{self, SettingField};
use crate::store::{PluginStore, StoredConfig};

/// Per-plugin budget for one `on_hook` call.
const HOOK_TIMEOUT: Duration = Duration::from_secs(5);
/// `ApiRequest` sits in the request path of every authenticated call.
const API_HOOK_TIMEOUT: Duration = Duration::from_millis(250);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const ACTION_TIMEOUT: Duration = Duration::from_secs(120);
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds on `HookAction::Multi` so one reply can't fan out unboundedly.
const MAX_MULTI_DEPTH: usize = 4;
const MAX_ACTIONS_PER_REPLY: usize = 64;

/// Counters for one plugin since the API started.
#[derive(Default)]
struct Stats {
    events: AtomicU64,
    actions: AtomicU64,
    errors: AtomicU64,
    timeouts: AtomicU64,
    panics: AtomicU64,
    last_event_ms: AtomicI64,
    last_latency_us: AtomicU64,
    total_latency_us: AtomicU64,
}

/// Snapshot of a plugin's dispatch counters.
#[derive(Debug, Clone, Serialize)]
pub struct PluginStats {
    /// Hook events delivered
    pub events: u64,
    /// Non-`Continue` actions applied
    pub actions: u64,
    /// Actions that failed to apply (e.g. denied table)
    pub errors: u64,
    /// `on_hook` calls that exceeded their budget
    pub timeouts: u64,
    /// `on_hook` calls that panicked
    pub panics: u64,
    /// Last delivered event
    pub last_event_at: Option<DateTime<Utc>>,
    /// Mean `on_hook` latency
    pub avg_latency_us: u64,
    /// Most recent `on_hook` latency
    pub last_latency_us: u64,
}

impl Stats {
    fn snapshot(&self) -> PluginStats {
        let events = self.events.load(Ordering::Relaxed);
        let last_ms = self.last_event_ms.load(Ordering::Relaxed);
        PluginStats {
            events,
            actions: self.actions.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            panics: self.panics.load(Ordering::Relaxed),
            last_event_at: (last_ms > 0)
                .then(|| DateTime::from_timestamp_millis(last_ms))
                .flatten(),
            avg_latency_us: self
                .total_latency_us
                .load(Ordering::Relaxed)
                .checked_div(events)
                .unwrap_or(0),
            last_latency_us: self.last_latency_us.load(Ordering::Relaxed),
        }
    }
}

/// Cheap-to-read lifecycle snapshot.
struct Status {
    state: PluginState,
    enabled: bool,
    last_error: Option<String>,
    started_at: Option<DateTime<Utc>>,
}

/// A started plugin and the hooks it asked for with its settings.
#[derive(Clone)]
struct Running {
    inst: Arc<dyn PluginInstance>,
    hooks: Vec<HookPoint>,
    mask: u32,
}

struct Entry {
    plugin: Arc<dyn Plugin>,
    info: PluginInfo,
    schema: Vec<SettingField>,
    actions: Vec<ActionInfo>,
    ctx: PluginContext,
    stats: Stats,
    /// Serializes every config write and start/stop for this plugin;
    /// holds the config marker last applied (reconcile compares it with
    /// the store).
    life: tokio::sync::Mutex<Option<String>>,
    running: RwLock<Option<Running>>,
    status: Mutex<Status>,
}

impl Entry {
    fn running(&self) -> Option<Running> {
        self.running
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn instance(&self) -> Option<Arc<dyn PluginInstance>> {
        self.running().map(|r| r.inst)
    }

    fn status(&self) -> MutexGuard<'_, Status> {
        self.status.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// List view of one plugin.
#[derive(Debug, Clone, Serialize)]
pub struct PluginSummary {
    /// Registration key
    pub name: String,
    /// Display name
    pub title: String,
    /// Version
    pub version: String,
    /// Description
    pub description: String,
    /// Author
    pub author: String,
    /// Hooks in use: the running instance's, or the plugin's full list
    /// while stopped
    pub hooks: Vec<HookPoint>,
    /// Lifecycle state
    pub state: PluginState,
    /// Operator wants it running
    pub enabled: bool,
    /// Why it isn't running, when `state == error`
    pub last_error: Option<String>,
    /// When the current run started
    pub started_at: Option<DateTime<Utc>>,
    /// Dispatch counters
    pub stats: PluginStats,
}

/// Full view of one plugin for its settings page.
#[derive(Debug, Clone, Serialize)]
pub struct PluginDetail {
    /// Summary fields
    #[serde(flatten)]
    pub summary: PluginSummary,
    /// Settings schema
    pub schema: Vec<SettingField>,
    /// Non-secret values the operator set (defaults omitted)
    pub values: Map<String, Value>,
    /// Effective non-secret settings (operator values over defaults)
    pub effective: Map<String, Value>,
    /// Secret keys that currently have a value (values never returned)
    pub secrets_set: Vec<String>,
    /// Operator actions
    pub actions: Vec<ActionInfo>,
    /// pf rules the plugin currently has loaded
    pub rules: Vec<String>,
}

/// Partial settings update. A `null` value resets a setting to its
/// default / clears a secret; absent keys are left unchanged.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct SettingsPatch {
    /// Non-secret settings
    #[serde(default)]
    pub values: Map<String, Value>,
    /// Secret settings
    #[serde(default)]
    pub secrets: Map<String, Value>,
}

/// Result of dispatching one event.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// A plugin returned `Block` for an `ApiRequest`
    pub blocked: bool,
}

fn hook_bit(h: HookPoint) -> u32 {
    1 << (h as u32)
}

fn hook_mask(hooks: &[HookPoint]) -> u32 {
    hooks.iter().fold(0, |m, h| m | hook_bit(*h))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Run `fut` to completion on its own task. Lifecycle work runs this way
/// so a client that disconnects mid-request (axum drops the handler
/// future) can't leave a plugin half stopped or half started.
async fn detached<T: Send + 'static>(fut: impl Future<Output = T> + Send + 'static) -> Result<T> {
    tokio::spawn(fut).await.map_err(|e| {
        PluginError::Plugin(if e.is_panic() {
            "plugin lifecycle task panicked".into()
        } else {
            "plugin lifecycle task cancelled".into()
        })
    })
}

struct Core {
    store: PluginStore,
    rules: Arc<RuleSink>,
    entries: BTreeMap<String, Arc<Entry>>,
    /// Registry order, for display.
    order: Vec<String>,
    hook_mask: AtomicU32,
}

/// Owns every registered plugin: lifecycle, settings, dispatch.
pub struct PluginManager {
    core: Arc<Core>,
}

impl PluginManager {
    /// Manager over the built-in plugins in [`crate::registry`].
    pub fn new(pf: Arc<dyn PfBackend>, pool: SqlitePool) -> Result<Self> {
        Self::with_plugins(pf, pool, registry::builtins())
    }

    /// Manager over an explicit plugin list (tests).
    pub fn with_plugins(
        pf: Arc<dyn PfBackend>,
        pool: SqlitePool,
        plugins: Vec<Arc<dyn Plugin>>,
    ) -> Result<Self> {
        let rules = Arc::new(RuleSink::new(pf.clone(), aifw_common::anchors::PLUGINS));
        let mut entries = BTreeMap::new();
        let mut order = Vec::new();
        for plugin in plugins {
            let info = plugin.info();
            if !valid_name(&info.name) {
                return Err(PluginError::Plugin(format!(
                    "invalid plugin name '{}' (use [a-z0-9-])",
                    info.name
                )));
            }
            if entries.contains_key(&info.name) {
                return Err(PluginError::Plugin(format!(
                    "plugin '{}' registered twice",
                    info.name
                )));
            }
            let entry = Entry {
                ctx: PluginContext::new(&info.name, pf.clone(), pool.clone(), rules.clone()),
                schema: plugin.settings_schema(),
                actions: plugin.actions(),
                plugin,
                info: info.clone(),
                stats: Stats::default(),
                life: tokio::sync::Mutex::new(None),
                running: RwLock::new(None),
                status: Mutex::new(Status {
                    state: PluginState::Stopped,
                    enabled: false,
                    last_error: None,
                    started_at: None,
                }),
            };
            order.push(info.name.clone());
            entries.insert(info.name, Arc::new(entry));
        }
        Ok(Self {
            core: Arc::new(Core {
                store: PluginStore::new(pool),
                rules,
                entries,
                order,
                hook_mask: AtomicU32::new(0),
            }),
        })
    }

    /// The config store backing this manager.
    pub fn store(&self) -> &PluginStore {
        &self.core.store
    }

    fn entry(&self, name: &str) -> Result<Arc<Entry>> {
        self.core.entry(name).cloned()
    }

    /// Settings schema of a registered plugin.
    pub fn schema(&self, name: &str) -> Result<&[SettingField]> {
        Ok(&self.core.entry(name)?.schema)
    }

    // ---- lifecycle --------------------------------------------------------

    /// Boot: clear the plugin anchor and start every plugin enabled in the
    /// store.
    pub async fn start(&self) {
        if let Err(e) = self.core.rules.reload().await {
            tracing::warn!(error = %e, "plugins: resetting plugin anchor failed");
        }
        for entry in self.core.entries.values() {
            let mut life = entry.life.lock().await;
            self.core.apply_locked(entry, &mut life).await;
        }
        tracing::info!(
            plugins = self.core.entries.len(),
            running = self.running_count(),
            "plugin system started"
        );
    }

    /// Apply config changes written by another path (CLI, restore, cluster
    /// sync): any plugin whose stored marker differs from the applied one
    /// is restarted with the stored config.
    pub async fn reconcile(&self) {
        for entry in self.core.entries.values() {
            let stored = match self.core.store.updated_at(&entry.info.name).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(plugin = %entry.info.name, error = %e, "plugins: reconcile read failed");
                    continue;
                }
            };
            let mut life = entry.life.lock().await;
            if stored != *life {
                self.core.apply_locked(entry, &mut life).await;
            }
        }
    }

    // ---- operator changes ---------------------------------------------

    /// Enable or disable a plugin. Enabling validates the current settings
    /// first so a plugin that can't start says why instead of flipping to
    /// `error`. Asking for the state it already has changes nothing.
    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<PluginSummary> {
        let core = self.core.clone();
        let entry = self.entry(name)?;
        detached(async move {
            let mut life = entry.life.lock().await;
            let mut cfg = core.store.load(&entry.info.name).await?;
            // Already in that state: nothing to restart. A plugin stuck in
            // `error` is the exception — asking again is a retry.
            if cfg.enabled == enabled && entry.status().state != PluginState::Error {
                return Ok(core.summary(&entry));
            }
            cfg.set_enabled(&*entry.plugin, enabled)?;
            core.store.save(&entry.info.name, &cfg).await?;
            core.apply_locked(&entry, &mut life).await;
            Ok(core.summary(&entry))
        })
        .await?
    }

    /// Merge, validate and persist a settings change; a running plugin is
    /// restarted with the new settings. A patch that changes nothing is a
    /// no-op.
    pub async fn update_settings(&self, name: &str, patch: SettingsPatch) -> Result<PluginDetail> {
        let core = self.core.clone();
        let entry = self.entry(name)?;
        detached(async move {
            let mut life = entry.life.lock().await;
            let mut cfg = core.store.load(&entry.info.name).await?;
            let before = cfg.clone();
            cfg.apply_patch(&*entry.plugin, patch)?;
            if cfg.values == before.values
                && cfg.secrets == before.secrets
                && before.updated_at.is_some()
                && entry.status().state != PluginState::Error
            {
                return core.detail(&entry).await;
            }
            core.store.save(&entry.info.name, &cfg).await?;
            core.apply_locked(&entry, &mut life).await;
            core.detail(&entry).await
        })
        .await?
    }

    /// Stop the plugin, empty its pf tables, and forget every setting,
    /// secret and stored value.
    pub async fn reset(&self, name: &str) -> Result<PluginSummary> {
        let core = self.core.clone();
        let entry = self.entry(name)?;
        detached(async move {
            let mut life = entry.life.lock().await;
            core.stop_locked(&entry, true).await;
            core.store.reset(&entry.info.name).await?;
            entry.status().enabled = false;
            *life = None;
            Ok(core.summary(&entry))
        })
        .await?
    }

    /// Run an operator action on a running plugin.
    pub async fn run_action(&self, name: &str, action: &str, args: Value) -> Result<Value> {
        let entry = self.entry(name)?;
        let info = entry
            .actions
            .iter()
            .find(|a| a.id == action)
            .ok_or_else(|| PluginError::NotFound(format!("action '{action}' on '{name}'")))?;
        let args = match args {
            Value::Null => Map::new(),
            Value::Object(m) => m,
            _ => {
                return Err(PluginError::Validation(
                    "action arguments must be an object".into(),
                ));
            }
        };
        let (args, _) = schema::normalize(&info.args, &args, &Map::new())?;
        let args = Value::Object(schema::effective(&info.args, &args, &Map::new()).into_map());
        let inst = entry.instance().ok_or_else(|| {
            PluginError::Validation(format!(
                "'{}' is not running; enable it first",
                entry.info.title
            ))
        })?;
        let ctx = entry.ctx.clone();
        let action_id = action.to_string();
        let task = tokio::spawn(async move {
            tokio::time::timeout(ACTION_TIMEOUT, inst.run_action(&action_id, args, &ctx)).await
        });
        let label = &info.label;
        match task.await {
            Ok(Ok(Ok(v))) => {
                entry.ctx.info(format!("action '{label}' completed"));
                Ok(v)
            }
            Ok(Ok(Err(e))) => {
                // A bad argument is the operator's typo, not a plugin
                // problem — keep it out of the warning count.
                if matches!(e, PluginError::Validation(_)) {
                    entry.ctx.info(format!("action '{label}' refused: {e}"));
                } else {
                    entry.ctx.warn(format!("action '{label}' failed: {e}"));
                }
                Err(e)
            }
            Ok(Err(_)) => Err(PluginError::Timeout(format!("action '{label}'"))),
            Err(_) => {
                entry.ctx.error(format!("action '{label}' panicked"));
                Err(PluginError::Plugin(format!("action '{label}' crashed")))
            }
        }
    }

    // ---- views ----------------------------------------------------------

    /// Every registered plugin.
    pub fn list(&self) -> Vec<PluginSummary> {
        self.core
            .order
            .iter()
            .filter_map(|n| self.core.entries.get(n))
            .map(|e| self.core.summary(e))
            .collect()
    }

    /// One plugin's summary.
    pub fn get(&self, name: &str) -> Result<PluginSummary> {
        Ok(self.core.summary(self.core.entry(name)?))
    }

    /// One plugin's full detail.
    pub async fn detail(&self, name: &str) -> Result<PluginDetail> {
        self.core.detail(self.core.entry(name)?).await
    }

    /// Plugin-specific live status (`null` when not running).
    pub async fn status(&self, name: &str) -> Result<Value> {
        let entry = self.entry(name)?;
        let Some(inst) = entry.instance() else {
            return Ok(Value::Null);
        };
        let ctx = entry.ctx.clone();
        let task =
            tokio::spawn(
                async move { tokio::time::timeout(STATUS_TIMEOUT, inst.status(&ctx)).await },
            );
        match task.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => Err(PluginError::Timeout("status".into())),
            Err(_) => Err(PluginError::Plugin("status crashed".into())),
        }
    }

    /// Newest-first activity log.
    pub fn logs(&self, name: &str, limit: usize, min_level: LogLevel) -> Result<Vec<LogEntry>> {
        Ok(self.core.entry(name)?.ctx.recent_logs(limit, min_level))
    }

    /// Number of registered plugins.
    pub fn count(&self) -> usize {
        self.core.entries.len()
    }

    /// Number of running plugins.
    pub fn running_count(&self) -> usize {
        self.core
            .entries
            .values()
            .filter(|e| e.instance().is_some())
            .count()
    }

    // ---- dispatch -------------------------------------------------------

    /// True when at least one running plugin subscribes to `hook`. Event
    /// sources check this before doing any work.
    pub fn wants(&self, hook: HookPoint) -> bool {
        self.core.hook_mask.load(Ordering::Relaxed) & hook_bit(hook) != 0
    }

    /// Deliver `event` to every running subscriber concurrently, each under
    /// a time budget and isolated from panics, then apply the returned
    /// actions through the plugin's own (sandboxed) context.
    pub async fn dispatch(&self, event: HookEvent) -> DispatchOutcome {
        let mut outcome = DispatchOutcome::default();
        if !self.wants(event.hook) {
            return outcome;
        }
        let budget = if event.hook == HookPoint::ApiRequest {
            API_HOOK_TIMEOUT
        } else {
            HOOK_TIMEOUT
        };
        let bit = hook_bit(event.hook);
        let event = Arc::new(event);
        let mut set = JoinSet::new();
        let mut owners = std::collections::HashMap::new();
        for entry in self.core.entries.values() {
            let Some(running) = entry.running() else {
                continue;
            };
            if running.mask & bit == 0 {
                continue;
            }
            let inst = running.inst;
            let ctx = entry.ctx.clone();
            let ev = event.clone();
            let handle = set.spawn(async move {
                let started = Instant::now();
                let r = tokio::time::timeout(budget, inst.on_hook(&ev, &ctx)).await;
                (r, started.elapsed())
            });
            owners.insert(handle.id(), entry.clone());
        }
        while let Some(joined) = set.join_next_with_id().await {
            let (id, result) = match joined {
                Ok((id, r)) => (id, Ok(r)),
                Err(e) => (e.id(), Err(e)),
            };
            let Some(entry) = owners.get(&id) else {
                continue;
            };
            let stats = &entry.stats;
            stats.events.fetch_add(1, Ordering::Relaxed);
            stats
                .last_event_ms
                .store(Utc::now().timestamp_millis(), Ordering::Relaxed);
            match result {
                Ok((Ok(action), elapsed)) => {
                    let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
                    stats.last_latency_us.store(us, Ordering::Relaxed);
                    stats.total_latency_us.fetch_add(us, Ordering::Relaxed);
                    let mut budget = MAX_ACTIONS_PER_REPLY;
                    apply_action(entry, event.hook, action, 0, &mut budget, &mut outcome).await;
                }
                Ok((Err(_), _)) => {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    entry.ctx.warn(format!(
                        "{} hook took longer than {}ms; skipped",
                        event.hook,
                        budget.as_millis()
                    ));
                }
                Err(_) => {
                    stats.panics.fetch_add(1, Ordering::Relaxed);
                    entry.ctx.error(format!("{} hook panicked", event.hook));
                }
            }
        }
        outcome
    }
}

impl Core {
    fn entry(&self, name: &str) -> Result<&Arc<Entry>> {
        self.entries
            .get(name)
            .ok_or_else(|| PluginError::NotFound(format!("plugin '{name}'")))
    }

    /// Stop the plugin and, if the stored config says enabled, start it
    /// fresh with the stored settings. The caller holds `entry.life`.
    async fn apply_locked(&self, entry: &Arc<Entry>, life: &mut Option<String>) {
        let cfg = match self.store.load(&entry.info.name).await {
            Ok(c) => c,
            Err(e) => {
                // Reconcile retries every few seconds; log the failure
                // once, not once per retry.
                let msg = format!("could not load configuration: {e}");
                let changed = {
                    let mut st = entry.status();
                    let changed = st.last_error.as_deref() != Some(msg.as_str());
                    st.state = PluginState::Error;
                    st.last_error = Some(msg.clone());
                    changed
                };
                if changed {
                    entry.ctx.error(msg);
                }
                return;
            }
        };
        // A disabled plugin gets its pf leftovers removed even when nothing
        // is running here — the CLI may have disabled it while the API was
        // down, leaving its tables filled.
        self.stop_locked(entry, !cfg.enabled).await;
        entry.status().enabled = cfg.enabled;
        if cfg.enabled {
            self.start_locked(entry, &cfg).await;
        }
        *life = cfg.updated_at;
    }

    async fn start_locked(&self, entry: &Arc<Entry>, cfg: &StoredConfig) {
        let settings = schema::effective(&entry.schema, &cfg.values, &cfg.secrets);
        let plugin = entry.plugin.clone();
        let ctx = entry.ctx.clone();
        let result = match plugin.validate_settings(&settings) {
            Err(e) => Err(e.to_string()),
            Ok(()) => {
                let hooks = plugin.hooks(&settings);
                entry.ctx.activate();
                // start runs in its own task so a panicking plugin can't
                // take the caller (boot, an API handler) down with it.
                let task = tokio::spawn(async move {
                    tokio::time::timeout(START_TIMEOUT, plugin.start(&settings, &ctx)).await
                });
                match task.await {
                    Ok(Ok(Ok(inst))) => Ok((inst, hooks)),
                    Ok(Ok(Err(e))) => Err(e.to_string()),
                    Ok(Err(_)) => Err(format!(
                        "start did not finish within {}s",
                        START_TIMEOUT.as_secs()
                    )),
                    Err(e) if e.is_panic() => Err("start panicked".to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
        };
        match result {
            Ok((inst, hooks)) => {
                let mask = hook_mask(&hooks);
                *entry.running.write().unwrap_or_else(|e| e.into_inner()) = Some(Running {
                    inst: Arc::from(inst),
                    hooks,
                    mask,
                });
                {
                    let mut st = entry.status();
                    st.state = PluginState::Running;
                    st.last_error = None;
                    st.started_at = Some(Utc::now());
                }
                entry.ctx.info("started");
            }
            Err(msg) => {
                entry.ctx.error(format!("failed to start: {msg}"));
                // Undo whatever a half-finished start left behind.
                Self::cleanup(&entry.ctx).await;
                entry.ctx.deactivate();
                let mut st = entry.status();
                st.state = PluginState::Error;
                st.last_error = Some(msg);
                st.started_at = None;
            }
        }
        self.recompute_mask();
    }

    /// Stop a running instance and remove its pf effects. With
    /// `cleanup_if_idle`, pf leftovers (persisted table list, rules) are
    /// removed even when no instance is running.
    async fn stop_locked(&self, entry: &Arc<Entry>, cleanup_if_idle: bool) {
        let running = entry
            .running
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        {
            let mut st = entry.status();
            st.state = PluginState::Stopped;
            st.last_error = None;
            st.started_at = None;
        }
        self.recompute_mask();
        entry.ctx.deactivate();
        let Some(running) = running else {
            if cleanup_if_idle {
                Self::cleanup(&entry.ctx).await;
            }
            return;
        };
        entry.ctx.abort_tasks();
        let ctx = entry.ctx.clone();
        let inst = running.inst;
        let task = tokio::spawn(async move {
            tokio::time::timeout(SHUTDOWN_TIMEOUT, inst.shutdown(&ctx)).await
        });
        match task.await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => entry.ctx.warn(format!("shutdown error: {e}")),
            Ok(Err(_)) => entry.ctx.warn("shutdown timed out"),
            Err(_) => entry.ctx.warn("shutdown panicked"),
        }
        Self::cleanup(&entry.ctx).await;
        entry.ctx.info("stopped");
    }

    /// Remove every pf effect of a plugin: tasks, rules, table contents.
    async fn cleanup(ctx: &PluginContext) {
        ctx.abort_tasks();
        if let Err(e) = ctx.clear_rules().await {
            ctx.warn(format!("removing pf rules failed: {e}"));
        }
        ctx.flush_touched_tables().await;
    }

    fn recompute_mask(&self) {
        let mask = self
            .entries
            .values()
            .filter_map(|e| e.running().map(|r| r.mask))
            .fold(0, |m, b| m | b);
        self.hook_mask.store(mask, Ordering::Relaxed);
    }

    fn summary(&self, entry: &Entry) -> PluginSummary {
        let hooks = entry
            .running()
            .map(|r| r.hooks)
            .unwrap_or_else(|| entry.info.hooks.clone());
        let st = entry.status();
        PluginSummary {
            name: entry.info.name.clone(),
            title: entry.info.title.clone(),
            version: entry.info.version.clone(),
            description: entry.info.description.clone(),
            author: entry.info.author.clone(),
            hooks,
            state: st.state,
            enabled: st.enabled,
            last_error: st.last_error.clone(),
            started_at: st.started_at,
            stats: entry.stats.snapshot(),
        }
    }

    async fn detail(&self, entry: &Entry) -> Result<PluginDetail> {
        let cfg = self.store.load(&entry.info.name).await?;
        let effective = schema::effective(&entry.schema, &cfg.values, &Map::new());
        let mut effective = effective.into_map();
        let mut secrets_set = Vec::new();
        for f in entry.schema.iter().filter(|f| f.secret) {
            effective.remove(&f.key);
            if cfg
                .secrets
                .get(&f.key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            {
                secrets_set.push(f.key.clone());
            }
        }
        Ok(PluginDetail {
            summary: self.summary(entry),
            schema: entry.schema.clone(),
            values: cfg.values,
            effective,
            secrets_set,
            actions: entry.actions.clone(),
            rules: entry.ctx.rules().await,
        })
    }
}

/// Apply one plugin reply. Boxed for the `Multi` recursion.
fn apply_action<'a>(
    entry: &'a Entry,
    hook: HookPoint,
    action: HookAction,
    depth: usize,
    budget: &'a mut usize,
    outcome: &'a mut DispatchOutcome,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if matches!(action, HookAction::Continue) {
            return;
        }
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let stats = &entry.stats;
        let ctx = &entry.ctx;
        match action {
            HookAction::Continue => {}
            HookAction::Block => {
                stats.actions.fetch_add(1, Ordering::Relaxed);
                if hook == HookPoint::ApiRequest {
                    outcome.blocked = true;
                }
            }
            HookAction::Log(msg) => {
                stats.actions.fetch_add(1, Ordering::Relaxed);
                ctx.info(msg);
            }
            HookAction::AddToTable { table, ip } => {
                stats.actions.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = ctx.add_to_table(&table, ip).await {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    ctx.warn(format!("add {ip} to <{table}> failed: {e}"));
                }
            }
            HookAction::RemoveFromTable { table, ip } => {
                stats.actions.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = ctx.remove_from_table(&table, ip).await {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    ctx.warn(format!("remove {ip} from <{table}> failed: {e}"));
                }
            }
            HookAction::Multi(list) => {
                if depth >= MAX_MULTI_DEPTH {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                    ctx.warn("Multi action nested too deeply; ignored");
                    return;
                }
                for a in list {
                    apply_action(entry, hook, a, depth + 1, budget, outcome).await;
                }
            }
        }
    })
}
