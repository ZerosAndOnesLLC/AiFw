use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::plugin::{Plugin, PluginConfig, PluginInfo, PluginState};

struct LoadedPlugin {
    plugin: Arc<dyn Plugin>,
    state: PluginState,
    info: PluginInfo,
}

/// A snapshot of the running plugins plus the shared context, detached from
/// the manager (PERF-H17 #361). Callers hold the manager lock only long
/// enough to clone Arcs via [`PluginManager::dispatch_set`], then dispatch
/// through the snapshot — so a slow plugin (e.g. a webhook HTTP POST) can't
/// block enable/disable, which needs the manager `write()` lock.
pub struct DispatchSet {
    plugins: Vec<(String, Vec<HookPoint>, Arc<dyn Plugin>)>,
    ctx: PluginContext,
}

impl DispatchSet {
    /// True if the snapshot contains no running plugins (dispatch would be a no-op)
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Dispatch a hook event to every snapshotted plugin subscribed to it.
    pub async fn dispatch(&self, event: &HookEvent) -> Vec<HookAction> {
        let mut actions = Vec::new();
        for (name, hooks, plugin) in &self.plugins {
            if !hooks.contains(&event.hook) {
                continue;
            }
            let action = plugin.on_hook(event, &self.ctx).await;
            if action != HookAction::Continue {
                tracing::debug!(plugin = %name, hook = %event.hook, "plugin returned action");
                actions.push(action);
            }
        }
        actions
    }
}

/// Manages the lifecycle of all loaded plugins
pub struct PluginManager {
    plugins: HashMap<String, LoadedPlugin>,
    ctx: PluginContext,
}

impl PluginManager {
    /// Create an empty manager; plugins are added via `register`
    pub fn new(ctx: PluginContext) -> Self {
        Self {
            plugins: HashMap::new(),
            ctx,
        }
    }

    /// Register a native Rust plugin
    pub async fn register(
        &mut self,
        plugin: Box<dyn Plugin>,
        config: PluginConfig,
    ) -> crate::Result<()> {
        let info = plugin.info();
        let name = info.name.clone();

        if self.plugins.contains_key(&name) {
            return Err(format!("plugin '{name}' already registered").into());
        }

        info!(plugin = %name, version = %info.version, "registering plugin");

        // init() needs `&mut`, so it runs on the Box before the plugin is
        // wrapped in the Arc that dispatch snapshots share.
        let mut plugin = plugin;
        let state = if config.enabled {
            match plugin.init(&config, &self.ctx).await {
                Ok(()) => {
                    info!(plugin = %name, "plugin initialized and running");
                    PluginState::Running
                }
                Err(e) => {
                    error!(plugin = %name, error = %e, "plugin init failed");
                    return Err(e);
                }
            }
        } else {
            PluginState::Stopped
        };

        self.plugins.insert(
            name,
            // `config` is consumed by init(); the plugin holds whatever
            // it needs from it, and the persisted copy lives in the DB.
            LoadedPlugin {
                plugin: Arc::from(plugin),
                state,
                info,
            },
        );
        Ok(())
    }

    /// Unload a plugin by name
    pub async fn unload(&mut self, name: &str) -> crate::Result<()> {
        let mut loaded = self
            .plugins
            .remove(name)
            .ok_or_else(|| format!("plugin '{name}' not found"))?;

        if loaded.state == PluginState::Running {
            // The plugin is already out of the map, so no new DispatchSet
            // can include it. shutdown() needs `&mut`, which Arc::get_mut
            // only yields once in-flight dispatch snapshots drop their
            // clones — wait bounded for that.
            let mut waited_ms = 0u32;
            loop {
                match Arc::get_mut(&mut loaded.plugin) {
                    Some(plugin) => {
                        if let Err(e) = plugin.shutdown().await {
                            warn!(plugin = %name, error = %e, "plugin shutdown error");
                        }
                        break;
                    }
                    None if waited_ms < 5_000 => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        waited_ms += 50;
                    }
                    None => {
                        warn!(plugin = %name, "shutdown skipped: dispatch still in flight after 5s");
                        break;
                    }
                }
            }
        }

        info!(plugin = %name, "plugin unloaded");
        Ok(())
    }

    /// Snapshot the running plugins for dispatch without holding the
    /// manager lock (PERF-H17 #361).
    pub fn dispatch_set(&self) -> DispatchSet {
        DispatchSet {
            plugins: self
                .plugins
                .iter()
                .filter(|(_, l)| l.state == PluginState::Running)
                .map(|(n, l)| (n.clone(), l.info.hooks.clone(), Arc::clone(&l.plugin)))
                .collect(),
            ctx: self.ctx.clone(),
        }
    }

    /// Dispatch a hook event to all plugins that are subscribed
    pub async fn dispatch(&self, event: &HookEvent) -> Vec<HookAction> {
        self.dispatch_set().dispatch(event).await
    }

    /// Get a list of all registered plugins and their states
    pub fn list_plugins(&self) -> Vec<(PluginInfo, PluginState)> {
        self.plugins
            .values()
            .map(|l| (l.info.clone(), l.state))
            .collect()
    }

    /// Get the number of registered plugins
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// Get the number of running plugins
    pub fn running_count(&self) -> usize {
        self.plugins
            .values()
            .filter(|l| l.state == PluginState::Running)
            .count()
    }

    /// Shutdown all plugins
    pub async fn shutdown_all(&mut self) {
        let names: Vec<String> = self.plugins.keys().cloned().collect();
        for name in names {
            let _ = self.unload(&name).await;
        }
    }
}
