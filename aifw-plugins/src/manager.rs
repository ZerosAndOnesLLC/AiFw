use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent};
use crate::plugin::{Plugin, PluginConfig, PluginInfo, PluginState};

struct LoadedPlugin {
    plugin: Box<dyn Plugin>,
    #[allow(dead_code)]
    config: PluginConfig,
    state: PluginState,
    info: PluginInfo,
}

/// Manages the lifecycle of all loaded plugins
pub struct PluginManager {
    plugins: HashMap<String, LoadedPlugin>,
    ctx: PluginContext,
}

impl PluginManager {
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
    ) -> Result<(), String> {
        let info = plugin.info();
        let name = info.name.clone();

        if self.plugins.contains_key(&name) {
            return Err(format!("plugin '{name}' already registered"));
        }

        info!(plugin = %name, version = %info.version, "registering plugin");

        let mut loaded = LoadedPlugin {
            plugin,
            config: config.clone(),
            state: PluginState::Loaded,
            info,
        };

        if config.enabled {
            match loaded.plugin.init(&config, &self.ctx).await {
                Ok(()) => {
                    loaded.state = PluginState::Running;
                    info!(plugin = %name, "plugin initialized and running");
                }
                Err(e) => {
                    loaded.state = PluginState::Error;
                    error!(plugin = %name, error = %e, "plugin init failed");
                    return Err(e);
                }
            }
        } else {
            loaded.state = PluginState::Stopped;
        }

        self.plugins.insert(name, loaded);
        Ok(())
    }

    /// Unload a plugin by name
    pub async fn unload(&mut self, name: &str) -> Result<(), String> {
        let mut loaded = self
            .plugins
            .remove(name)
            .ok_or_else(|| format!("plugin '{name}' not found"))?;

        if loaded.state == PluginState::Running
            && let Err(e) = loaded.plugin.shutdown().await
        {
            warn!(plugin = %name, error = %e, "plugin shutdown error");
        }

        info!(plugin = %name, "plugin unloaded");
        Ok(())
    }

    /// Dispatch a hook event to all plugins that are subscribed
    pub async fn dispatch(&self, event: &HookEvent) -> Vec<HookAction> {
        let mut actions = Vec::new();

        for (name, loaded) in &self.plugins {
            if loaded.state != PluginState::Running {
                continue;
            }
            if !loaded.info.hooks.contains(&event.hook) {
                continue;
            }

            let action = loaded.plugin.on_hook(event, &self.ctx).await;
            if action != HookAction::Continue {
                tracing::debug!(plugin = %name, hook = %event.hook, "plugin returned action");
                actions.push(action);
            }
        }

        actions
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
