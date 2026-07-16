use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookPoint};

/// Information about a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin name (registration key)
    pub name: String,
    /// Plugin version string
    pub version: String,
    /// Human-readable description of what the plugin does
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Which hooks this plugin wants to receive
    pub hooks: Vec<HookPoint>,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    /// Whether to initialize and run the plugin on registration
    pub enabled: bool,
    /// Free-form plugin settings (read via `get_str`/`get_u64`/`get_bool`)
    pub settings: HashMap<String, serde_json::Value>,
}

impl PluginConfig {
    /// Setting as a string; `None` if the key is missing or not a JSON string
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(|v| v.as_str())
    }

    /// Setting as a u64; `None` if the key is missing or not an unsigned JSON number
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.settings.get(key).and_then(|v| v.as_u64())
    }

    /// Setting as a bool; `None` if the key is missing or not a JSON boolean
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.settings.get(key).and_then(|v| v.as_bool())
    }
}

/// Current state of a loaded plugin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginState {
    /// Registered but not yet initialized
    Loaded,
    /// `init` completed but the plugin is not yet receiving hooks
    Initialized,
    /// Active and receiving hook events
    Running,
    /// Disabled or shut down; not receiving hooks
    Stopped,
    /// Initialization or runtime failure
    Error,
}

impl std::fmt::Display for PluginState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginState::Loaded => write!(f, "loaded"),
            PluginState::Initialized => write!(f, "initialized"),
            PluginState::Running => write!(f, "running"),
            PluginState::Stopped => write!(f, "stopped"),
            PluginState::Error => write!(f, "error"),
        }
    }
}

/// The core plugin trait. All native plugins implement this.
#[async_trait]
pub trait Plugin: Send + Sync {
    /// Return plugin metadata
    fn info(&self) -> PluginInfo;

    /// Initialize the plugin with its configuration
    async fn init(&mut self, config: &PluginConfig, ctx: &PluginContext) -> crate::Result<()>;

    /// Handle a hook event. Return an action to influence firewall behavior.
    async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction;

    /// Graceful shutdown
    async fn shutdown(&mut self) -> crate::Result<()>;
}
