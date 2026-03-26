use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookPoint};

/// Information about a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// Which hooks this plugin wants to receive
    pub hooks: Vec<HookPoint>,
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    pub enabled: bool,
    pub settings: HashMap<String, serde_json::Value>,
}

impl PluginConfig {
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.settings.get(key).and_then(|v| v.as_str())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.settings.get(key).and_then(|v| v.as_u64())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.settings.get(key).and_then(|v| v.as_bool())
    }
}

/// Current state of a loaded plugin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginState {
    Loaded,
    Initialized,
    Running,
    Stopped,
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
    async fn init(&mut self, config: &PluginConfig, ctx: &PluginContext) -> Result<(), String>;

    /// Handle a hook event. Return an action to influence firewall behavior.
    async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction;

    /// Graceful shutdown
    async fn shutdown(&mut self) -> Result<(), String>;
}
