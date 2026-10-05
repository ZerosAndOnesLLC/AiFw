use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::schema::{PluginSettings, SettingField};

/// Static metadata about a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin name (registration key, `[a-z0-9-]`)
    pub name: String,
    /// Display name shown in the UI
    pub title: String,
    /// Plugin version string
    pub version: String,
    /// What the plugin does, one or two sentences
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Which hooks this plugin wants to receive
    pub hooks: Vec<HookPoint>,
}

/// An operator-triggered action a plugin exposes (e.g. "Refresh now",
/// "Send test notification").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    /// Action id used in `POST /plugins/{name}/actions/{id}`
    pub id: String,
    /// Button label
    pub label: String,
    /// What the action does
    pub description: String,
    /// Arguments the action takes (rendered as a small form; may be empty)
    pub args: Vec<SettingField>,
}

impl ActionInfo {
    /// Action without arguments.
    pub fn new(id: &str, label: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            label: label.to_string(),
            description: description.to_string(),
            args: Vec::new(),
        }
    }

    /// Add an argument.
    pub fn arg(mut self, field: SettingField) -> Self {
        self.args.push(field);
        self
    }
}

/// Lifecycle state of a registered plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginState {
    /// Active and receiving hook events
    Running,
    /// Disabled; not receiving hooks
    Stopped,
    /// Enabled, but `init` failed — see `last_error`
    Error,
}

impl std::fmt::Display for PluginState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PluginState::Running => "running",
            PluginState::Stopped => "stopped",
            PluginState::Error => "error",
        })
    }
}

/// The plugin trait. Every built-in plugin implements it and is listed in
/// [`crate::registry`].
///
/// Lifecycle: the manager builds a fresh instance from the registry
/// factory, calls [`Plugin::init`] with the validated settings, routes
/// subscribed hook events to [`Plugin::on_hook`], and calls
/// [`Plugin::shutdown`] on disable or settings change (a settings change is
/// a stop + fresh start). Background work goes through
/// [`PluginContext::spawn`] so it is cancelled on stop.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    /// Static metadata.
    fn info(&self) -> PluginInfo;

    /// Settings the plugin accepts. The store validates every write
    /// against this and the UI renders its form from it.
    fn settings_schema(&self) -> Vec<SettingField> {
        Vec::new()
    }

    /// Cross-field checks that the per-field schema can't express. Runs
    /// after schema validation on every settings write.
    fn validate_settings(&self, _settings: &PluginSettings) -> Result<()> {
        Ok(())
    }

    /// Operator-triggered actions.
    fn actions(&self) -> Vec<ActionInfo> {
        Vec::new()
    }

    /// Start the plugin with its effective settings. An error leaves the
    /// plugin in the `error` state with the message shown to the operator.
    async fn init(&mut self, settings: &PluginSettings, ctx: &PluginContext) -> Result<()>;

    /// Handle a subscribed hook event. Must be quick: dispatch has a time
    /// budget; push slow work to a task started with `ctx.spawn`.
    async fn on_hook(&self, _event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        HookAction::Continue
    }

    /// Run an action declared in [`Plugin::actions`]. Returns JSON shown
    /// to the operator.
    async fn run_action(&self, action: &str, _args: Value, _ctx: &PluginContext) -> Result<Value> {
        Err(PluginError::NotFound(format!("action '{action}'")))
    }

    /// Plugin-specific live status for the UI (JSON object).
    async fn status(&self, _ctx: &PluginContext) -> Value {
        Value::Null
    }

    /// Release resources. Spawned tasks, pf rules and touched tables are
    /// cleaned up by the manager after this returns.
    async fn shutdown(&self, _ctx: &PluginContext) -> Result<()> {
        Ok(())
    }
}
