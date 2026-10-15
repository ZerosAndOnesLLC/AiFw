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
    /// Which hooks this plugin can receive. [`Plugin::hooks`] may narrow
    /// this per configuration; this list is what the UI shows.
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
    /// Arguments the action takes (rendered as a small form; may be empty).
    /// Only the field's key, label, kind and default matter here —
    /// `secret`, `group` and `visible_if` have no meaning for arguments.
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
    /// Enabled, but `start` failed — see `last_error`
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

/// A plugin as registered in [`crate::registry`]: its metadata, settings
/// schema and the way to start it. Implementors are stateless (usually a
/// unit struct); everything that belongs to a running plugin lives in the
/// [`PluginInstance`] that [`Plugin::start`] returns.
///
/// Lifecycle: the manager validates the stored settings, calls
/// [`Plugin::start`] with them, routes subscribed hook events to the
/// instance's [`PluginInstance::on_hook`], and calls
/// [`PluginInstance::shutdown`] on disable or settings change (a settings
/// change is a stop + fresh start). Background work goes through
/// [`PluginContext::spawn`] so it is cancelled on stop.
///
/// A minimal plugin:
///
/// ```ignore
/// pub struct Hello;
///
/// struct HelloRunning;
///
/// #[async_trait]
/// impl Plugin for Hello {
///     fn info(&self) -> PluginInfo { /* name, title, hooks: vec![HookPoint::Timer] … */ }
///     async fn start(&self, _s: &PluginSettings, ctx: &PluginContext) -> Result<Box<dyn PluginInstance>> {
///         ctx.info("hello");
///         Ok(Box::new(HelloRunning))
///     }
/// }
///
/// #[async_trait]
/// impl PluginInstance for HelloRunning {
///     async fn on_hook(&self, _e: &HookEvent, ctx: &PluginContext) -> HookAction {
///         ctx.info("tick");
///         HookAction::Continue
///     }
/// }
/// ```
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
    /// after schema validation on every settings write while the plugin
    /// is enabled, and when it is enabled. The message is shown to the
    /// operator.
    fn validate_settings(&self, _settings: &PluginSettings) -> Result<()> {
        Ok(())
    }

    /// Operator-triggered actions.
    fn actions(&self) -> Vec<ActionInfo> {
        Vec::new()
    }

    /// Hooks to deliver for a run with `settings`. Defaults to every hook
    /// in [`PluginInfo::hooks`]; override to skip event sources the
    /// operator turned off, so they stay idle.
    fn hooks(&self, _settings: &PluginSettings) -> Vec<HookPoint> {
        self.info().hooks
    }

    /// Start the plugin with its effective settings. An error leaves the
    /// plugin in the `error` state with the message shown to the operator.
    /// Must not wait on the network: schedule slow work with
    /// [`PluginContext::spawn`].
    async fn start(
        &self,
        settings: &PluginSettings,
        ctx: &PluginContext,
    ) -> Result<Box<dyn PluginInstance>>;
}

/// A running plugin, built by [`Plugin::start`] with its settings already
/// applied. Every method has a fully constructed `self`.
#[async_trait]
pub trait PluginInstance: Send + Sync + 'static {
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
