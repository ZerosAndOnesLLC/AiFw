#![warn(missing_docs)]
//! # aifw-plugins
//!
//! Native, in-tree plugins for AiFw. A plugin implements [`Plugin`], is
//! listed in [`registry`], and gets:
//!
//! - typed, validated settings ([`schema`]) rendered as a form in the UI
//!   and editable from the CLI, with secrets sealed at rest ([`store`]);
//! - hook events ([`hooks`]) delivered by the [`PluginManager`] with a time
//!   budget and panic isolation;
//! - a sandboxed [`PluginContext`]: an activity log, a persistent
//!   key/value store, cancellable background tasks, and pf access limited
//!   to `plugin_*` tables and `block`/`match` rules ([`rules`]).
//!
//! See `docs/plugins.md` for a walkthrough.

/// Built-in plugins shipped with AiFw
pub mod builtin;
/// [`PluginContext`] — the per-plugin, sandboxed handle into AiFw
pub mod context;
/// Crate error type ([`PluginError`]) and `Result` alias
pub mod error;
/// Hook points, event payloads, and the [`HookAction`] responses plugins return
pub mod hooks;
/// Outbound HTTP helpers with SSRF guards and size caps
pub mod http;
/// [`PluginManager`] — lifecycle, settings, and hook dispatch
pub mod manager;
/// The [`Plugin`] trait plus plugin metadata and state types
pub mod plugin;
/// The built-in plugin list
pub mod registry;
/// pf rules contributed by plugins, and their validation
pub mod rules;
/// Typed plugin settings
pub mod schema;
/// `plugin_config` persistence
pub mod store;

#[cfg(test)]
mod tests;

pub use context::{LogEntry, LogLevel, PluginContext};
pub use error::{PluginError, Result};
pub use hooks::{HookAction, HookEvent, HookEventData, HookPoint};
pub use manager::{DispatchOutcome, PluginDetail, PluginManager, PluginSummary, SettingsPatch};
pub use plugin::{ActionInfo, Plugin, PluginInfo, PluginState};
pub use schema::{FieldKind, ListItem, PluginSettings, SelectOption, SettingField};
