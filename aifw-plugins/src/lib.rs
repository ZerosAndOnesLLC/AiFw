#![warn(missing_docs)]
//! # aifw-plugins
//!
//! Plugin subsystem: manages the lifecycle of native, in-tree plugins and
//! dispatches hook events (with `HookAction` responses such as `Block`)
//! at defined points like incoming API requests. See [`manager::PluginManager`].

/// [`PluginContext`] — the restricted firewall handle given to plugins (pf tables + shared KV store)
pub mod context;
/// Crate error type ([`PluginError`]) and `Result` alias
pub mod error;
/// Hook points, event payloads, and the [`HookAction`] responses plugins return
pub mod hooks;
/// [`PluginManager`] — registration, lifecycle, and hook dispatch
pub mod manager;
/// The [`Plugin`] trait plus plugin metadata, config, and state types
pub mod plugin;

#[cfg(test)]
mod tests;

pub use context::PluginContext;
pub use error::{PluginError, Result};
pub use hooks::{HookAction, HookEvent, HookPoint};
pub use manager::{DispatchSet, PluginManager};
pub use plugin::{Plugin, PluginConfig, PluginInfo, PluginState};
