//! # aifw-plugins
//!
//! Plugin subsystem: discovers, loads, and manages the lifecycle of plugins,
//! and dispatches hook events (with `HookAction` responses such as `Block`)
//! at defined points like incoming API requests. See [`manager::PluginManager`].

pub mod context;
pub mod discovery;
pub mod examples;
pub mod hooks;
pub mod manager;
pub mod plugin;
pub mod wasm;

#[cfg(test)]
mod tests;

pub use context::PluginContext;
pub use hooks::{HookAction, HookEvent, HookPoint};
pub use manager::PluginManager;
pub use plugin::{Plugin, PluginConfig, PluginInfo, PluginState};
