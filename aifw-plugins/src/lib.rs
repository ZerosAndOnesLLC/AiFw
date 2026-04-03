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
