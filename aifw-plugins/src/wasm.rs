use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::plugin::{Plugin, PluginConfig, PluginInfo, PluginState};

/// Configuration for a WASM plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPluginConfig {
    /// Path to the .wasm file
    pub wasm_path: PathBuf,
    /// Plugin name (derived from filename if not set)
    pub name: Option<String>,
    /// Memory limit in bytes (default 16MB)
    pub memory_limit: Option<usize>,
    /// Fuel limit for execution (default 1_000_000)
    pub fuel_limit: Option<u64>,
    /// Which hooks to subscribe to
    pub hooks: Vec<HookPoint>,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            wasm_path: PathBuf::new(),
            name: None,
            memory_limit: Some(16 * 1024 * 1024),
            fuel_limit: Some(1_000_000),
            hooks: Vec::new(),
        }
    }
}

/// A WASM sandboxed plugin.
///
/// This is the plugin wrapper that loads a .wasm module and provides
/// sandboxed execution. The WASM module must export these functions:
///
/// - `plugin_info() -> *const u8` — returns JSON PluginInfo
/// - `plugin_init(config_ptr: *const u8, config_len: u32) -> i32`
/// - `plugin_on_hook(event_ptr: *const u8, event_len: u32) -> *const u8`
/// - `plugin_shutdown() -> i32`
///
/// Currently uses a stub implementation. Real wasmtime integration
/// can be enabled via the `wasmtime` feature flag.
pub struct WasmPlugin {
    config: WasmPluginConfig,
    info: PluginInfo,
    state: PluginState,
}

impl WasmPlugin {
    pub fn new(config: WasmPluginConfig) -> Self {
        let name = config
            .name
            .clone()
            .unwrap_or_else(|| {
                config
                    .wasm_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unnamed-wasm".to_string())
            });

        Self {
            info: PluginInfo {
                name,
                version: "0.0.0".to_string(),
                description: format!("WASM plugin from {:?}", config.wasm_path),
                author: "unknown".to_string(),
                hooks: config.hooks.clone(),
            },
            config,
            state: PluginState::Loaded,
        }
    }

    pub fn state(&self) -> PluginState {
        self.state
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn info(&self) -> PluginInfo {
        self.info.clone()
    }

    async fn init(&mut self, _config: &PluginConfig, _ctx: &PluginContext) -> Result<(), String> {
        // WASM sandbox is not yet implemented — refuse to load WASM plugins
        // to prevent running untrusted code without proper isolation.
        if !self.config.wasm_path.as_os_str().is_empty() {
            tracing::warn!(
                wasm = ?self.config.wasm_path,
                "WASM plugin loading is disabled — sandbox not implemented"
            );
            return Err("WASM plugin loading is disabled: sandbox not yet implemented. Only native Rust plugins are supported.".to_string());
        }
        self.state = PluginState::Running;
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        // In a real implementation, this would:
        // 1. Serialize the event to JSON
        // 2. Copy into WASM linear memory
        // 3. Call plugin_on_hook() export
        // 4. Read the HookAction result from WASM memory
        tracing::trace!(
            plugin = %self.info.name,
            hook = %event.hook,
            "WASM hook (stub)"
        );
        HookAction::Continue
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        self.state = PluginState::Stopped;
        Ok(())
    }
}

/// Host functions that would be exported to WASM modules.
/// These define the WASM plugin API contract.
pub mod host_functions {
    /// Log a message from the WASM plugin
    pub const LOG: &str = "aifw_log";
    /// Add an IP to a pf table
    pub const ADD_TO_TABLE: &str = "aifw_add_to_table";
    /// Remove an IP from a pf table
    pub const REMOVE_FROM_TABLE: &str = "aifw_remove_from_table";
    /// Get a config value
    pub const GET_CONFIG: &str = "aifw_get_config";
    /// Store a value in the shared plugin store
    pub const STORE_SET: &str = "aifw_store_set";
    /// Get a value from the shared plugin store
    pub const STORE_GET: &str = "aifw_store_get";
}
