use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Plugin manifest — read from plugin.toml in each plugin directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    /// "native" or "wasm"
    pub plugin_type: String,
    /// For WASM plugins: path to .wasm file relative to plugin dir
    pub wasm_file: Option<String>,
    /// Which hooks this plugin subscribes to
    pub hooks: Vec<String>,
    /// Default settings
    #[serde(default)]
    pub default_settings: std::collections::HashMap<String, serde_json::Value>,
}

/// A discovered plugin from the plugin directory
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPlugin {
    pub manifest: PluginManifest,
    pub path: PathBuf,
    pub installed: bool,
}

const PLUGIN_DIR: &str = "/usr/local/lib/aifw/plugins";

/// Discover all plugins in the plugin directory.
/// Each plugin is a subdirectory with a plugin.toml manifest.
pub fn discover_plugins() -> Vec<DiscoveredPlugin> {
    let dir = Path::new(PLUGIN_DIR);
    if !dir.exists() {
        return Vec::new();
    }

    let mut plugins = Vec::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let manifest_path = path.join("plugin.toml");
            if !manifest_path.exists() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&manifest_path)
                && let Ok(manifest) = toml::from_str::<PluginManifest>(&content)
            {
                plugins.push(DiscoveredPlugin {
                    manifest,
                    path: path.clone(),
                    installed: true,
                });
            }
        }
    }

    plugins
}

/// Ensure the plugin directory exists
pub fn ensure_plugin_dir() {
    let _ = std::fs::create_dir_all(PLUGIN_DIR);
}
