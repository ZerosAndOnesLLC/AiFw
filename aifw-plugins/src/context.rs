use aifw_pf::PfBackend;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Tables that plugins are allowed to modify (plugin-specific tables only).
const PLUGIN_ALLOWED_TABLE_PREFIX: &str = "plugin_";

/// Context provided to plugins for interacting with the firewall.
/// Plugins can only modify pf tables prefixed with "plugin_" to prevent
/// them from interfering with system tables.
#[derive(Clone)]
pub struct PluginContext {
    pf: Arc<dyn PfBackend>,
    /// Shared key-value store for inter-plugin communication
    store: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl PluginContext {
    pub fn new(pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pf,
            store: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Check if a table name is allowed for plugin access.
    fn is_table_allowed(table: &str) -> bool {
        table.starts_with(PLUGIN_ALLOWED_TABLE_PREFIX)
    }

    /// Store a value in the shared plugin store
    pub async fn store_set(&self, key: &str, value: &str) {
        self.store
            .write()
            .await
            .insert(key.to_string(), value.to_string());
    }

    /// Get a value from the shared plugin store
    pub async fn store_get(&self, key: &str) -> Option<String> {
        self.store.read().await.get(key).cloned()
    }

    /// Add an IP to a pf table (restricted to plugin_ prefixed tables)
    pub async fn add_to_table(&self, table: &str, ip: std::net::IpAddr) -> Result<(), String> {
        if !Self::is_table_allowed(table) {
            return Err(format!(
                "plugins can only modify tables with prefix '{PLUGIN_ALLOWED_TABLE_PREFIX}'"
            ));
        }
        self.pf
            .add_table_entry(table, ip)
            .await
            .map_err(|e| e.to_string())
    }

    /// Remove an IP from a pf table (restricted to plugin_ prefixed tables)
    pub async fn remove_from_table(&self, table: &str, ip: std::net::IpAddr) -> Result<(), String> {
        if !Self::is_table_allowed(table) {
            return Err(format!(
                "plugins can only modify tables with prefix '{PLUGIN_ALLOWED_TABLE_PREFIX}'"
            ));
        }
        self.pf
            .remove_table_entry(table, ip)
            .await
            .map_err(|e| e.to_string())
    }
}
