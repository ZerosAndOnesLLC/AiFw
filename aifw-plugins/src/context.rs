use aifw_pf::PfBackend;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Context provided to plugins for interacting with the firewall
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

    /// Get a reference to the pf backend (for table operations, etc.)
    pub fn pf(&self) -> &dyn PfBackend {
        self.pf.as_ref()
    }

    pub fn pf_arc(&self) -> Arc<dyn PfBackend> {
        self.pf.clone()
    }

    /// Store a value in the shared plugin store
    pub async fn store_set(&self, key: &str, value: &str) {
        self.store.write().await.insert(key.to_string(), value.to_string());
    }

    /// Get a value from the shared plugin store
    pub async fn store_get(&self, key: &str) -> Option<String> {
        self.store.read().await.get(key).cloned()
    }

    /// Add an IP to a pf table
    pub async fn add_to_table(&self, table: &str, ip: std::net::IpAddr) -> Result<(), String> {
        self.pf
            .add_table_entry(table, ip)
            .await
            .map_err(|e| e.to_string())
    }

    /// Remove an IP from a pf table
    pub async fn remove_from_table(&self, table: &str, ip: std::net::IpAddr) -> Result<(), String> {
        self.pf
            .remove_table_entry(table, ip)
            .await
            .map_err(|e| e.to_string())
    }
}
