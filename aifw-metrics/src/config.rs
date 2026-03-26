use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Backend type: "local" or "postgres"
    pub backend: MetricsBackendType,
    /// PostgreSQL connection URL (only used if backend = postgres)
    pub postgres_url: Option<String>,
    /// How often to collect metrics (seconds)
    pub collection_interval_secs: u64,
    /// Retention in days for the day tier
    pub retention_days: u32,
    /// Enable SQLite persistence for local backend (survive restarts)
    pub persist_to_sqlite: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricsBackendType {
    Local,
    Postgres,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            backend: MetricsBackendType::Local,
            postgres_url: None,
            collection_interval_secs: 1,
            retention_days: 365,
            persist_to_sqlite: true,
        }
    }
}
