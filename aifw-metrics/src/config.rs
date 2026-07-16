use serde::{Deserialize, Serialize};

/// Configuration for the metrics subsystem (storage backend, collection
/// cadence, retention)
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

/// Which metrics storage backend to use; serialized lowercase on the wire
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricsBackendType {
    /// In-memory ring-buffer store (`MetricsStore`), the standalone default
    Local,
    /// PostgreSQL-backed store; requires the `postgres` feature and `postgres_url`
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
