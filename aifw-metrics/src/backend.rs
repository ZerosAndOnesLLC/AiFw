use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::series::{MetricPoint, Tier};

/// Response type for metric queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQueryResult {
    pub name: String,
    pub tier: String,
    pub points: Vec<MetricPoint>,
}

/// Trait for metrics storage backends
#[async_trait]
pub trait MetricsBackend: Send + Sync {
    /// Record a metric value
    async fn record(&self, name: &str, value: f64) -> Result<(), String>;

    /// Query metric data for a given tier
    async fn query(
        &self,
        name: &str,
        tier: Tier,
        last_n: Option<usize>,
    ) -> Result<MetricQueryResult, String>;

    /// Get the latest value for a metric
    async fn latest(&self, name: &str) -> Result<Option<f64>, String>;

    /// List all available metric names
    async fn list_metrics(&self) -> Result<Vec<String>, String>;

    /// Get a summary of all metrics (latest values)
    async fn summary(&self) -> Result<Vec<(String, f64)>, String>;
}
