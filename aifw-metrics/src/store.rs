use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Mutex;

use crate::backend::{MetricQueryResult, MetricsBackend};
use crate::series::{Aggregation, MetricPoint, MetricSeries, Tier};

/// Default local metrics store using in-memory ring buffers.
/// This is the RRD-like backend that works standalone.
///
/// DashMap shards the keyspace so concurrent record() calls on different
/// series don't contend. The per-series Mutex is a plain std::sync::Mutex
/// — record() does not await while holding it, so blocking semantics are
/// fine and avoid the cost of a fully-async lock.
pub struct MetricsStore {
    series: DashMap<String, Mutex<MetricSeries>>,
    default_aggregation: Aggregation,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            series: DashMap::new(),
            default_aggregation: Aggregation::Average,
        }
    }

    /// Pre-register metric series with specific aggregation methods
    pub async fn register(&self, name: &str, aggregation: Aggregation) {
        self.series
            .entry(name.to_string())
            .or_insert_with(|| Mutex::new(MetricSeries::new(name, aggregation)));
    }

    /// Get a snapshot of all series names and their latest values
    pub async fn snapshot(&self) -> Vec<(String, Option<f64>)> {
        self.series
            .iter()
            .map(|entry| {
                let latest = entry.value().lock().expect("series mutex poisoned").latest();
                (entry.key().clone(), latest)
            })
            .collect()
    }
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MetricsBackend for MetricsStore {
    async fn record(&self, name: &str, value: f64) -> Result<(), String> {
        let entry = self
            .series
            .entry(name.to_string())
            .or_insert_with(|| Mutex::new(MetricSeries::new(name, self.default_aggregation)));
        entry
            .value()
            .lock()
            .expect("series mutex poisoned")
            .record(value);
        Ok(())
    }

    async fn query(
        &self,
        name: &str,
        tier: Tier,
        last_n: Option<usize>,
    ) -> Result<MetricQueryResult, String> {
        let entry = self
            .series
            .get(name)
            .ok_or_else(|| format!("metric '{name}' not found"))?;
        let s = entry.value().lock().expect("series mutex poisoned");
        let points: Vec<MetricPoint> = match last_n {
            Some(n) => s.get_last(tier, n).into_iter().cloned().collect(),
            None => s.get_tier(tier).into_iter().cloned().collect(),
        };

        Ok(MetricQueryResult {
            name: name.to_string(),
            tier: tier.label().to_string(),
            points,
        })
    }

    async fn latest(&self, name: &str) -> Result<Option<f64>, String> {
        Ok(self.series.get(name).and_then(|e| {
            e.value()
                .lock()
                .expect("series mutex poisoned")
                .latest()
        }))
    }

    async fn list_metrics(&self) -> Result<Vec<String>, String> {
        Ok(self.series.iter().map(|e| e.key().clone()).collect())
    }

    async fn summary(&self) -> Result<Vec<(String, f64)>, String> {
        Ok(self
            .series
            .iter()
            .filter_map(|e| {
                let v = e.value().lock().expect("series mutex poisoned").latest()?;
                Some((e.key().clone(), v))
            })
            .collect())
    }
}

/// PostgreSQL-backed metrics store.
/// Feature-gated behind `postgres`. Falls back to local if not compiled in.
#[cfg(feature = "postgres")]
pub struct PostgresMetricsStore {
    // In production this would hold a sqlx::PgPool
    // and store metrics in time-series optimized tables:
    //
    // CREATE TABLE metrics_raw (
    //     name TEXT NOT NULL,
    //     ts TIMESTAMPTZ NOT NULL,
    //     value DOUBLE PRECISION NOT NULL,
    //     min_val DOUBLE PRECISION,
    //     max_val DOUBLE PRECISION,
    //     count BIGINT DEFAULT 1
    // );
    // CREATE INDEX idx_metrics_raw_name_ts ON metrics_raw(name, ts DESC);
    //
    // CREATE TABLE metrics_rollup_1m ( ... same schema ... );
    // CREATE TABLE metrics_rollup_1h ( ... same schema ... );
    // CREATE TABLE metrics_rollup_1d ( ... same schema ... );
    //
    // Periodic jobs consolidate raw -> 1m -> 1h -> 1d
    // with retention policies (DELETE WHERE ts < now() - interval)
}
