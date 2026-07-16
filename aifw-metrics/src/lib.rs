#![warn(missing_docs)]
//! # aifw-metrics
//!
//! Time-series metrics collection and storage: pluggable collectors feed a
//! ring-buffered series store, exposed to the API for dashboards and history.

/// `MetricsBackend` storage trait and query result types
pub mod backend;
/// Background collector that samples pf stats into the store
pub mod collector;
/// Metrics subsystem configuration (backend choice, intervals, retention)
pub mod config;
/// Crate error type (`MetricsError`) and result alias
pub mod error;
/// Fixed-capacity ring buffer used for per-tier point storage
pub mod ring;
/// Metric points, aggregation methods, RRD tiers, and multi-resolution series
pub mod series;
/// In-memory RRD-like `MetricsStore` backend
pub mod store;

#[cfg(test)]
mod tests;

pub use backend::MetricsBackend;
pub use collector::MetricsCollector;
pub use config::MetricsConfig;
pub use error::{MetricsError, Result};
pub use ring::RingBuffer;
pub use series::{Aggregation, MetricPoint, MetricSeries};
pub use store::MetricsStore;
