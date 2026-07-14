//! # aifw-metrics
//!
//! Time-series metrics collection and storage: pluggable collectors feed a
//! ring-buffered series store, exposed to the API for dashboards and history.

pub mod backend;
pub mod collector;
pub mod config;
pub mod ring;
pub mod series;
pub mod store;

#[cfg(test)]
mod tests;

pub use backend::MetricsBackend;
pub use collector::MetricsCollector;
pub use config::MetricsConfig;
pub use ring::RingBuffer;
pub use series::{Aggregation, MetricPoint, MetricSeries};
pub use store::MetricsStore;
