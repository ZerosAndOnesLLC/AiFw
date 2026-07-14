//! # aifw-conntrack
//!
//! Connection tracking and pflog ingestion: parses `pflog` events, maintains
//! the live connection/state table, and exposes queries and rolled-up stats
//! consumed by the API status and metrics surfaces.

pub mod pflog;
pub mod query;
pub mod stats;
pub mod tracker;

#[cfg(test)]
mod tests;

pub use pflog::{PfLogEntry, PfLogParser};
pub use query::{ConnectionFilter, ConnectionQuery};
pub use stats::ConntrackStats;
pub use tracker::ConnectionTracker;
