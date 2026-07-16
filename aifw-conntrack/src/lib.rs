#![warn(missing_docs)]
//! # aifw-conntrack
//!
//! Connection tracking and pflog ingestion: parses `pflog` events, maintains
//! the live connection/state table, and exposes queries and rolled-up stats
//! consumed by the API status and metrics surfaces.

/// Crate error type (`ConntrackError`) and result alias
pub mod error;
/// pflog line parsing into structured `PfLogEntry` events
pub mod pflog;
/// Filtering and aggregation queries over pf state snapshots
pub mod query;
/// Rolled-up connection statistics computed from pf states
pub mod stats;
/// Background-polling cache of the pf state table
pub mod tracker;

#[cfg(test)]
mod tests;

pub use error::{ConntrackError, Result};
pub use pflog::{PfLogEntry, PfLogParser};
pub use query::{ConnectionFilter, ConnectionQuery};
pub use stats::ConntrackStats;
pub use tracker::ConnectionTracker;
