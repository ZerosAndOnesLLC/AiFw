//! Alert outputs. This module root declares the per-sink submodules plus
//! the `pipeline` (the `AlertOutput` trait and `AlertPipeline`), and
//! re-exports the pipeline surface so `output::AlertPipeline`,
//! `output::AlertOutput` keep resolving (#477).

/// EVE JSON file sink — Suricata-compatible one-JSON-per-line, with rotation
pub mod eve;
/// In-memory alert ring buffer sink with byte/age limits and query support
pub mod memory;
pub mod pipeline;
/// SQLite alert sink — persistent storage powering the UI alert viewer
pub mod sqlite;
/// Syslog alert sink — RFC 5424 messages over UDP to a remote server
pub mod syslog;

pub use pipeline::*;
