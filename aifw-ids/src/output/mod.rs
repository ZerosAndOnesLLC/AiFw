//! Alert outputs. This module root declares the per-sink submodules plus
//! the `pipeline` (the `AlertOutput` trait and `AlertPipeline`), and
//! re-exports the pipeline surface so `output::AlertPipeline`,
//! `output::AlertOutput` keep resolving (#477).

pub mod eve;
pub mod memory;
pub mod pipeline;
pub mod sqlite;
pub mod syslog;

pub use pipeline::*;
