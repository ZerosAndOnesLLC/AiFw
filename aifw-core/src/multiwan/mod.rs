//! Multi-WAN engines: routing instances (FIBs), gateways, groups, policies, leaks.
//!
//! Phased implementation tracked in working-plan.md (issue #132).

pub mod gateway;
pub mod instance;
pub mod probe;

pub use gateway::{GatewayEngine, GatewayMetrics, evaluate_transition};
pub use instance::InstanceEngine;
pub use probe::{ProbeKind, ProbeOutcome, ProbeSpec, run_probe};
