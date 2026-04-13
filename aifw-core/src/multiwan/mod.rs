//! Multi-WAN engines: routing instances (FIBs), gateways, groups, policies, leaks.
//!
//! Phased implementation tracked in working-plan.md (issue #132).

pub mod gateway;
pub mod group;
pub mod instance;
pub mod policy;
pub mod probe;

pub use gateway::{GatewayEngine, GatewayMetrics, evaluate_transition};
pub use group::{GroupEngine, Selection, select};
pub use instance::InstanceEngine;
pub use policy::{CompiledPolicies, PBR_ANCHOR, PolicyEngine, REPLY_ANCHOR};
pub use probe::{ProbeKind, ProbeOutcome, ProbeSpec, run_probe};
