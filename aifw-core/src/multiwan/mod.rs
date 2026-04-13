//! Multi-WAN engines: routing instances (FIBs), gateways, groups, policies, leaks.
//!
//! Phased implementation tracked in working-plan.md (issue #132).

pub mod gateway;
pub mod group;
pub mod instance;
pub mod leak;
pub mod policy;
pub mod preflight;
pub mod probe;
pub mod sla;

pub use gateway::{GatewayEngine, GatewayMetrics, evaluate_transition};
pub use group::{GroupEngine, Selection, select};
pub use instance::InstanceEngine;
pub use leak::{LEAK_ANCHOR, LeakEngine};
pub use policy::{CompiledPolicies, PBR_ANCHOR, PolicyEngine, REPLY_ANCHOR};
pub use preflight::{BlastRadiusReport, PreflightEngine};
pub use probe::{ProbeKind, ProbeOutcome, ProbeSpec, run_probe};
pub use sla::{SlaEngine, SlaSample};
