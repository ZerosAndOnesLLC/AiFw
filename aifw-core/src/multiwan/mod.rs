//! Multi-WAN engines: routing instances (FIBs), gateways, groups, policies, leaks.
//!
//! Phased implementation tracked in working-plan.md (issue #132).

/// Gateway CRUD, health-probe monitors, and the up/down state machine
pub mod gateway;
/// Gateway groups: membership, tiers/weights, and pure failover/LB selection logic
pub mod group;
/// Routing instances — each maps to a FreeBSD FIB — and their member interfaces
pub mod instance;
/// Route leaks: controlled cross-instance (cross-FIB) traffic exceptions
pub mod leak;
/// Policy-based routing rules compiled into the pf PBR/reply anchors
pub mod policy;
pub mod preflight;
pub mod probe;
pub mod sla;

pub use gateway::{GatewayEngine, GatewayMetrics, dampening_holds, evaluate_transition};
pub use group::{GroupEngine, Selection, select};
pub use instance::InstanceEngine;
pub use leak::{LEAK_ANCHOR, LeakEngine};
pub use policy::{CompiledPolicies, PBR_ANCHOR, PolicyEngine, REPLY_ANCHOR};
pub use preflight::{BlastRadiusReport, PreflightEngine};
pub use probe::{ProbeKind, ProbeOutcome, ProbeSpec, run_probe};
pub use sla::{SlaEngine, SlaSample};
