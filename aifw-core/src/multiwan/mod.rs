//! Multi-WAN engines: routing instances (FIBs), gateways, groups, policies, leaks.
//!
//! Phased implementation tracked in working-plan.md (issue #132).

pub mod instance;

pub use instance::InstanceEngine;
