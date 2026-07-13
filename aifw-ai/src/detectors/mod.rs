//! Threat detectors. This module root declares the per-detector
//! submodules plus the `registry` (the `Detector` trait and the
//! run/default helpers), and re-exports the registry surface so
//! `detectors::Detector`, `detectors::default_detectors`, etc. keep
//! resolving (#477).

pub mod brute_force;
pub mod c2_beacon;
pub mod ddos;
pub mod dns_tunnel;
pub mod port_scan;
pub mod registry;

pub use registry::*;
