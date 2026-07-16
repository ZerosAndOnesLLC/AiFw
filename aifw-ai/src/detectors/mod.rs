//! Threat detectors. This module root declares the per-detector
//! submodules plus the `registry` (the `Detector` trait and the
//! run/default helpers), and re-exports the registry surface so
//! `detectors::Detector`, `detectors::default_detectors`, etc. keep
//! resolving (#477).

/// Brute-force login attack detection (focused ports, high failure ratio)
pub mod brute_force;
/// Command-and-control beacon detection (regular small connections to few hosts)
pub mod c2_beacon;
/// DDoS detection (SYN floods and high connection rates)
pub mod ddos;
/// DNS tunneling detection (excessive DNS query volume and ratio)
pub mod dns_tunnel;
/// Port-scan detection (many unique ports with failed connections)
pub mod port_scan;
pub mod registry;

pub use registry::*;
