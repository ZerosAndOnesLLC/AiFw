//! Packet capture. This module root declares the per-platform backend
//! submodules plus the shared model (`types`) and the `factory`, and
//! re-exports their surface so `capture::CaptureConfig`,
//! `capture::create_capture`, etc. keep resolving (#477).

pub mod factory;
/// pcap-based capture backend for development on Linux/WSL/macOS
pub mod pcap;
pub mod types;

/// BPF-based packet capture (FreeBSD /dev/bpf).
#[cfg(target_os = "freebsd")]
pub mod bpf;
/// netmap-based high-rate capture (FreeBSD, experimental — #484).
#[cfg(target_os = "freebsd")]
pub mod netmap;

pub use factory::*;
pub use types::*;
