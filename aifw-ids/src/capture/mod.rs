//! Packet capture. This module root declares the per-platform backend
//! submodules plus the shared model (`types`) and the `factory`, and
//! re-exports their surface so `capture::CaptureConfig`,
//! `capture::create_capture`, etc. keep resolving (#477).

pub mod factory;
pub mod pcap;
pub mod types;

#[cfg(target_os = "freebsd")]
pub mod bpf;
#[cfg(target_os = "freebsd")]
pub mod netmap;

pub use factory::*;
pub use types::*;
