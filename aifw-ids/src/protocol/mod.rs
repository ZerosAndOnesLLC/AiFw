//! Application-layer protocol detection and parsing. This module root
//! declares the per-protocol parser submodules plus the shared model
//! (`types`) and the `registry`, and re-exports their surface so
//! `protocol::AppProto`, `protocol::ProtocolRegistry`, etc. keep
//! resolving (#477).

pub mod dns;
pub mod http;
pub mod registry;
pub mod smtp;
pub mod ssh;
pub mod tls;
pub mod types;

pub use registry::*;
pub use types::*;
