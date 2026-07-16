//! Application-layer protocol detection and parsing. This module root
//! declares the per-protocol parser submodules plus the shared model
//! (`types`) and the `registry`, and re-exports their surface so
//! `protocol::AppProto`, `protocol::ProtocolRegistry`, etc. keep
//! resolving (#477).

/// DNS parser — query name, type, response code, answer data
pub mod dns;
/// HTTP/1.x parser — method, URI, host, user-agent, headers
pub mod http;
pub mod registry;
/// SMTP parser — HELO, MAIL FROM, RCPT TO, command/response data
pub mod smtp;
/// SSH parser — banner (software version) and protocol version
pub mod ssh;
/// TLS parser — SNI, JA3 fingerprint, version, cipher suites from ClientHello
pub mod tls;
pub mod types;

pub use registry::*;
pub use types::*;
