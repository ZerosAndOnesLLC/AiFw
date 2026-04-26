//! IPC protocol between aifw-api and aifw-ids.
//!
//! Wire format: 4-byte big-endian length prefix + UTF-8 JSON body.
//! Connection-per-call (no streaming yet — keeps the server stateless).
//!
//! `proto` defines the on-wire request/response shapes. `framing` reads
//! and writes the length-prefixed envelopes. `client` provides a thin
//! Unix-socket client with TTL caching of read responses. `server` is the
//! glue that turns an `IpcHandler` impl into a request loop.

pub mod client;
pub mod framing;
pub mod proto;
pub mod server;

pub use client::{IdsClient, IdsClientError};
pub use proto::{IpcRequest, IpcResponse};
pub use server::IpcHandler;
