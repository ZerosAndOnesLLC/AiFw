//! `aifw-client` — async client for the AiFw REST API (`/api/v1`).
//!
//! The crate has no CLI concerns: it resolves credentials into request
//! headers, pins TLS, refreshes sessions, and maps HTTP failures onto
//! [`ClientError`]. The `aifw` CLI and (later) the TUI build on it.

pub mod auth;
pub mod client;
pub mod error;
pub mod tls;

pub use auth::{Auth, Session, SessionStore, TokenPair, credential_from_token};
pub use client::{Client, ClientBuilder, LoginOutcome, Upload, UploadFile};
pub use error::{ClientError, Result};

/// Default base URL of the API on the appliance itself (the API serves
/// HTTPS on 127.0.0.1:8080 by default).
pub const DEFAULT_LOCAL_URL: &str = "https://127.0.0.1:8080";
