//! Shared response envelopes returned by every `/api/v1` handler.
//!
//! Re-exported from `routes/mod.rs`, so submodules pick these up through
//! their `use super::*;` wildcard.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}
