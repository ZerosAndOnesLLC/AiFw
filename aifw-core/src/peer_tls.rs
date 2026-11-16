//! TLS pinning for AiFw-to-AiFw HTTPS calls (#317). The implementation moved
//! to `aifw_client::tls` (CLI v2) so the CLI can share it without depending
//! on this crate; this re-export keeps `aifw_core::peer_tls::*` paths stable.

pub use aifw_client::tls::*;
