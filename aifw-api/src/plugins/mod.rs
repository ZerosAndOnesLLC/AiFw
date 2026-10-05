//! Plugin system API surface: `/api/v1/plugins/*` handlers and the event
//! bridges that feed plugin hooks.

mod bridges;
mod handlers;
mod tails;
mod vpn_watch;

pub use bridges::start;
pub use handlers::*;
