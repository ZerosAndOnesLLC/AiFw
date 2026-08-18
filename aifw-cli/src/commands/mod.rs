//! CLI command implementations, one module per `aifw <group>` (#190).
//! Everything public is re-exported so `main.rs` keeps calling
//! `commands::<fn>`.

mod cluster;
mod common;
mod config;
mod dhcp;
mod dns;
mod geoip;
mod ids;
mod interfaces;
mod logging;
mod multiwan;
mod nat;
mod reverse_proxy;
mod routes;
mod rules;
mod shaping;
mod system;
mod updates;
mod users;
mod vpn;

pub use cluster::*;
pub use config::*;
pub use dhcp::*;
pub use dns::*;
pub use geoip::*;
pub use ids::*;
pub use interfaces::*;
pub use logging::*;
pub use multiwan::*;
pub use nat::*;
pub use reverse_proxy::*;
pub use routes::*;
pub use rules::*;
pub use shaping::*;
pub use system::*;
pub use updates::*;
pub use users::*;
pub use vpn::*;
