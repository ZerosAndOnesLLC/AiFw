//! CLI command implementations, one module per `aifw <group>` (#190).
//! Legacy groups re-export their functions flat (`commands::<fn>`); CLI v2
//! groups are reached by module path (`commands::session::login`).

mod cluster;
mod common;
mod config;
pub mod context;
mod dhcp;
mod dns;
mod geoip;
mod ids;
mod interfaces;
pub mod local;
mod logging;
mod multiwan;
mod nat;
mod plugins;
mod reverse_proxy;
mod routes;
mod rules;
pub mod session;
mod shaping;
pub mod staging;
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
pub use plugins::*;
pub use reverse_proxy::*;
pub use routes::*;
pub use rules::*;
pub use shaping::*;
pub use system::*;
pub use updates::*;
pub use users::*;
pub use vpn::*;
