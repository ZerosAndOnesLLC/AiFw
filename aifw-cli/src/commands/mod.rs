//! CLI command implementations, one module per `aifw <group>` (#190).
//! Legacy groups re-export their functions flat (`commands::<fn>`); CLI v2
//! groups are reached by module path (`commands::session::login`).

mod cluster;
mod config;
pub mod context;
mod dhcp;
pub mod dns;
pub mod geoip;
mod ids;
pub mod interfaces;
pub mod local;
mod logging;
mod multiwan;
pub mod nat;
mod plugins;
mod reverse_proxy;
pub mod routes;
pub mod rules;
pub mod session;
pub mod shaping;
pub mod staging;
pub mod system;
mod updates;
pub mod users;
mod vpn;

pub use cluster::*;
pub use config::*;
pub use dhcp::*;
pub use ids::*;
pub use logging::*;
pub use multiwan::*;
pub use plugins::*;
pub use reverse_proxy::*;
pub use updates::*;
pub use vpn::*;
