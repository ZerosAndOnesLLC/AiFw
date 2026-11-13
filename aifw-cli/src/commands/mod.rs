//! CLI command implementations, one module per `aifw <group>` (#190).
//! Legacy groups re-export their functions flat (`commands::<fn>`); CLI v2
//! groups are reached by module path (`commands::session::login`).

pub mod cluster;
mod config;
pub mod context;
pub mod dhcp;
pub mod dns;
pub mod geoip;
pub mod ids;
pub mod interfaces;
pub mod local;
pub mod logging;
pub mod logs;
pub mod multiwan;
pub mod nat;
pub mod plugins;
pub mod reverse_proxy;
pub mod routes;
pub mod rules;
pub mod session;
pub mod shaping;
pub mod staging;
pub mod system;
pub mod updates;
pub mod users;
pub mod vpn;

pub use config::*;
