//! CLI command implementations, one module per `aifw <group>` (#190).
//! Each group is a clap enum plus `run()`, reached by module path
//! (`commands::rules::run`). Only `local` touches the database or pf.

pub mod api_keys;
pub mod cluster;
pub mod config;
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
pub mod resource;
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
