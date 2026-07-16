#![warn(missing_docs)]
//! # aifw-core
//!
//! Core firewall engines built on top of [`aifw_pf`] and [`aifw_common`]:
//! rules, NAT, aliases, geo-IP, VPN, traffic shaping, HA/clustering, audit,
//! ACME/TLS, DDNS, and the multiwan family. Each engine owns a pf anchor and
//! an inline `migrate()` that creates its SQLite tables; the shared
//! [`Database`] handle wraps the `SqlitePool` used throughout.

pub mod acme;
pub mod acme_dns;
pub mod acme_engine;
pub mod acme_export;
/// [`AliasEngine`] — named host/network/port/URL aliases mirrored into pf tables
pub mod alias;
/// Append-only audit log of configuration changes
pub mod audit;
/// Persisted system configuration types (console, SSH access, firewall policy)
pub mod config;
/// [`ConfigManager`] — loads and saves the persisted system configuration
pub mod config_manager;
/// [`Database`] — SQLite pool wrapper and filter-rule persistence
pub mod db;
pub mod ddns;
pub mod dns_blocklists;
/// [`RuleEngine`] — filter rule CRUD and application to the `aifw` pf anchor
pub mod engine;
pub mod error;
/// [`GeoIpEngine`] — country-based blocking via GeoLite2 data and pf tables
pub mod geoip;
/// [`ClusterEngine`] and CARP role helpers for high-availability clustering
pub mod ha;
pub mod migrations;
pub mod multiwan;
/// [`NatEngine`] — SNAT/DNAT/masquerade rule CRUD and application to pf
pub mod nat;
/// SSRF guard for operator-configurable outbound HTTP. Relocated to
/// `aifw-common` so downloaders in sibling crates (aifw-ids) can share it;
/// re-exported here so existing `crate::net_safety::…` call sites keep working.
pub use aifw_common::net_safety;
pub mod path_safety;
pub mod pf_tuning;
pub mod s3_backup;
/// [`ShapingEngine`] — traffic-shaping queues and connection rate limits
pub mod shaping;
pub mod smtp_notify;
pub mod sudo;
pub mod system_apply;
pub mod system_apply_helpers;
#[cfg(test)]
mod tests;
/// [`TlsEngine`] — SNI rules, JA3 blocklist, and TLS/MITM policy enforcement
pub mod tls;
pub mod updater;
/// Input validation for filter rules, interface names, and pf labels
pub mod validation;
/// [`VpnEngine`] — WireGuard tunnels/peers and IPsec SAs
pub mod vpn;

pub use alias::AliasEngine;
pub use audit::{AuditAction, AuditLog};
pub use config::{ConsoleConfig, ConsoleKind, FirewallConfig, SshAccessConfig, SystemConfig};
pub use config_manager::ConfigManager;
/// [`Database`] is re-exported from [`db::Database`] as the crate's primary
/// entry point; prefer `aifw_core::Database` over the fully-qualified path.
pub use db::Database;
pub use engine::RuleEngine;
pub use error::{CoreError, Result};
pub use geoip::GeoIpEngine;
pub use ha::{ClusterEngine, current_local_role, is_local_master, sha256_hex};
pub use multiwan::{
    GatewayEngine, GroupEngine, InstanceEngine, LeakEngine, PolicyEngine, PreflightEngine,
    SlaEngine,
};
pub use nat::NatEngine;
pub use shaping::ShapingEngine;
pub use tls::TlsEngine;
pub use vpn::VpnEngine;
