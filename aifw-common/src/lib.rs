#![warn(missing_docs)]
//! # aifw-common
//!
//! Shared types for AiFw: rules, NAT, VPN, TLS, geo-IP, HA, IDS, and metrics,
//! plus the loopback API constants used to reach the local `aifw-api` process.

/// Default loopback API port. Used by daemon background tasks and CLI
/// to reach the local aifw-api process. The actual listen port is
/// configured via `aifw-api --listen` but defaults to this value.
///
/// TODO(#487): when peer ports become configurable per-node, store on
/// cluster_nodes and use that instead.
pub const DEFAULT_LOOPBACK_API_PORT: u16 = 8080;
/// Base URL for the local aifw-api over loopback HTTPS (self-signed cert),
/// combining `https://127.0.0.1` with [`DEFAULT_LOOPBACK_API_PORT`].
pub const DEFAULT_LOOPBACK_API_BASE: &str = "https://127.0.0.1:8080";

/// Named aliases (host/network/port/URL-table) usable in firewall rules
pub mod alias;
pub mod cluster_events;
/// Crate-wide `AifwError` enum and `Result` alias
pub mod error;
/// Geo-IP types: country codes, per-country rules, GeoLite2 CSV parsing, CIDR aggregation
pub mod geoip;
/// High-availability types: CARP VIPs, pfsync, cluster nodes, health checks
pub mod ha;
/// Intrusion detection types: config, rulesets, rules, alerts, suppressions
pub mod ids;
pub mod ipsec;
/// Multi-WAN types: routing instances, gateways, groups, policies, SLA, leak detection
pub mod multiwan;
/// NAT types: SNAT/DNAT/masquerade/binat/NAT64/NAT46 rules and pf rendering
pub mod nat;
pub mod net_safety;
/// Granular permission bitmask model shared by JWT claims and role definitions
pub mod permission;
/// Traffic shaping (pf queues) and per-IP rate limiting / SYN flood protection
pub mod ratelimit;
/// Core firewall rule model and pf rule rendering
pub mod rule;
pub mod schedule;
pub mod schemas;
#[cfg(unix)]
pub mod single_instance;
#[cfg(test)]
mod tests;
/// TLS inspection types: versions, JA3/JA3S fingerprints, SNI rules, cert policy, MITM proxy config
pub mod tls;
/// Primitive wire types: addresses, ports, port ranges, interfaces
pub mod types;
/// VPN types: WireGuard tunnels/peers and IPsec SAs/SPs
pub mod vpn;

pub use alias::{Alias, AliasType};
pub use cluster_events::{ClusterEvent, ClusterEventBus};
pub use error::{AifwError, Result};
pub use geoip::{
    CountryCode, GeoIpAction, GeoIpDbConfig, GeoIpEntry, GeoIpLookupResult, GeoIpRule,
    GeoIpRuleStatus,
};
pub use ha::{
    CarpLatencyProfile, CarpStatus, CarpTiming, CarpVip, ClusterNode, ClusterRole, ConfigSnapshot,
    HealthCheck, HealthCheckType, NodeHealth, PfsyncConfig,
};
pub use ids::{
    AlertClassification, IdsAction, IdsAlert, IdsConfig, IdsMode, IdsRule, IdsRuleMatch,
    IdsRuleset, IdsSeverity, IdsStats, IdsSuppression, RuleFormat, RuleSource, SuppressType,
};
pub use ipsec::{
    ChildSaStatus, IpsecAuthMethod, IpsecCertSource, IpsecLiveStatus, IpsecStartAction, IpsecTunnel,
};
pub use multiwan::{
    DEFAULT_FIB_NUMBER, DEFAULT_INSTANCE_ID, DEFAULT_INSTANCE_NAME, Gateway, GatewayEvent,
    GatewayGroup, GatewayState, GroupMember, GroupPolicy, InstanceMember, InstanceStatus,
    LeakDirection, MwIpVersion, MwProtocol, PolicyRule, PolicyStatus, RouteAction, RouteLeak,
    RoutingInstance, StickyMode,
};
pub use nat::{NatRedirect, NatRule, NatStatus, NatType};
pub use permission::{ALL_PERMISSIONS, Permission, PermissionSet, builtin_role_permissions};
pub use ratelimit::{
    Bandwidth, BandwidthUnit, FqCodelConfig, QueueConfig, QueueStatus, QueueType, RateLimitRule,
    RateLimitStatus, SynFloodConfig, TrafficClass,
};
pub use rule::{
    Action, AdaptiveTimeouts, Direction, IpVersion, Protocol, Rule, RuleMatch, RuleStatus,
    StateOptions, StatePolicy, StateTracking,
};
pub use tls::{
    CertInfo, Ja3Fingerprint, Ja3sFingerprint, MitmProxyConfig, SniAction, SniRule, SniRuleStatus,
    TlsPolicy, TlsVersion,
};
pub use types::{Address, Interface, Port, PortRange};
pub use vpn::{
    IpsecMode, IpsecProtocol, IpsecSa, IpsecSp, SpDirection, SpLevel, VpnStatus, VpnType, WgPeer,
    WgTunnel,
};
