pub mod alias;
pub mod permission;
pub mod error;
pub mod geoip;
pub mod ha;
pub mod ids;
pub mod nat;
pub mod ratelimit;
pub mod rule;
#[cfg(test)]
mod tests;
pub mod tls;
pub mod types;
pub mod vpn;

pub use alias::{Alias, AliasType};
pub use error::{AifwError, Result};
pub use ha::{
    CarpStatus, CarpVip, ClusterNode, ClusterRole, ConfigSnapshot, HealthCheck, HealthCheckType,
    NodeHealth, PfsyncConfig,
};
pub use geoip::{
    CountryCode, GeoIpAction, GeoIpDbConfig, GeoIpEntry, GeoIpLookupResult, GeoIpRule,
    GeoIpRuleStatus,
};
pub use nat::{NatRedirect, NatRule, NatStatus, NatType};
pub use ratelimit::{
    Bandwidth, BandwidthUnit, QueueConfig, QueueStatus, QueueType, RateLimitRule,
    RateLimitStatus, SynFloodConfig, TrafficClass,
};
pub use rule::{
    Action, AdaptiveTimeouts, Direction, IpVersion, Protocol, Rule, RuleMatch, RuleStatus,
    StateOptions, StatePolicy, StateTracking,
};
pub use tls::{
    CertInfo, Ja3Fingerprint, Ja3sFingerprint, MitmProxyConfig, SniAction, SniRule,
    SniRuleStatus, TlsPolicy, TlsVersion,
};
pub use types::{Address, Interface, Port, PortRange};
pub use vpn::{
    IpsecMode, IpsecProtocol, IpsecSa, IpsecSp, SpDirection, SpLevel, VpnStatus, VpnType,
    WgPeer, WgTunnel,
};
pub use permission::{Permission, PermissionSet, ALL_PERMISSIONS, builtin_role_permissions};
pub use ids::{
    IdsAction, IdsAlert, IdsConfig, IdsMode, IdsRule, IdsRuleMatch, IdsRuleset, IdsSeverity,
    IdsStats, IdsSuppression, RuleFormat, RuleSource, SuppressType,
};
