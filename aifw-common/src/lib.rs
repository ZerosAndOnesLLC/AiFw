pub mod error;
pub mod geoip;
pub mod nat;
pub mod ratelimit;
pub mod rule;
#[cfg(test)]
mod tests;
pub mod types;
pub mod vpn;

pub use error::{AifwError, Result};
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
    Action, AdaptiveTimeouts, Direction, Protocol, Rule, RuleMatch, RuleStatus, StateOptions,
    StatePolicy, StateTracking,
};
pub use types::{Address, Interface, Port, PortRange};
pub use vpn::{
    IpsecMode, IpsecProtocol, IpsecSa, IpsecSp, SpDirection, SpLevel, VpnStatus, VpnType,
    WgPeer, WgTunnel,
};
