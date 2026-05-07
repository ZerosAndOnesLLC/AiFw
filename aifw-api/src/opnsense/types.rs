//! Typed representation of the parts of an OPNsense / pfSense `config.xml`
//! that AiFw imports. Only fields the importer actually applies are modeled —
//! everything else round-trips through the preview as a "skipped" count.

use serde::Serialize;

/// Address family carried on a filter rule. OPNsense uses `inet`/`inet6`/
/// `inet46`. Default in OPNsense is `inet` when the element is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AddrFamily {
    Inet,
    Inet6,
    Both,
}

impl AddrFamily {
    pub fn parse(s: &str) -> Self {
        match s {
            "inet6" => AddrFamily::Inet6,
            "inet46" => AddrFamily::Both,
            _ => AddrFamily::Inet,
        }
    }
}

/// One side (source or destination) of a filter rule.
///
/// Maps the OPNsense XML form:
/// ```xml
/// <source>
///   <any/> | <network>lan</network> | <address>1.2.3.4/24</address>
///   <port>80</port>
///   <not/>           <!-- inverse match -->
/// </source>
/// ```
#[derive(Debug, Clone, Default, Serialize)]
pub struct OpnEndpoint {
    /// Literal address (CIDR or single IP) if `<address>` was present.
    pub address: Option<String>,
    /// Network reference (`lan`, `wan`, `lanip`, `wanip`, `(self)`, or an alias name).
    pub network: Option<String>,
    /// Match-anything (`<any/>`).
    pub any: bool,
    /// Inverse match (`<not/>`).
    pub not: bool,
    /// Port spec — single `80`, range `8000-8100`, or alias name.
    pub port: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnRule {
    pub action: String,           // pass | block | reject
    pub direction: String,        // in | out | any
    pub interface: Vec<String>,   // typically one; floating rules carry many
    pub floating: bool,
    pub ipprotocol: AddrFamily,
    pub protocol: String,         // any | tcp | udp | icmp | …
    pub source: OpnEndpoint,
    pub destination: OpnEndpoint,
    pub disabled: bool,
    pub log: bool,
    pub quick: bool,
    pub descr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnNatPortForward {
    pub interface: String,
    pub protocol: String,
    pub source: OpnEndpoint,
    pub destination: OpnEndpoint,
    pub target: String,           // redirect IP
    pub local_port: Option<String>, // redirect port (single or range)
    pub disabled: bool,
    pub descr: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnNatOutbound {
    pub interface: String,
    pub protocol: String,
    pub source: OpnEndpoint,
    pub destination: OpnEndpoint,
    pub target: Option<String>,   // empty / absent = use interface address
    pub disabled: bool,
    pub descr: Option<String>,
    /// `<nonat>1</nonat>` — explicit "do not NAT this traffic" rule. Becomes
    /// a pf `no nat ...` rule rather than a regular SNAT/masq.
    pub nonat: bool,
    /// `<staticnatport>1</staticnatport>` — preserve source port instead of
    /// rewriting it. Becomes pf's `static-port` keyword.
    pub staticnatport: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnNatOneToOne {
    pub interface: String,
    pub external: String,
    pub internal: String,
    pub destination: OpnEndpoint,
    pub disabled: bool,
    pub descr: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OpnNat {
    pub mode: Option<String>,                   // automatic | hybrid | manual | disabled
    pub port_forwards: Vec<OpnNatPortForward>,
    pub outbound: Vec<OpnNatOutbound>,
    pub onetoone: Vec<OpnNatOneToOne>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnAlias {
    pub name: String,
    pub kind: String,             // host | network | port | url | urltable | geoip
    pub content: Vec<String>,     // entries (may be alias references themselves)
    pub descr: Option<String>,
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnGateway {
    pub name: String,
    pub interface: Option<String>,
    pub gateway: String,          // IP, or `dynamic` for DHCP-derived
    pub ipprotocol: AddrFamily,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpnRoute {
    pub network: String,
    pub gateway: String,          // resolves to the IP from <gateways> when possible
    pub gateway_name: String,     // original name for diagnostics
    pub disabled: bool,
    pub descr: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OpnSystem {
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub dns_servers: Vec<String>,
    pub timezone: Option<String>,
    pub timeservers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OpnConfig {
    pub kind: ConfigKind,         // OPNsense vs pfSense, for downstream UX
    pub version: Option<String>,  // <version> or root attribute
    pub system: OpnSystem,
    pub aliases: Vec<OpnAlias>,
    pub gateways: Vec<OpnGateway>,
    pub rules: Vec<OpnRule>,
    pub nat: OpnNat,
    pub routes: Vec<OpnRoute>,
    pub interface_names: Vec<String>, // every iface keyword referenced by rules/NAT/routes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum ConfigKind {
    #[default]
    Opnsense,
    Pfsense,
}
