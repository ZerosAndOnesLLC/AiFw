use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of NAT translation a [`NatRule`] performs (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// Source NAT — rewrite source address on outbound traffic
    Snat,
    /// Destination NAT / port forwarding (rdr)
    Dnat,
    /// Masquerading — dynamic SNAT using interface address
    Masquerade,
    /// Bidirectional NAT
    Binat,
    /// NAT64 — translate IPv6 to IPv4
    Nat64,
    /// NAT46 — translate IPv4 to IPv6
    Nat46,
    /// NAT bypass — pf `no nat`: matching traffic is exempted from any
    /// later `nat` rule (e.g. keep site-to-site VPN traffic un-NATed).
    /// Has no translation target. Order matters: place before the SNAT /
    /// masquerade rule it should exempt (#253).
    #[serde(rename = "nonat")]
    NoNat,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Snat => write!(f, "snat"),
            NatType::Dnat => write!(f, "dnat"),
            NatType::Masquerade => write!(f, "masquerade"),
            NatType::Binat => write!(f, "binat"),
            NatType::Nat64 => write!(f, "nat64"),
            NatType::Nat46 => write!(f, "nat46"),
            NatType::NoNat => write!(f, "nonat"),
        }
    }
}

impl NatType {
    /// Parse from a case-insensitive string; accepts synonyms
    /// ("rdr" for dnat, "masq" for masquerade). Fails with `Validation`
    /// on anything else.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "snat" => Ok(NatType::Snat),
            "dnat" | "rdr" => Ok(NatType::Dnat),
            "masquerade" | "masq" => Ok(NatType::Masquerade),
            "binat" => Ok(NatType::Binat),
            "nat64" => Ok(NatType::Nat64),
            "nat46" => Ok(NatType::Nat46),
            "nonat" | "no-nat" | "no_nat" => Ok(NatType::NoNat),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown NAT type: {s}"
            ))),
        }
    }
}

/// Enabled/disabled state of a NAT rule
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NatStatus {
    /// Rule is enforced in pf
    Active,
    /// Rule is stored but not pushed to pf
    Disabled,
}

/// Redirect target for NAT rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatRedirect {
    /// Address traffic is translated to
    pub address: Address,
    /// Optional target port (range); `None` keeps the original port
    pub port: Option<PortRange>,
}

impl std::fmt::Display for NatRedirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)?;
        if let Some(ref port) = self.port {
            write!(f, " port {port}")?;
        }
        Ok(())
    }
}

/// A NAT rule, rendered to pf `nat`/`rdr`/`binat` syntax via [`Self::to_pf_rules`]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    /// Unique rule ID
    pub id: Uuid,
    /// Kind of translation (SNAT, DNAT, masquerade, ...)
    pub nat_type: NatType,
    /// Interface the rule is applied on (`nat on <iface>`)
    pub interface: Interface,
    /// Protocol to match; `Any` omits the `proto` clause
    pub protocol: crate::Protocol,
    /// Source address to match
    pub src_addr: Address,
    /// Optional source port (range) to match
    pub src_port: Option<PortRange>,
    /// Destination address to match (for DNAT, the external address being redirected)
    pub dst_addr: Address,
    /// Optional destination port (range) to match
    pub dst_port: Option<PortRange>,
    /// Translation target (address and optional port)
    pub redirect: NatRedirect,
    /// Optional display label; stored in the DB only — pf NAT rules don't support labels
    pub label: Option<String>,
    /// Whether the rule is active or disabled
    pub status: NatStatus,
    /// Preserve the original source port on SNAT / masquerade (pf
    /// `static-port`). Some protocols (SIP, some VPNs, games) break when
    /// the source port is rewritten. Ignored for other NAT types (#253).
    #[serde(default)]
    pub static_port: bool,
    /// Creation timestamp (UTC)
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp (UTC)
    pub updated_at: DateTime<Utc>,
}

impl NatRule {
    /// Create an active rule with a random ID, no ports/label, and both
    /// timestamps set to now
    pub fn new(
        nat_type: NatType,
        interface: Interface,
        protocol: crate::Protocol,
        src_addr: Address,
        dst_addr: Address,
        redirect: NatRedirect,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            nat_type,
            interface,
            protocol,
            src_addr,
            src_port: None,
            dst_addr,
            dst_port: None,
            redirect,
            label: None,
            status: NatStatus::Active,
            static_port: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate the pf NAT rule syntax (may return multiple rules for DNAT + reflection)
    pub fn to_pf_rules(&self) -> Vec<String> {
        match self.nat_type {
            NatType::Snat => vec![self.to_pf_nat()],
            NatType::Dnat => {
                let mut rules = vec![self.to_pf_rdr()];
                // NAT reflection: SNAT forwarded traffic so replies route back through the firewall.
                // Without this, the redirect target may reply directly to the client (asymmetric routing),
                // causing pf to drop the return packets because they don't match any state.
                rules.push(self.to_pf_rdr_reflection());
                rules
            }
            NatType::Masquerade => vec![self.to_pf_masquerade()],
            NatType::Binat => vec![self.to_pf_binat()],
            NatType::Nat64 => vec![self.to_pf_nat64()],
            NatType::Nat46 => vec![self.to_pf_nat46()],
            NatType::NoNat => vec![self.to_pf_no_nat()],
        }
    }

    /// Legacy single-rule accessor (for callers that expect one string)
    pub fn to_pf_rule(&self) -> String {
        self.to_pf_rules().join("\n")
    }

    /// NAT reflection companion for rdr rules.
    /// `nat on <iface> [proto <proto>] from any to <redirect_addr> [port <port>] -> (<iface>)`
    /// Ensures return traffic from the redirect target routes back through the firewall.
    fn to_pf_rdr_reflection(&self) -> String {
        let mut parts = vec![format!("nat on {}", self.interface)];
        self.push_proto(&mut parts);
        parts.push(format!("from any to {}", self.redirect));
        parts.push(format!("-> ({})", self.interface));
        parts.join(" ")
    }

    /// `nat on <iface> [proto <proto>] from <src> to <dst> -> <redirect> [static-port]`
    fn to_pf_nat(&self) -> String {
        let mut parts = vec![format!("nat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> {}", self.redirect));
        self.push_static_port(&mut parts);
        self.push_label(&mut parts);
        parts.join(" ")
    }

    /// `no nat on <iface> [proto <proto>] from <src> to <dst>` — exempts
    /// matching traffic from later `nat` rules. No translation target.
    fn to_pf_no_nat(&self) -> String {
        let mut parts = vec![format!("no nat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.join(" ")
    }

    /// `rdr on <iface> [proto <proto>] from <src> to <dst> [port <port>] -> <redirect>`
    fn to_pf_rdr(&self) -> String {
        let mut parts = vec![format!("rdr on {}", self.interface)];
        self.push_proto(&mut parts);

        // source
        if self.src_addr != Address::Any {
            parts.push(format!("from {}", self.src_addr));
            if let Some(ref port) = self.src_port {
                parts.push(format!("port {port}"));
            }
        }

        // destination (the external address being redirected)
        parts.push(format!("to {}", self.dst_addr));
        if let Some(ref port) = self.dst_port {
            parts.push(format!("port {port}"));
        }

        parts.push(format!("-> {}", self.redirect));
        self.push_label(&mut parts);
        parts.join(" ")
    }

    /// `nat on <iface> [proto <proto>] from <src> to <dst> -> (<iface>) [static-port]`
    fn to_pf_masquerade(&self) -> String {
        let mut parts = vec![format!("nat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> ({})", self.interface));
        self.push_static_port(&mut parts);
        self.push_label(&mut parts);
        parts.join(" ")
    }

    /// `binat on <iface> from <src> to <dst> -> <redirect>`
    fn to_pf_binat(&self) -> String {
        let mut parts = vec![format!("binat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> {}", self.redirect));
        self.push_label(&mut parts);
        parts.join(" ")
    }

    /// NAT64 (IPv6→IPv4), pf `af-to` address-family translation (FreeBSD 15+):
    /// `pass in quick on <iface> inet6 [proto <p>] from <src> to <prefix/96> af-to inet from <v4-src> [label "..."]`
    ///
    /// `af-to` is a filter-class rule and only valid on inbound rules; `quick`
    /// is required because the main ruleset's default policy follows the
    /// anchor hooks and would otherwise override the pass (last-match wins).
    /// The translated destination is the IPv4 embedded in the low 32 bits of
    /// the matched /96 prefix (RFC 6052).
    fn to_pf_nat64(&self) -> String {
        let mut parts = vec![format!("pass in quick on {} inet6", self.interface)];
        self.push_af_proto(&mut parts, true);
        self.push_from_to(&mut parts);
        parts.push(format!("af-to inet from {}", self.redirect.address));
        self.push_filter_label(&mut parts);
        parts.join(" ")
    }

    /// NAT46 (IPv4→IPv6), pf `af-to` address-family translation (FreeBSD 15+):
    /// `pass in quick on <iface> inet [proto <p>] from <src> to <v4-dst> af-to inet6 from <v6-src> [label "..."]`
    ///
    /// The translated destination defaults to the RFC 6052 embedding of the
    /// original IPv4 destination in the /96 subnet of the new IPv6 source.
    fn to_pf_nat46(&self) -> String {
        let mut parts = vec![format!("pass in quick on {} inet", self.interface)];
        self.push_af_proto(&mut parts, false);
        self.push_from_to(&mut parts);
        parts.push(format!("af-to inet6 from {}", self.redirect.address));
        self.push_filter_label(&mut parts);
        parts.join(" ")
    }

    fn push_proto(&self, parts: &mut Vec<String>) {
        if self.protocol != crate::Protocol::Any {
            parts.push(format!("proto {}", self.protocol));
        }
    }

    /// Protocol clause for `af-to` rules. The keyword must match the
    /// pre-translation family (a NAT64 rule matches IPv6 ingress), so
    /// `icmp`/`icmp6` are normalized to the matching side's family.
    fn push_af_proto(&self, parts: &mut Vec<String>, inet6_match: bool) {
        let proto = match (self.protocol, inet6_match) {
            (crate::Protocol::Any, _) => return,
            (crate::Protocol::Icmp, true) => "icmp6".to_string(),
            (crate::Protocol::Icmp6, false) => "icmp".to_string(),
            (p, _) => p.to_string(),
        };
        parts.push(format!("proto {proto}"));
    }

    /// Label clause for filter-class (`af-to`) rules — unlike nat-class
    /// rules, pass rules support pf labels for per-rule counters.
    fn push_filter_label(&self, parts: &mut Vec<String>) {
        if let Some(ref label) = self.label {
            parts.push(format!("label \"{label}\""));
        }
    }

    fn push_from_to(&self, parts: &mut Vec<String>) {
        // source
        let mut from = format!("from {}", self.src_addr);
        if let Some(ref port) = self.src_port {
            from.push_str(&format!(" port {port}"));
        }
        parts.push(from);

        // destination
        let mut to = format!("to {}", self.dst_addr);
        if let Some(ref port) = self.dst_port {
            to.push_str(&format!(" port {port}"));
        }
        parts.push(to);
    }

    /// pf `static-port` pool option (SNAT / masquerade only).
    fn push_static_port(&self, parts: &mut Vec<String>) {
        if self.static_port {
            parts.push("static-port".to_string());
        }
    }

    fn push_label(&self, _parts: &mut Vec<String>) {
        // pf NAT rules do not support the label keyword — labels are filter-only.
        // The label is stored in the DB for UI display purposes only.
    }
}

/// Embed an IPv4 address into an IPv6 /96 prefix per RFC 6052 §2.2 — the
/// NAT64 address mapping (e.g. `64:ff9b::/96` + `10.99.2.2` →
/// `64:ff9b::a63:202`). This is the address an IPv6-only client uses to
/// reach an IPv4 host through a NAT64 rule.
pub fn embed_rfc6052(prefix: std::net::Ipv6Addr, v4: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    let mut octets = prefix.octets();
    octets[12..16].copy_from_slice(&v4.octets());
    std::net::Ipv6Addr::from(octets)
}
