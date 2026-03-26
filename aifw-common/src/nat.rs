use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
        }
    }
}

impl NatType {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "snat" => Ok(NatType::Snat),
            "dnat" | "rdr" => Ok(NatType::Dnat),
            "masquerade" | "masq" => Ok(NatType::Masquerade),
            "binat" => Ok(NatType::Binat),
            "nat64" => Ok(NatType::Nat64),
            "nat46" => Ok(NatType::Nat46),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown NAT type: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NatStatus {
    Active,
    Disabled,
}

/// Redirect target for NAT rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatRedirect {
    pub address: Address,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: Uuid,
    pub nat_type: NatType,
    pub interface: Interface,
    pub protocol: crate::Protocol,
    pub src_addr: Address,
    pub src_port: Option<PortRange>,
    pub dst_addr: Address,
    pub dst_port: Option<PortRange>,
    pub redirect: NatRedirect,
    pub label: Option<String>,
    pub status: NatStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl NatRule {
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
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate the pf NAT rule syntax
    pub fn to_pf_rule(&self) -> String {
        match self.nat_type {
            NatType::Snat => self.to_pf_nat(),
            NatType::Dnat => self.to_pf_rdr(),
            NatType::Masquerade => self.to_pf_masquerade(),
            NatType::Binat => self.to_pf_binat(),
            NatType::Nat64 => self.to_pf_nat64(),
            NatType::Nat46 => self.to_pf_nat46(),
        }
    }

    /// `nat on <iface> [proto <proto>] from <src> to <dst> -> <redirect>`
    fn to_pf_nat(&self) -> String {
        let mut parts = vec![format!("nat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> {}", self.redirect));
        self.push_label(&mut parts);
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

    /// `nat on <iface> [proto <proto>] from <src> to <dst> -> (<iface>)`
    fn to_pf_masquerade(&self) -> String {
        let mut parts = vec![format!("nat on {}", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> ({})", self.interface));
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

    /// NAT64: `nat on <iface> inet6 from <src> to <dst> -> <redirect>`
    fn to_pf_nat64(&self) -> String {
        let mut parts = vec![format!("nat on {} inet6", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> {}", self.redirect));
        self.push_label(&mut parts);
        parts.join(" ")
    }

    /// NAT46: `nat on <iface> inet from <src> to <dst> -> <redirect>`
    fn to_pf_nat46(&self) -> String {
        let mut parts = vec![format!("nat on {} inet", self.interface)];
        self.push_proto(&mut parts);
        self.push_from_to(&mut parts);
        parts.push(format!("-> {}", self.redirect));
        self.push_label(&mut parts);
        parts.join(" ")
    }

    fn push_proto(&self, parts: &mut Vec<String>) {
        if self.protocol != crate::Protocol::Any {
            parts.push(format!("proto {}", self.protocol));
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

    fn push_label(&self, parts: &mut Vec<String>) {
        if let Some(ref label) = self.label {
            parts.push(format!("label \"{label}\""));
        }
    }
}
