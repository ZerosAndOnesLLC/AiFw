use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;

/// An address expression usable in pf rules. Serialized as a flat string
/// ("any", "192.168.1.1", "10.0.0.0/8", "`<table>`").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Match any address (pf `any`)
    Any,
    /// A single host IP
    Single(IpAddr),
    /// A CIDR network: base address and prefix length
    Network(IpAddr, u8),
    /// A pf table reference by name (rendered as `<name>`)
    Table(String),
}

/// Serialize Address as a flat string: "any", "10.0.0.0/8", "192.168.1.1", "`<table>`"
impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Deserialize Address from a flat string or from the legacy enum format.
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(deserializer)?;
        match v {
            serde_json::Value::String(s) => Address::parse(&s).map_err(serde::de::Error::custom),
            // Legacy: {"Network":["10.0.0.0",8]} / {"Single":"1.2.3.4"} / "Any"
            serde_json::Value::Object(ref map) => {
                if let Some(arr) = map.get("Network").and_then(|v| v.as_array())
                    && arr.len() == 2
                {
                    let ip: IpAddr = arr[0]
                        .as_str()
                        .unwrap_or("0.0.0.0")
                        .parse()
                        .map_err(serde::de::Error::custom)?;
                    let prefix = arr[1].as_u64().unwrap_or(32) as u8;
                    return Ok(Address::Network(ip, prefix));
                }
                if let Some(s) = map.get("Single").and_then(|v| v.as_str()) {
                    let ip: IpAddr = s.parse().map_err(serde::de::Error::custom)?;
                    return Ok(Address::Single(ip));
                }
                if let Some(s) = map.get("Table").and_then(|v| v.as_str()) {
                    Address::validate_table_name(s).map_err(serde::de::Error::custom)?;
                    return Ok(Address::Table(s.to_string()));
                }
                Ok(Address::Any)
            }
            _ => Ok(Address::Any),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Any => write!(f, "any"),
            Address::Single(ip) => write!(f, "{ip}"),
            Address::Network(ip, prefix) => write!(f, "{ip}/{prefix}"),
            Address::Table(name) => write!(f, "<{name}>"),
        }
    }
}

impl Address {
    /// Validate a pf table name. pf table names are letters, digits, `_` and
    /// `-`, 1-31 characters. Rejecting anything else (notably whitespace and
    /// newlines) prevents pf rule injection: `Display` renders a table as
    /// `<{name}>` straight into pf rule text, so an embedded newline would let
    /// the rest of the name be parsed by pf as a separate rule.
    pub fn validate_table_name(name: &str) -> crate::Result<()> {
        if name.is_empty() || name.len() > 31 {
            return Err(crate::AifwError::Validation(
                "pf table name must be 1-31 characters".to_string(),
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(crate::AifwError::Validation(
                "pf table name contains invalid characters (allowed: alphanumeric, _, -)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Parse from a flat string: "any" (also "interface"/"interface address"),
    /// "`<table>`" (name validated), "ip/prefix", or a bare IP. Fails with
    /// `Validation` on malformed input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("any")
            || s.eq_ignore_ascii_case("interface")
            || s.eq_ignore_ascii_case("interface address")
        {
            return Ok(Address::Any);
        }
        if s.starts_with('<') && s.ends_with('>') {
            let name = &s[1..s.len() - 1];
            Address::validate_table_name(name)?;
            return Ok(Address::Table(name.to_string()));
        }
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|e| crate::AifwError::Validation(format!("invalid IP: {e}")))?;
            let prefix: u8 = prefix_str
                .parse()
                .map_err(|e| crate::AifwError::Validation(format!("invalid prefix: {e}")))?;
            return Ok(Address::Network(ip, prefix));
        }
        let ip: IpAddr = s
            .parse()
            .map_err(|e| crate::AifwError::Validation(format!("invalid address '{s}': {e}")))?;
        Ok(Address::Single(ip))
    }
}

/// A single TCP/UDP port number
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Port(pub u16);

/// An inclusive port range; start == end represents a single port
/// (displayed as `start:end` or just the port)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    /// First port in the range (inclusive)
    pub start: u16,
    /// Last port in the range (inclusive)
    pub end: u16,
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}:{}", self.start, self.end)
        }
    }
}

/// A network interface name (e.g. "em0"), passed through to pf verbatim
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interface(pub String);

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
