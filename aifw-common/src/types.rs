use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Any,
    Single(IpAddr),
    Network(IpAddr, u8),
    Table(String),
}

/// Serialize Address as a flat string: "any", "10.0.0.0/8", "192.168.1.1", "<table>"
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
            serde_json::Value::String(s) => {
                Address::parse(&s).map_err(serde::de::Error::custom)
            }
            // Legacy: {"Network":["10.0.0.0",8]} / {"Single":"1.2.3.4"} / "Any"
            serde_json::Value::Object(ref map) => {
                if let Some(arr) = map.get("Network").and_then(|v| v.as_array()) {
                    if arr.len() == 2 {
                        let ip: IpAddr = arr[0].as_str().unwrap_or("0.0.0.0").parse()
                            .map_err(serde::de::Error::custom)?;
                        let prefix = arr[1].as_u64().unwrap_or(32) as u8;
                        return Ok(Address::Network(ip, prefix));
                    }
                }
                if let Some(s) = map.get("Single").and_then(|v| v.as_str()) {
                    let ip: IpAddr = s.parse().map_err(serde::de::Error::custom)?;
                    return Ok(Address::Single(ip));
                }
                if let Some(s) = map.get("Table").and_then(|v| v.as_str()) {
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
    pub fn parse(s: &str) -> crate::Result<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("any")
            || s.eq_ignore_ascii_case("interface")
            || s.eq_ignore_ascii_case("interface address")
        {
            return Ok(Address::Any);
        }
        if s.starts_with('<') && s.ends_with('>') {
            return Ok(Address::Table(s[1..s.len() - 1].to_string()));
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Port(pub u16);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interface(pub String);

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
