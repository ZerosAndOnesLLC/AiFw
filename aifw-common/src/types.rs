use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Address {
    Any,
    Single(IpAddr),
    Network(IpAddr, u8),
    Table(String),
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
