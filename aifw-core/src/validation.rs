use aifw_common::{Address, AifwError, Protocol, Result, Rule};
use std::net::IpAddr;

pub fn validate_rule(rule: &Rule) -> Result<()> {
    validate_address(&rule.rule_match.src_addr)?;
    validate_address(&rule.rule_match.dst_addr)?;

    if let Some(ref port) = rule.rule_match.src_port {
        if port.start > port.end {
            return Err(AifwError::Validation(
                "source port range start must be <= end".to_string(),
            ));
        }
        validate_port_protocol(&rule.protocol)?;
    }

    if let Some(ref port) = rule.rule_match.dst_port {
        if port.start > port.end {
            return Err(AifwError::Validation(
                "destination port range start must be <= end".to_string(),
            ));
        }
        validate_port_protocol(&rule.protocol)?;
    }

    if rule.priority < 0 || rule.priority > 10000 {
        return Err(AifwError::Validation(
            "priority must be between 0 and 10000".to_string(),
        ));
    }

    Ok(())
}

fn validate_address(addr: &Address) -> Result<()> {
    match addr {
        Address::Network(ip, prefix) => {
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if *prefix > max_prefix {
                return Err(AifwError::Validation(format!(
                    "prefix length {prefix} exceeds maximum {max_prefix} for {}",
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                )));
            }
        }
        Address::Table(name) => {
            if name.is_empty() {
                return Err(AifwError::Validation(
                    "table name cannot be empty".to_string(),
                ));
            }
            if name.len() > 31 {
                return Err(AifwError::Validation(
                    "table name exceeds pf maximum of 31 characters".to_string(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_port_protocol(proto: &Protocol) -> Result<()> {
    match proto {
        Protocol::Tcp | Protocol::Udp => Ok(()),
        _ => Err(AifwError::Validation(
            "port matching requires TCP or UDP protocol".to_string(),
        )),
    }
}
