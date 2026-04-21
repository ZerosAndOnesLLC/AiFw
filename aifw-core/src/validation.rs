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

    if let Some(ref iface) = rule.interface {
        validate_interface_name(&iface.0)?;
    }

    if let Some(ref label) = rule.label {
        validate_label(label)?;
    }

    Ok(())
}

/// Validate interface name — alphanumeric, underscore, hyphen, dot only. Max 15 chars.
pub fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(AifwError::Validation(
            "interface name must be 1-15 characters".to_string(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AifwError::Validation(
            "interface name contains invalid characters (allowed: alphanumeric, _, -, .)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Validate pf rule label — no quotes, semicolons, newlines, or other injection chars. Max 63 chars.
pub fn validate_label(label: &str) -> Result<()> {
    if label.len() > 63 {
        return Err(AifwError::Validation(
            "label must be at most 63 characters".to_string(),
        ));
    }
    if label.contains('"')
        || label.contains('\'')
        || label.contains(';')
        || label.contains('\n')
        || label.contains('\r')
        || label.contains('\\')
        || label.contains('\0')
    {
        return Err(AifwError::Validation(
            "label contains invalid characters (quotes, semicolons, backslashes, newlines not allowed)".to_string(),
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
        Protocol::Tcp | Protocol::Udp | Protocol::TcpUdp => Ok(()),
        _ => Err(AifwError::Validation(
            "port matching requires TCP, UDP, or TCP/UDP protocol".to_string(),
        )),
    }
}
