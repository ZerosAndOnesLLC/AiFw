//! `aifw nat …`.

use aifw_common::{Address, Interface, NatRedirect, NatRule, NatType, Protocol};
use std::path::Path;
use uuid::Uuid;

use super::common::*;

pub async fn nat_add(
    db_path: &Path,
    nat_type: &str,
    interface: &str,
    proto: &str,
    src: &str,
    src_port: Option<&str>,
    dst: &str,
    dst_port: Option<&str>,
    redirect: &str,
    redirect_port: Option<&str>,
    label: Option<&str>,
    static_port: bool,
    af_to_dst: Option<&str>,
) -> anyhow::Result<()> {
    let nat = create_nat_engine(db_path).await?;

    let mut rule = NatRule::new(
        NatType::parse(nat_type)?,
        Interface(interface.to_string()),
        Protocol::parse(proto)?,
        Address::parse(src)?,
        Address::parse(dst)?,
        NatRedirect {
            address: Address::parse(redirect)?,
            port: redirect_port.map(parse_port).transpose()?,
        },
    );
    rule.src_port = src_port.map(parse_port).transpose()?;
    rule.dst_port = dst_port.map(parse_port).transpose()?;
    rule.label = label.map(String::from);
    rule.static_port = static_port;
    rule.af_to_dst = af_to_dst
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Address::parse)
        .transpose()?;

    let rule = nat.add_rule(rule).await.map_err(|e| {
        let msg = e.to_string();
        match nat_flag_hint(&msg) {
            Some(hint) => anyhow::anyhow!("{msg}\n  hint: {hint}"),
            None => anyhow::anyhow!(msg),
        }
    })?;
    println!("Added NAT rule {}", rule.id);
    println!("  pf: {}", rule.to_pf_rule());
    if rule.nat_type == NatType::Nat64
        && let aifw_common::Address::Network(std::net::IpAddr::V6(p6), 96) = rule.dst_addr
    {
        let example = aifw_common::embed_rfc6052(p6, std::net::Ipv4Addr::new(10, 0, 0, 1));
        println!("  IPv6 clients reach IPv4 hosts via {p6}/96 (e.g. 10.0.0.1 -> {example})");
    }
    Ok(())
}

/// Map engine validation messages to the CLI flag the user should fix.
fn nat_flag_hint(msg: &str) -> Option<&'static str> {
    if msg.contains("nat64 destination") {
        Some(
            "set --dst to an IPv6 /96 prefix, e.g. --dst 64:ff9b::/96 (or omit --dst for the default)",
        )
    } else if msg.contains("nat46 destination") {
        Some("set --dst to the IPv4 address being reached, e.g. --dst 10.99.1.1")
    } else if msg.contains("translation source") {
        Some(
            "set --redirect to a single address the firewall owns in the translated family (IPv4 for nat64, IPv6 for nat46)",
        )
    } else if msg.contains("redirect port") {
        Some("drop --redirect-port — af-to translates addresses, not ports")
    } else if msg.contains("source address must be") {
        Some("fix --src: it must match the rule's ingress family (IPv6 for nat64, IPv4 for nat46)")
    } else if msg.contains("static_port is only valid") {
        Some("drop --static-port — it only applies to --type snat / masquerade")
    } else if msg.contains("af_to_dst (translated destination) is only valid") {
        Some("drop --af-to-dst — it only applies to --type nat46 / nat64")
    } else if msg.contains("translated destination must be a single") {
        Some(
            "--af-to-dst must be one host address in the translated family (IPv6 for nat46, IPv4 for nat64)",
        )
    } else if msg.contains("no-nat rules") {
        Some("drop --redirect / --redirect-port — nonat exempts traffic and has no target")
    } else {
        None
    }
}

/// Print the RFC 6052 embedded address for a prefix + IPv4 pair.
pub fn nat_embed(prefix: &str, ipv4: &str) -> anyhow::Result<()> {
    let p: std::net::Ipv6Addr = prefix
        .split('/')
        .next()
        .unwrap_or(prefix)
        .parse()
        .map_err(|_| anyhow::anyhow!("'{prefix}' is not a valid IPv6 prefix"))?;
    let v4: std::net::Ipv4Addr = ipv4
        .parse()
        .map_err(|_| anyhow::anyhow!("'{ipv4}' is not a valid IPv4 address"))?;
    println!("{}", aifw_common::embed_rfc6052(p, v4));
    Ok(())
}

pub async fn nat_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let nat = create_nat_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    nat.delete_rule(uuid).await?;
    println!("Removed NAT rule {id}");
    Ok(())
}

pub async fn nat_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let nat = create_nat_engine(db_path).await?;
    let rules = nat.list_rules().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No NAT rules configured");
        return Ok(());
    }

    println!(
        "{:<38} {:<12} {:<8} {:<5} {:<20} {:<20} {:<20} LABEL",
        "ID", "TYPE", "IFACE", "PROTO", "SOURCE", "DESTINATION", "REDIRECT"
    );
    println!("{}", "-".repeat(130));

    for rule in &rules {
        let src = format!(
            "{}{}",
            rule.src_addr,
            rule.src_port
                .as_ref()
                .map(|p| format!(":{p}"))
                .unwrap_or_default()
        );
        let dst = format!(
            "{}{}",
            rule.dst_addr,
            rule.dst_port
                .as_ref()
                .map(|p| format!(":{p}"))
                .unwrap_or_default()
        );
        // Cross-family rules read as a direction, not an address rewrite.
        let af_dst = rule
            .af_to_dst
            .as_ref()
            .map(|d| format!(" to {d}"))
            .unwrap_or_default();
        let redir = match rule.nat_type {
            NatType::Nat64 => format!("v6->v4 via {}{af_dst}", rule.redirect.address),
            NatType::Nat46 => format!("v4->v6 via {}{af_dst}", rule.redirect.address),
            NatType::NoNat => "(bypass — no NAT)".to_string(),
            NatType::Masquerade => format!("({})", rule.interface),
            _ => format!("{}", rule.redirect),
        };
        let redir = if rule.static_port {
            format!("{redir} static-port")
        } else {
            redir
        };
        let status = match rule.status {
            aifw_common::NatStatus::Active => "",
            aifw_common::NatStatus::Disabled => " [disabled]",
        };
        println!(
            "{:<38} {:<12} {:<8} {:<5} {:<20} {:<20} {:<20} {}{}",
            rule.id,
            rule.nat_type,
            rule.interface,
            rule.protocol,
            src,
            dst,
            redir,
            rule.label.as_deref().unwrap_or(""),
            status,
        );
    }

    println!("\n{} NAT rule(s) total", rules.len());
    Ok(())
}
