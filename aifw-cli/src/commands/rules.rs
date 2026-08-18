//! `aifw init` and `aifw rules …`.

use aifw_common::{Address, Interface, Protocol, Rule, RuleMatch};
use aifw_core::Database;
use std::path::Path;
use uuid::Uuid;

use super::common::*;

pub async fn init(db_path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = db_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let _db = Database::new(db_path).await?;
    println!("Initialized AiFw database at {}", db_path.display());
    Ok(())
}

pub async fn rules_add(
    db_path: &Path,
    action: &str,
    direction: &str,
    proto: &str,
    src: &str,
    src_port: Option<&str>,
    dst: &str,
    dst_port: Option<&str>,
    interface: Option<&str>,
    priority: i32,
    log: bool,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;

    let rule_match = RuleMatch {
        src_addr: Address::parse(src)?,
        src_port: src_port.map(parse_port).transpose()?,
        dst_addr: Address::parse(dst)?,
        dst_port: dst_port.map(parse_port).transpose()?,
    };

    let mut rule = Rule::new(
        parse_action(action)?,
        parse_direction(direction)?,
        Protocol::parse(proto)?,
        rule_match,
    );
    rule.priority = priority;
    rule.log = log;
    rule.label = label.map(String::from);
    rule.interface = interface.map(|s| Interface(s.to_string()));

    let rule = engine.add_rule(rule).await?;
    println!("Added rule {}", rule.id);
    println!("  pf: {}", rule.to_pf_rule("aifw"));
    Ok(())
}

pub async fn rules_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete_rule(uuid).await?;
    println!("Removed rule {id}");
    Ok(())
}

pub async fn rules_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;
    let rules = engine.list_rules().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No rules configured");
        return Ok(());
    }

    println!(
        "{:<38} {:<6} {:<6} {:<5} {:<5} {:<20} {:<20} LABEL",
        "ID", "PRI", "ACTION", "DIR", "PROTO", "SOURCE", "DESTINATION"
    );
    println!("{}", "-".repeat(110));

    for rule in &rules {
        let src = format!(
            "{}{}",
            rule.rule_match.src_addr,
            rule.rule_match
                .src_port
                .as_ref()
                .map(|p| format!(":{p}"))
                .unwrap_or_default()
        );
        let dst = format!(
            "{}{}",
            rule.rule_match.dst_addr,
            rule.rule_match
                .dst_port
                .as_ref()
                .map(|p| format!(":{p}"))
                .unwrap_or_default()
        );
        let status = match rule.status {
            aifw_common::RuleStatus::Active => "",
            aifw_common::RuleStatus::Disabled => " [disabled]",
        };
        println!(
            "{:<38} {:<6} {:<6} {:<5} {:<5} {:<20} {:<20} {}{}",
            rule.id,
            rule.priority,
            rule.action,
            rule.direction,
            rule.protocol,
            src,
            dst,
            rule.label.as_deref().unwrap_or(""),
            status,
        );
    }

    println!("\n{} rule(s) total", rules.len());
    Ok(())
}
