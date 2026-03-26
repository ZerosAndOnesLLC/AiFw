use aifw_common::{
    Action, Address, Direction, Interface, NatRedirect, NatRule, NatType, PortRange, Protocol, Rule,
    RuleMatch,
};
use aifw_core::{Database, NatEngine, RuleEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

fn parse_port(s: &str) -> anyhow::Result<PortRange> {
    if let Some((start, end)) = s.split_once(':') {
        Ok(PortRange {
            start: start.parse()?,
            end: end.parse()?,
        })
    } else {
        let port: u16 = s.parse()?;
        Ok(PortRange {
            start: port,
            end: port,
        })
    }
}

fn parse_action(s: &str) -> anyhow::Result<Action> {
    match s {
        "pass" => Ok(Action::Pass),
        "block" => Ok(Action::Block),
        "block-drop" => Ok(Action::BlockDrop),
        "block-return" => Ok(Action::BlockReturn),
        _ => anyhow::bail!("unknown action: {s} (use pass, block, block-drop, block-return)"),
    }
}

fn parse_direction(s: &str) -> anyhow::Result<Direction> {
    match s {
        "in" => Ok(Direction::In),
        "out" => Ok(Direction::Out),
        "any" => Ok(Direction::Any),
        _ => anyhow::bail!("unknown direction: {s} (use in, out, any)"),
    }
}

async fn create_engine(db_path: &Path) -> anyhow::Result<RuleEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    Ok(RuleEngine::new(db, pf))
}

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
        "{:<38} {:<6} {:<6} {:<5} {:<5} {:<20} {:<20} {}",
        "ID", "PRI", "ACTION", "DIR", "PROTO", "SOURCE", "DESTINATION", "LABEL"
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

pub async fn status(db_path: &Path) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;

    let pf = engine.pf();
    let stats = pf.get_stats().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let rules = engine.list_rules().await?;
    let active_rules = rules
        .iter()
        .filter(|r| r.status == aifw_common::RuleStatus::Active)
        .count();

    println!("AiFw Status");
    println!("===========");
    println!("pf running:     {}", if stats.running { "yes" } else { "no" });
    println!("pf states:      {}", stats.states_count);
    println!("pf rules (pf):  {}", stats.rules_count);
    println!("aifw rules:     {} ({} active)", rules.len(), active_rules);
    println!("packets in:     {}", stats.packets_in);
    println!("packets out:    {}", stats.packets_out);
    println!("bytes in:       {}", stats.bytes_in);
    println!("bytes out:      {}", stats.bytes_out);

    Ok(())
}

pub async fn reload(db_path: &Path) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;
    engine.apply_rules().await?;
    let rules = engine.list_rules().await?;

    let nat = create_nat_engine(db_path).await?;
    nat.apply_rules().await?;
    let nat_rules = nat.list_rules().await?;

    println!(
        "Reloaded {} filter rules and {} NAT rules into pf anchor",
        rules.len(),
        nat_rules.len()
    );
    Ok(())
}

async fn create_nat_engine(db_path: &Path) -> anyhow::Result<NatEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    Ok(NatEngine::new(db.pool().clone(), pf))
}

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

    let rule = nat.add_rule(rule).await?;
    println!("Added NAT rule {}", rule.id);
    println!("  pf: {}", rule.to_pf_rule());
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
        "{:<38} {:<12} {:<8} {:<5} {:<20} {:<20} {:<20} {}",
        "ID", "TYPE", "IFACE", "PROTO", "SOURCE", "DESTINATION", "REDIRECT", "LABEL"
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
        let redir = format!("{}", rule.redirect);
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
