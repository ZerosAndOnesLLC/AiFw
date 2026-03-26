use aifw_common::{
    Action, Address, Bandwidth, CountryCode, Direction, GeoIpAction, GeoIpRule, Interface,
    IpsecMode, IpsecProtocol, IpsecSa, NatRedirect, NatRule, NatType, PortRange, Protocol,
    QueueConfig, QueueType, RateLimitRule, Rule, RuleMatch, TrafficClass, WgPeer, WgTunnel,
};
use aifw_core::{Database, GeoIpEngine, NatEngine, RuleEngine, ShapingEngine, VpnEngine};
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

    let shaping = create_shaping_engine(db_path).await?;
    shaping.apply_queues().await?;
    shaping.apply_rate_limits().await?;
    let queues = shaping.list_queues().await?;
    let rate_limits = shaping.list_rate_limits().await?;

    println!(
        "Reloaded {} filter rules, {} NAT rules, {} queues, {} rate limits into pf",
        rules.len(),
        nat_rules.len(),
        queues.len(),
        rate_limits.len(),
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

// --- Queue commands ---

async fn create_shaping_engine(db_path: &Path) -> anyhow::Result<ShapingEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    let engine = ShapingEngine::new(db.pool().clone(), pf);
    engine.migrate().await?;
    Ok(engine)
}

pub async fn queue_add(
    db_path: &Path,
    name: &str,
    interface: &str,
    queue_type: &str,
    bandwidth: &str,
    class: &str,
    pct: Option<u8>,
    default: bool,
) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;

    let mut config = QueueConfig::new(
        Interface(interface.to_string()),
        QueueType::parse(queue_type)?,
        Bandwidth::parse(bandwidth)?,
        name.to_string(),
        TrafficClass::parse(class)?,
    );
    config.bandwidth_pct = pct;
    config.default = default;

    let config = engine.add_queue(config).await?;
    println!("Added queue {}", config.id);
    println!("  pf: {}", config.to_pf_queue());
    Ok(())
}

pub async fn queue_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete_queue(uuid).await?;
    println!("Removed queue {id}");
    Ok(())
}

pub async fn queue_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;
    let queues = engine.list_queues().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&queues)?);
        return Ok(());
    }

    if queues.is_empty() {
        println!("No queues configured");
        return Ok(());
    }

    println!(
        "{:<38} {:<15} {:<8} {:<8} {:<12} {:<12} {}",
        "ID", "NAME", "IFACE", "TYPE", "BANDWIDTH", "CLASS", "DEFAULT"
    );
    println!("{}", "-".repeat(100));

    for q in &queues {
        println!(
            "{:<38} {:<15} {:<8} {:<8} {:<12} {:<12} {}",
            q.id,
            q.name,
            q.interface,
            q.queue_type,
            q.bandwidth.to_string(),
            q.traffic_class,
            if q.default { "yes" } else { "" },
        );
    }

    println!("\n{} queue(s) total", queues.len());
    Ok(())
}

// --- Rate limit commands ---

pub async fn ratelimit_add(
    db_path: &Path,
    name: &str,
    proto: &str,
    max_conn: u32,
    window: u32,
    table: &str,
    dst_port: Option<&str>,
    interface: Option<&str>,
    flush: bool,
) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;

    let mut rule = RateLimitRule::new(
        name.to_string(),
        Protocol::parse(proto)?,
        max_conn,
        window,
        table.to_string(),
    );
    rule.dst_port = dst_port.map(parse_port).transpose()?;
    rule.interface = interface.map(|s| Interface(s.to_string()));
    rule.flush_states = flush;

    let rule = engine.add_rate_limit(rule).await?;
    println!("Added rate limit {}", rule.id);
    println!("  pf: {}", rule.to_pf_rule());
    Ok(())
}

pub async fn ratelimit_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete_rate_limit(uuid).await?;
    println!("Removed rate limit {id}");
    Ok(())
}

pub async fn ratelimit_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;
    let rules = engine.list_rate_limits().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No rate limit rules configured");
        return Ok(());
    }

    println!(
        "{:<38} {:<15} {:<6} {:<10} {:<8} {:<20} {}",
        "ID", "NAME", "PROTO", "MAX_CONN", "WINDOW", "TABLE", "FLUSH"
    );
    println!("{}", "-".repeat(105));

    for r in &rules {
        println!(
            "{:<38} {:<15} {:<6} {:<10} {:<8} {:<20} {}",
            r.id,
            r.name,
            r.protocol,
            r.max_connections,
            format!("{}s", r.window_secs),
            r.overload_table,
            if r.flush_states { "yes" } else { "no" },
        );
    }

    println!("\n{} rate limit(s) total", rules.len());
    Ok(())
}

// --- VPN commands ---

async fn create_vpn_engine(db_path: &Path) -> anyhow::Result<VpnEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    let engine = VpnEngine::new(db.pool().clone(), pf);
    engine.migrate().await?;
    Ok(engine)
}

pub async fn vpn_wg_add(
    db_path: &Path,
    name: &str,
    interface: &str,
    port: u16,
    address: &str,
) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let tunnel = WgTunnel::new(
        name.to_string(),
        Interface(interface.to_string()),
        port,
        Address::parse(address)?,
    );
    let tunnel = engine.add_wg_tunnel(tunnel).await?;
    println!("Added WireGuard tunnel {}", tunnel.id);
    println!("  Interface:  {}", tunnel.interface);
    println!("  Port:       {}", tunnel.listen_port);
    println!("  Address:    {}", tunnel.address);
    println!("  Public Key: {}", tunnel.public_key);
    Ok(())
}

pub async fn vpn_wg_peer_add(
    db_path: &Path,
    tunnel_id: &str,
    name: &str,
    pubkey: &str,
    endpoint: Option<&str>,
    allowed_ips: &str,
    keepalive: Option<u16>,
) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let tid = Uuid::parse_str(tunnel_id)?;

    let mut peer = WgPeer::new(tid, name.to_string(), pubkey.to_string());
    peer.endpoint = endpoint.map(String::from);
    peer.allowed_ips = allowed_ips
        .split(',')
        .map(|s| Address::parse(s.trim()))
        .collect::<aifw_common::Result<Vec<_>>>()?;
    peer.persistent_keepalive = keepalive;

    let peer = engine.add_wg_peer(peer).await?;
    println!("Added WireGuard peer {}", peer.id);
    println!("  Name:     {}", peer.name);
    println!("  Endpoint: {}", peer.endpoint.as_deref().unwrap_or("(none)"));
    Ok(())
}

pub async fn vpn_ipsec_add(
    db_path: &Path,
    name: &str,
    src: &str,
    dst: &str,
    proto: &str,
    mode: &str,
) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;

    let ipsec_mode = match mode {
        "transport" => IpsecMode::Transport,
        _ => IpsecMode::Tunnel,
    };

    let sa = IpsecSa::new(
        name.to_string(),
        Address::parse(src)?,
        Address::parse(dst)?,
        IpsecProtocol::parse(proto)?,
        ipsec_mode,
    );
    let sa = engine.add_ipsec_sa(sa).await?;
    println!("Added IPsec SA {}", sa.id);
    println!("  Name:     {}", sa.name);
    println!("  SPI:      0x{:08x}", sa.spi);
    println!("  Protocol: {}", sa.protocol);
    println!("  Mode:     {}", sa.mode);
    Ok(())
}

pub async fn vpn_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;

    // Try WG tunnel first, then IPsec SA
    if engine.delete_wg_tunnel(uuid).await.is_ok() {
        println!("Removed WireGuard tunnel {id}");
    } else if engine.delete_ipsec_sa(uuid).await.is_ok() {
        println!("Removed IPsec SA {id}");
    } else if engine.delete_wg_peer(uuid).await.is_ok() {
        println!("Removed WireGuard peer {id}");
    } else {
        anyhow::bail!("VPN resource {id} not found");
    }
    Ok(())
}

pub async fn vpn_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;

    let tunnels = engine.list_wg_tunnels().await?;
    let sas = engine.list_ipsec_sas().await?;

    if json {
        let data = serde_json::json!({
            "wireguard": tunnels,
            "ipsec": sas,
        });
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    // WireGuard
    if tunnels.is_empty() {
        println!("No WireGuard tunnels configured");
    } else {
        println!("WireGuard Tunnels:");
        println!(
            "{:<38} {:<12} {:<8} {:<6} {:<20} {:<8}",
            "ID", "NAME", "IFACE", "PORT", "ADDRESS", "STATUS"
        );
        println!("{}", "-".repeat(95));
        for t in &tunnels {
            println!(
                "{:<38} {:<12} {:<8} {:<6} {:<20} {:<8}",
                t.id, t.name, t.interface, t.listen_port, t.address, t.status,
            );

            // List peers
            if let Ok(peers) = engine.list_wg_peers(t.id).await {
                for p in &peers {
                    println!(
                        "  Peer: {} | {} | endpoint: {} | allowed: {}",
                        p.name,
                        &p.public_key[..12],
                        p.endpoint.as_deref().unwrap_or("(none)"),
                        p.allowed_ips.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(","),
                    );
                }
            }
        }
        println!("\n{} tunnel(s)", tunnels.len());
    }

    println!();

    // IPsec
    if sas.is_empty() {
        println!("No IPsec SAs configured");
    } else {
        println!("IPsec Security Associations:");
        println!(
            "{:<38} {:<12} {:<20} {:<20} {:<8} {:<10} {:<8}",
            "ID", "NAME", "SOURCE", "DESTINATION", "PROTO", "MODE", "STATUS"
        );
        println!("{}", "-".repeat(115));
        for sa in &sas {
            println!(
                "{:<38} {:<12} {:<20} {:<20} {:<8} {:<10} {:<8}",
                sa.id, sa.name, sa.src_addr, sa.dst_addr, sa.protocol, sa.mode, sa.status,
            );
        }
        println!("\n{} SA(s)", sas.len());
    }

    Ok(())
}

// --- Geo-IP commands ---

async fn create_geoip_engine(db_path: &Path) -> anyhow::Result<GeoIpEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    let engine = GeoIpEngine::new(db.pool().clone(), pf);
    engine.migrate().await?;
    Ok(engine)
}

pub async fn geoip_add(
    db_path: &Path,
    country: &str,
    action: &str,
    label: Option<&str>,
) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let mut rule = GeoIpRule::new(CountryCode::new(country)?, GeoIpAction::parse(action)?);
    rule.label = label.map(String::from);
    let rule = engine.add_rule(rule).await?;
    println!("Added geo-ip rule {}", rule.id);
    println!("  Country: {}", rule.country);
    println!("  Action:  {}", rule.action);
    println!("  Table:   <{}>", rule.table_name());
    println!("  pf:      {}", rule.to_pf_rule());
    Ok(())
}

pub async fn geoip_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete_rule(uuid).await?;
    println!("Removed geo-ip rule {id}");
    Ok(())
}

pub async fn geoip_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let rules = engine.list_rules().await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&rules)?);
        return Ok(());
    }

    if rules.is_empty() {
        println!("No geo-ip rules configured");
        return Ok(());
    }

    let (countries, entries) = engine.db_stats().await;

    println!(
        "{:<38} {:<8} {:<8} {:<20} {}",
        "ID", "COUNTRY", "ACTION", "TABLE", "LABEL"
    );
    println!("{}", "-".repeat(85));

    for r in &rules {
        let status = match r.status {
            aifw_common::GeoIpRuleStatus::Active => "",
            aifw_common::GeoIpRuleStatus::Disabled => " [disabled]",
        };
        println!(
            "{:<38} {:<8} {:<8} {:<20} {}{}",
            r.id,
            r.country,
            r.action,
            r.table_name(),
            r.label.as_deref().unwrap_or(""),
            status,
        );
    }

    println!("\n{} rule(s) | DB: {} countries, {} CIDRs loaded", rules.len(), countries, entries);
    Ok(())
}

pub async fn geoip_lookup(db_path: &Path, ip_str: &str) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let ip: std::net::IpAddr = ip_str.parse()?;
    let result = engine.lookup(ip).await;

    println!("IP:      {}", result.ip);
    match result.country {
        Some(cc) => {
            println!("Country: {cc}");
            println!("Network: {}", result.network.unwrap_or_default());
        }
        None => println!("Country: (not found — geo-ip database may not be loaded)"),
    }
    Ok(())
}

// --- Config commands ---

async fn create_config_manager(db_path: &Path) -> anyhow::Result<aifw_core::ConfigManager> {
    let db = Database::new(db_path).await?;
    let mgr = aifw_core::ConfigManager::new(db.pool().clone());
    mgr.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(mgr)
}

pub async fn config_show(db_path: &Path) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    match mgr.get_active().await.map_err(|e| anyhow::anyhow!(e))? {
        Some((version, config)) => {
            println!("Active config version: {version}");
            println!("Resources: {}", config.resource_count());
            println!("Hash: {}", config.hash());
            println!();
            println!("{}", config.to_json());
        }
        None => {
            println!("No active configuration. Run 'aifw-setup' or 'aifw config import'.");
        }
    }
    Ok(())
}

pub async fn config_export(db_path: &Path) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    match mgr.get_active().await.map_err(|e| anyhow::anyhow!(e))? {
        Some((_, config)) => print!("{}", config.to_json()),
        None => anyhow::bail!("no active configuration"),
    }
    Ok(())
}

pub async fn config_import(db_path: &Path, file: &str) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let content = std::fs::read_to_string(file)?;
    let config = aifw_core::FirewallConfig::from_json(&content).map_err(|e| anyhow::anyhow!(e))?;

    println!("Importing config: {} resources", config.resource_count());

    // Save and mark as applied (no pf apply on CLI import — use 'aifw reload' after)
    let version = mgr.save_version(&config, "cli-import", Some(&format!("imported from {file}")))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    mgr.mark_applied(version).await.map_err(|e| anyhow::anyhow!(e))?;

    println!("Imported as config version {version}");
    println!("Run 'aifw reload' to apply to pf");
    Ok(())
}

pub async fn config_history(db_path: &Path, limit: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let versions = mgr.history(limit).await.map_err(|e| anyhow::anyhow!(e))?;

    if versions.is_empty() {
        println!("No config versions found.");
        return Ok(());
    }

    println!("{:<8} {:<10} {:<12} {:<22} {:<10} {}", "VERSION", "STATUS", "RESOURCES", "CREATED", "BY", "COMMENT");
    println!("{}", "-".repeat(90));

    for v in &versions {
        let status = if v.applied {
            "ACTIVE"
        } else if v.rolled_back {
            "ROLLED_BACK"
        } else {
            "saved"
        };
        let ts = &v.created_at[..19]; // trim timezone
        println!(
            "{:<8} {:<10} {:<12} {:<22} {:<10} {}",
            v.version,
            status,
            v.resource_count,
            ts,
            v.created_by,
            v.comment.as_deref().unwrap_or(""),
        );
    }

    let total = mgr.version_count().await.map_err(|e| anyhow::anyhow!(e))?;
    println!("\n{total} total version(s)");
    Ok(())
}

pub async fn config_rollback(db_path: &Path, version: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;

    println!("Rolling back to config version {version}...");
    mgr.rollback(version, |_config| async { Ok(()) })
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("Rolled back to version {version}");
    println!("Run 'aifw reload' to apply to pf");
    Ok(())
}

pub async fn config_diff(db_path: &Path, v1: i64, v2: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let diff = mgr.diff(v1, v2).await.map_err(|e| anyhow::anyhow!(e))?;

    println!("Config diff: v{} vs v{}", diff.v1, diff.v2);
    println!();
    if diff.identical {
        println!("  Configs are identical (same hash)");
    } else {
        println!("  Hash v{}: {}", diff.v1, &diff.v1_hash[..16]);
        println!("  Hash v{}: {}", diff.v2, &diff.v2_hash[..16]);
        println!();
        println!("  Rules:     {} -> {} (+{} -{})", diff.rules_diff.v1_count, diff.rules_diff.v2_count, diff.rules_diff.added, diff.rules_diff.removed);
        println!("  NAT:       {} -> {} (+{} -{})", diff.nat_diff.v1_count, diff.nat_diff.v2_count, diff.nat_diff.added, diff.nat_diff.removed);
        println!("  Total:     {} -> {}", diff.total_v1, diff.total_v2);
    }
    Ok(())
}
