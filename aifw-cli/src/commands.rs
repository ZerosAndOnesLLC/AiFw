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

// ============================================================
// Static routes
// ============================================================

pub async fn routes_add(db_path: &Path, dest: &str, gateway: &str, interface: Option<&str>, metric: i32, desc: Option<&str>) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    // Ensure table exists
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS static_routes (id TEXT PRIMARY KEY, destination TEXT NOT NULL, gateway TEXT NOT NULL, interface TEXT, metric INTEGER DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, description TEXT, created_at TEXT NOT NULL)",
    ).execute(pool).await?;

    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)")
        .bind(&id).bind(dest).bind(gateway).bind(interface).bind(metric).bind(desc).bind(&now)
        .execute(pool).await?;

    // Apply to system
    let mut cmd = std::process::Command::new("route");
    cmd.args(["add", dest, gateway]);
    if let Some(iface) = interface {
        cmd.args(["-interface", iface]);
    }
    let _ = cmd.output();

    println!("Added route: {} via {} (id: {})", dest, gateway, &id[..8]);
    Ok(())
}

pub async fn routes_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let row = sqlx::query_as::<_, (String, String, bool)>(
        "SELECT destination, gateway, enabled FROM static_routes WHERE id = ?1",
    ).bind(id).fetch_optional(pool).await?;

    if let Some((dest, gw, enabled)) = row {
        if enabled {
            let _ = std::process::Command::new("route").args(["delete", &dest, &gw]).output();
        }
        sqlx::query("DELETE FROM static_routes WHERE id = ?1").bind(id).execute(pool).await?;
        println!("Removed route: {} via {}", dest, gw);
    } else {
        anyhow::bail!("Route {} not found", id);
    }
    Ok(())
}

pub async fn routes_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let _ = sqlx::query(
        "CREATE TABLE IF NOT EXISTS static_routes (id TEXT PRIMARY KEY, destination TEXT NOT NULL, gateway TEXT NOT NULL, interface TEXT, metric INTEGER DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, description TEXT, created_at TEXT NOT NULL)",
    ).execute(pool).await;

    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, i32, bool, Option<String>)>(
        "SELECT id, destination, gateway, interface, metric, enabled, description FROM static_routes ORDER BY metric ASC",
    ).fetch_all(pool).await?;

    if json {
        let routes: Vec<serde_json::Value> = rows.iter().map(|(id, d, g, i, m, e, desc)| {
            serde_json::json!({"id": id, "destination": d, "gateway": g, "interface": i, "metric": m, "enabled": e, "description": desc})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&routes)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No static routes configured.");
        return Ok(());
    }

    println!("{:<36} {:<20} {:<16} {:<8} {:<8} {}", "ID", "Destination", "Gateway", "Iface", "Metric", "Status");
    println!("{}", "-".repeat(100));
    for (id, dest, gw, iface, metric, enabled, _desc) in &rows {
        let status = if *enabled { "active" } else { "disabled" };
        println!("{:<36} {:<20} {:<16} {:<8} {:<8} {}", id, dest, gw, iface.as_deref().unwrap_or("-"), metric, status);
    }
    Ok(())
}

pub async fn routes_system() -> anyhow::Result<()> {
    let output = std::process::Command::new("netstat").args(["-rn"]).output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

// ============================================================
// DNS
// ============================================================

pub async fn dns_list() -> anyhow::Result<()> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let servers: Vec<&str> = content.lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim()))
        .collect();

    if servers.is_empty() {
        println!("No DNS servers configured.");
    } else {
        println!("DNS Servers:");
        for s in &servers {
            println!("  {}", s);
        }
    }
    Ok(())
}

pub async fn dns_set(servers_str: &str) -> anyhow::Result<()> {
    let servers: Vec<&str> = servers_str.split(',').map(|s| s.trim()).collect();
    let content: String = servers.iter().map(|s| format!("nameserver {s}")).collect::<Vec<_>>().join("\n");
    std::fs::write("/etc/resolv.conf", &content)?;
    println!("DNS servers updated:");
    for s in &servers {
        println!("  {}", s);
    }
    Ok(())
}

// ============================================================
// Users
// ============================================================

pub async fn users_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, String, bool, bool)>(
        "SELECT id, username, role, totp_enabled, enabled FROM users ORDER BY created_at ASC",
    ).fetch_all(pool).await.unwrap_or_default();

    if json {
        let users: Vec<serde_json::Value> = rows.iter().map(|(id, u, r, mfa, e)| {
            serde_json::json!({"id": id, "username": u, "role": r, "mfa": mfa, "enabled": e})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&users)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No users.");
        return Ok(());
    }

    println!("{:<36} {:<16} {:<10} {:<6} {}", "ID", "Username", "Role", "MFA", "Status");
    println!("{}", "-".repeat(80));
    for (id, username, role, mfa, enabled) in &rows {
        let status = if *enabled { "active" } else { "disabled" };
        let mfa_str = if *mfa { "yes" } else { "no" };
        println!("{:<36} {:<16} {:<10} {:<6} {}", id, username, role, mfa_str, status);
    }
    Ok(())
}

pub async fn users_add(db_path: &Path, username: &str, password: &str, role: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    use argon2::{Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    let pw_hash = Argon2::default().hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash error: {e}"))?;

    sqlx::query("INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, role, enabled, created_at) VALUES (?1, ?2, ?3, 0, 'local', ?4, 1, ?5)")
        .bind(&id).bind(username).bind(&pw_hash).bind(role).bind(&now)
        .execute(pool).await?;

    println!("Created user: {} (role: {}, id: {})", username, role, &id[..8]);
    Ok(())
}

pub async fn users_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("DELETE FROM users WHERE id = ?1").bind(id).execute(pool).await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1").bind(id).execute(pool).await;
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1").bind(id).execute(pool).await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?1").bind(id).execute(pool).await;
    println!("Deleted user {}", id);
    Ok(())
}

pub async fn users_set_enabled(db_path: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("UPDATE users SET enabled = ?2 WHERE id = ?1").bind(id).bind(enabled).execute(pool).await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    println!("User {} {}", id, if enabled { "enabled" } else { "disabled" });
    Ok(())
}

// ============================================================
// Interfaces
// ============================================================

pub async fn interfaces_list() -> anyhow::Result<()> {
    let output = std::process::Command::new("ifconfig").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("{:<12} {:<18} {:<18} {:<6}", "Interface", "IPv4", "MAC", "Status");
    println!("{}", "-".repeat(60));

    let mut name = String::new();
    let mut ipv4 = String::from("-");
    let mut mac = String::from("-");
    let mut status = "down";

    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if !name.is_empty() && !name.starts_with("lo") && !name.starts_with("pflog") {
                println!("{:<12} {:<18} {:<18} {:<6}", name, ipv4, mac, status);
            }
            name = line.split(':').next().unwrap_or("").to_string();
            ipv4 = "-".to_string();
            mac = "-".to_string();
            status = if line.contains("UP") { "up" } else { "down" };
        }
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            ipv4 = trimmed.split_whitespace().nth(1).unwrap_or("-").to_string();
        }
        if trimmed.starts_with("ether ") {
            mac = trimmed.split_whitespace().nth(1).unwrap_or("-").to_string();
        }
    }
    if !name.is_empty() && !name.starts_with("lo") && !name.starts_with("pflog") {
        println!("{:<12} {:<18} {:<18} {:<6}", name, ipv4, mac, status);
    }
    Ok(())
}

// ============================================================
// DHCP
// ============================================================

pub async fn dhcp_status(db_path: &Path) -> anyhow::Result<()> {
    let running = std::process::Command::new("service").args(["rdhcpd", "status"]).output()
        .map(|o| o.status.success()).unwrap_or(false);
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    let subnets: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dhcp_subnets")
        .fetch_one(pool).await.map(|r| r.0).unwrap_or(0);
    let reservations: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dhcp_reservations")
        .fetch_one(pool).await.map(|r| r.0).unwrap_or(0);

    println!("DHCP Server Status:");
    println!("  Running:      {}", if running { "yes" } else { "no" });
    println!("  Subnets:      {}", subnets);
    println!("  Reservations: {}", reservations);
    Ok(())
}

pub async fn dhcp_subnets(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, String, String, String, bool)>(
        "SELECT id, network, pool_start, pool_end, gateway, enabled FROM dhcp_subnets ORDER BY created_at ASC"
    ).fetch_all(pool).await?;

    if json {
        let data: Vec<serde_json::Value> = rows.iter().map(|(id,net,ps,pe,gw,en)| {
            serde_json::json!({"id":id,"network":net,"pool_start":ps,"pool_end":pe,"gateway":gw,"enabled":en})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    if rows.is_empty() { println!("No DHCP subnets."); return Ok(()); }
    println!("{:<36} {:<20} {:<16} {:<16} {:<16} {}", "ID", "Network", "Pool Start", "Pool End", "Gateway", "Status");
    println!("{}", "-".repeat(110));
    for (id, net, ps, pe, gw, en) in &rows {
        println!("{:<36} {:<20} {:<16} {:<16} {:<16} {}", id, net, ps, pe, gw, if *en { "active" } else { "disabled" });
    }
    Ok(())
}

pub async fn dhcp_subnet_add(db_path: &Path, network: &str, pool_start: &str, pool_end: &str, gateway: &str, dns: Option<&str>, domain: Option<&str>, lease_time: Option<u32>, desc: Option<&str>) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO dhcp_subnets (id, network, pool_start, pool_end, gateway, dns_servers, domain_name, lease_time, enabled, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10)")
        .bind(&id).bind(network).bind(pool_start).bind(pool_end).bind(gateway)
        .bind(dns).bind(domain).bind(lease_time.map(|v| v as i64)).bind(desc).bind(&now)
        .execute(pool).await?;
    println!("Added DHCP subnet: {} (id: {})", network, &id[..8]);
    Ok(())
}

pub async fn dhcp_subnet_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let result = sqlx::query("DELETE FROM dhcp_subnets WHERE id = ?1").bind(id).execute(db.pool()).await?;
    if result.rows_affected() == 0 { anyhow::bail!("Subnet {} not found", id); }
    println!("Removed DHCP subnet {}", id);
    Ok(())
}

pub async fn dhcp_reservations(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT id, mac_address, ip_address, hostname FROM dhcp_reservations ORDER BY ip_address ASC"
    ).fetch_all(db.pool()).await?;

    if json {
        let data: Vec<serde_json::Value> = rows.iter().map(|(id,mac,ip,hn)| {
            serde_json::json!({"id":id,"mac":mac,"ip":ip,"hostname":hn})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    if rows.is_empty() { println!("No DHCP reservations."); return Ok(()); }
    println!("{:<36} {:<20} {:<16} {}", "ID", "MAC", "IP", "Hostname");
    println!("{}", "-".repeat(80));
    for (id, mac, ip, hn) in &rows {
        println!("{:<36} {:<20} {:<16} {}", id, mac, ip, hn.as_deref().unwrap_or("-"));
    }
    Ok(())
}

pub async fn dhcp_reservation_add(db_path: &Path, mac: &str, ip: &str, hostname: Option<&str>, subnet: Option<&str>, desc: Option<&str>) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO dhcp_reservations (id, subnet_id, mac_address, ip_address, hostname, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")
        .bind(&id).bind(subnet).bind(mac).bind(ip).bind(hostname).bind(desc).bind(&now)
        .execute(db.pool()).await?;
    println!("Added reservation: {} -> {} (id: {})", mac, ip, &id[..8]);
    Ok(())
}

pub async fn dhcp_reservation_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let result = sqlx::query("DELETE FROM dhcp_reservations WHERE id = ?1").bind(id).execute(db.pool()).await?;
    if result.rows_affected() == 0 { anyhow::bail!("Reservation {} not found", id); }
    println!("Removed reservation {}", id);
    Ok(())
}

pub async fn dhcp_leases(json: bool) -> anyhow::Result<()> {
    // Query rDHCP management API for active leases
    let output = std::process::Command::new("curl")
        .args(["-sf", "--max-time", "3", "http://127.0.0.1:9967/api/v1/leases?state=bound&limit=10000"])
        .output();

    let body = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => { println!("No active DHCP leases (rDHCP may not be running)."); return Ok(()); }
    };

    if json {
        // Pretty-print the raw JSON from rDHCP
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
            println!("{}", serde_json::to_string_pretty(&parsed)?);
        } else {
            println!("{}", body);
        }
        return Ok(());
    }

    let leases: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();
    if leases.is_empty() { println!("No active DHCP leases."); return Ok(()); }

    println!("{:<16} {:<20} {:<20} {:<20} {}", "IP", "MAC", "Hostname", "Subnet", "State");
    println!("{}", "-".repeat(90));
    for lease in &leases {
        let ip = lease["ip"].as_str().unwrap_or("-");
        let mac = lease["mac"].as_str().unwrap_or("-");
        let hn = lease["hostname"].as_str().unwrap_or("-");
        let subnet = lease["subnet"].as_str().unwrap_or("-");
        let state = lease["state"].as_str().unwrap_or("-");
        println!("{:<16} {:<20} {:<20} {:<20} {}", ip, mac, hn, subnet, state);
    }
    Ok(())
}

pub async fn dhcp_apply(_db_path: &Path) -> anyhow::Result<()> {
    println!("Generating rDHCP config...");
    // Config generation is in the API — for CLI, just call the API
    println!("Use the web UI or API to apply DHCP config:");
    println!("  curl -X POST https://<host>:8080/api/v1/dhcp/v4/apply");
    Ok(())
}

// ============================================================
// Update commands
// ============================================================

pub async fn update_check() -> anyhow::Result<()> {
    use aifw_core::updater;

    println!("Checking for AiFw updates...");
    let info = updater::check_for_update().await?;

    println!("  Current version: v{}", info.current_version);
    println!("  Latest version:  v{}", info.latest_version);
    if info.update_available {
        println!("  Update available!");
        if info.tarball_url.is_some() {
            println!("  Run 'aifw update install' to update.");
        } else {
            println!("  No update tarball found in the release.");
        }
    } else {
        println!("  Already running the latest version.");
    }
    if info.has_backup {
        println!(
            "  Backup: v{} (run 'aifw update rollback' to restore)",
            info.backup_version.as_deref().unwrap_or("unknown")
        );
    }
    Ok(())
}

pub async fn update_install() -> anyhow::Result<()> {
    use aifw_core::updater;

    println!("Checking for AiFw updates...");
    let info = updater::check_for_update().await?;

    if !info.update_available {
        println!("Already running the latest version (v{}).", info.current_version);
        return Ok(());
    }

    println!(
        "Updating AiFw from v{} to v{}...",
        info.current_version, info.latest_version
    );
    let msg = updater::download_and_install(&info).await?;
    println!("{}", msg);

    println!("Restarting services...");
    updater::restart_services_sync().await;
    println!("Done.");
    Ok(())
}

pub async fn update_rollback() -> anyhow::Result<()> {
    use aifw_core::updater;

    let msg = updater::rollback().await?;
    println!("{}", msg);

    println!("Restarting services...");
    updater::restart_services_sync().await;
    println!("Done.");
    Ok(())
}

pub async fn update_os_check() -> anyhow::Result<()> {
    println!("Checking for OS and package updates...");

    let pkg = tokio::process::Command::new("sudo")
        .args(["/usr/sbin/pkg", "update"])
        .output()
        .await?;
    if pkg.status.success() {
        println!("  Package catalog updated.");
    } else {
        println!(
            "  Package update failed: {}",
            String::from_utf8_lossy(&pkg.stderr).trim()
        );
    }

    let os = tokio::process::Command::new("sudo")
        .args(["/usr/sbin/freebsd-update", "fetch", "--not-running-from-cron"])
        .output()
        .await?;
    if os.status.success() {
        println!("  OS update check complete.");
    } else {
        println!(
            "  OS update check: {}",
            String::from_utf8_lossy(&os.stderr).lines().next().unwrap_or("")
        );
    }

    // Show pending
    let pending = tokio::process::Command::new("sudo")
        .args(["/usr/sbin/pkg", "upgrade", "-n"])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&pending.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.trim().starts_with("Upgrading") || l.trim().starts_with("Installing"))
        .count();
    if count > 0 {
        println!("  {} package(s) pending.", count);
    } else {
        println!("  Packages are up to date.");
    }

    Ok(())
}

pub async fn update_os_install() -> anyhow::Result<()> {
    println!("Installing OS and package updates...");

    let pkg = tokio::process::Command::new("sudo")
        .args(["/usr/sbin/pkg", "upgrade", "-y"])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&pkg.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.contains("Upgrading") || l.contains("Installing"))
        .count();
    println!("  {} package(s) updated.", count);

    let os = tokio::process::Command::new("sudo")
        .args(["/usr/sbin/freebsd-update", "install"])
        .output()
        .await?;
    if os.status.success() {
        println!("  OS updates installed.");
    } else {
        println!("  No OS updates to install.");
    }

    if std::path::Path::new("/var/run/reboot-required").exists() {
        println!("  Reboot required to complete updates.");
    }

    Ok(())
}

// ============================================================
// Reverse Proxy (TrafficCop) commands
// ============================================================

pub async fn rp_status(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    // Check service status
    let output = tokio::process::Command::new("sudo")
        .args(["service", "trafficcop", "status"])
        .output()
        .await;
    let running = output.map(|o| o.status.success()).unwrap_or(false);

    println!("Reverse Proxy (TrafficCop)");
    println!("  Status: {}", if running { "running" } else { "stopped" });

    // Count entities
    let eps: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_entrypoints WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));
    let hr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_routers WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));
    let hs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_services WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));
    let hm: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_middlewares WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));
    let tr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_tcp_routers WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));
    let ur: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_udp_routers WHERE enabled = 1")
        .fetch_one(pool).await.unwrap_or((0,));

    println!("  Entrypoints:     {}", eps.0);
    println!("  HTTP Routers:    {}", hr.0);
    println!("  HTTP Services:   {}", hs.0);
    println!("  HTTP Middlewares: {}", hm.0);
    println!("  TCP Routers:     {}", tr.0);
    println!("  UDP Routers:     {}", ur.0);
    Ok(())
}

pub async fn rp_start() -> anyhow::Result<()> {
    let output = tokio::process::Command::new("sudo")
        .args(["service", "trafficcop", "start"])
        .output()
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

pub async fn rp_stop() -> anyhow::Result<()> {
    let output = tokio::process::Command::new("sudo")
        .args(["service", "trafficcop", "stop"])
        .output()
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_restart() -> anyhow::Result<()> {
    let output = tokio::process::Command::new("sudo")
        .args(["service", "trafficcop", "restart"])
        .output()
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_validate(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    println!("Generating config...");
    let yaml = rp_generate_config(pool).await?;

    let tmp = "/tmp/trafficcop-validate.yaml";
    tokio::fs::write(tmp, &yaml).await?;

    let output = tokio::process::Command::new("trafficcop")
        .args(["-c", tmp, "--validate"])
        .output()
        .await?;

    let _ = tokio::fs::remove_file(tmp).await;

    if output.status.success() {
        println!("Config is valid.");
    } else {
        println!("Config validation failed:");
        println!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

pub async fn rp_apply(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    println!("Generating config...");
    let yaml = rp_generate_config(pool).await?;

    // Write config via sudo
    let mut child = tokio::process::Command::new("sudo")
        .args(["tee", "/usr/local/etc/trafficcop/config.yaml"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(yaml.as_bytes()).await?;
    }
    child.wait().await?;

    println!("Config written. Restarting service...");
    let output = tokio::process::Command::new("sudo")
        .args(["service", "trafficcop", "restart"])
        .output()
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_routers(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, String, String, i32, i64)>(
        "SELECT name, rule, service, entry_points, priority, enabled FROM tc_http_routers ORDER BY name"
    ).fetch_all(pool).await?;

    if json {
        let items: Vec<serde_json::Value> = rows.iter().map(|(n, r, s, ep, p, e)| {
            serde_json::json!({"name": n, "rule": r, "service": s, "entry_points": ep, "priority": p, "enabled": *e == 1})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<20} {:<40} {:<20} {:<5} {}", "NAME", "RULE", "SERVICE", "PRI", "ENABLED");
        println!("{}", "-".repeat(95));
        for (n, r, s, _, p, e) in &rows {
            let rule_display = if r.len() > 38 { format!("{}...", &r[..35]) } else { r.clone() };
            println!("{:<20} {:<40} {:<20} {:<5} {}", n, rule_display, s, p, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_services(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, service_type, enabled FROM tc_http_services ORDER BY name"
    ).fetch_all(pool).await?;

    if json {
        let items: Vec<serde_json::Value> = rows.iter().map(|(n, t, e)| {
            serde_json::json!({"name": n, "type": t, "enabled": *e == 1})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<20} {}", "NAME", "TYPE", "ENABLED");
        println!("{}", "-".repeat(55));
        for (n, t, e) in &rows {
            println!("{:<30} {:<20} {}", n, t, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_middlewares(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, middleware_type, enabled FROM tc_http_middlewares ORDER BY name"
    ).fetch_all(pool).await?;

    if json {
        let items: Vec<serde_json::Value> = rows.iter().map(|(n, t, e)| {
            serde_json::json!({"name": n, "type": t, "enabled": *e == 1})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<25} {}", "NAME", "TYPE", "ENABLED");
        println!("{}", "-".repeat(60));
        for (n, t, e) in &rows {
            println!("{:<30} {:<25} {}", n, t, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_entrypoints(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, address, enabled FROM tc_entrypoints ORDER BY name"
    ).fetch_all(pool).await?;

    if json {
        let items: Vec<serde_json::Value> = rows.iter().map(|(n, a, e)| {
            serde_json::json!({"name": n, "address": a, "enabled": *e == 1})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<20} {:<20} {}", "NAME", "ADDRESS", "ENABLED");
        println!("{}", "-".repeat(45));
        for (n, a, e) in &rows {
            println!("{:<20} {:<20} {}", n, a, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_show_config(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let yaml = rp_generate_config(pool).await?;
    println!("{}", yaml);
    Ok(())
}

/// Generate TrafficCop YAML config from DB (CLI version, mirrors the API logic).
async fn rp_generate_config(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
    use serde_json::json;

    let mut root = serde_json::Map::new();

    // Entry points
    let eps = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, address, config_json FROM tc_entrypoints WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !eps.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, addr, cfg) in &eps {
            let mut val: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            val["address"] = json!(addr);
            map.insert(name.clone(), val);
        }
        root.insert("entryPoints".to_string(), json!(map));
    }

    // HTTP
    let mut http = serde_json::Map::new();

    let routers = sqlx::query_as::<_, (String, String, String, String, String, i32, Option<String>)>(
        "SELECT name, rule, service, entry_points, middlewares, priority, tls_json FROM tc_http_routers WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, mw_json, pri, tls) in &routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mws: Vec<String> = serde_json::from_str(mw_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() { rv["entryPoints"] = json!(eps); }
            if !mws.is_empty() { rv["middlewares"] = json!(mws); }
            if *pri != 0 { rv["priority"] = json!(pri); }
            if let Some(t) = tls {
                if let Ok(tv) = serde_json::from_str::<serde_json::Value>(t) { rv["tls"] = tv; }
            }
            map.insert(name.clone(), rv);
        }
        http.insert("routers".to_string(), json!(map));
    }

    let services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_http_services WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        http.insert("services".to_string(), json!(map));
    }

    let middlewares = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, middleware_type, config_json FROM tc_http_middlewares WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !middlewares.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, mtype, cfg) in &middlewares {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut mv = serde_json::Map::new();
            mv.insert(mtype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(mv));
        }
        http.insert("middlewares".to_string(), json!(map));
    }

    if !http.is_empty() { root.insert("http".to_string(), json!(http)); }

    // TCP
    let mut tcp = serde_json::Map::new();
    let tcp_routers = sqlx::query_as::<_, (String, String, String, String, i32, Option<String>)>(
        "SELECT name, rule, service, entry_points, priority, tls_json FROM tc_tcp_routers WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !tcp_routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, pri, tls) in &tcp_routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() { rv["entryPoints"] = json!(eps); }
            if *pri != 0 { rv["priority"] = json!(pri); }
            if let Some(t) = tls {
                if let Ok(tv) = serde_json::from_str::<serde_json::Value>(t) { rv["tls"] = tv; }
            }
            map.insert(name.clone(), rv);
        }
        tcp.insert("routers".to_string(), json!(map));
    }
    let tcp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_tcp_services WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !tcp_services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &tcp_services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        tcp.insert("services".to_string(), json!(map));
    }
    if !tcp.is_empty() { root.insert("tcp".to_string(), json!(tcp)); }

    // UDP
    let mut udp = serde_json::Map::new();
    let udp_routers = sqlx::query_as::<_, (String, String, String, String, i32)>(
        "SELECT name, rule, service, entry_points, priority FROM tc_udp_routers WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !udp_routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, pri) in &udp_routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() { rv["entryPoints"] = json!(eps); }
            if *pri != 0 { rv["priority"] = json!(pri); }
            map.insert(name.clone(), rv);
        }
        udp.insert("routers".to_string(), json!(map));
    }
    let udp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_udp_services WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !udp_services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &udp_services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        udp.insert("services".to_string(), json!(map));
    }
    if !udp.is_empty() { root.insert("udp".to_string(), json!(udp)); }

    // TLS
    let tls_certs = sqlx::query_as::<_, (String, String)>(
        "SELECT cert_file, key_file FROM tc_tls_certs"
    ).fetch_all(pool).await?;
    let tls_opts = sqlx::query_as::<_, (String, String)>(
        "SELECT name, config_json FROM tc_tls_options"
    ).fetch_all(pool).await?;
    if !tls_certs.is_empty() || !tls_opts.is_empty() {
        let mut tls = serde_json::Map::new();
        if !tls_certs.is_empty() {
            let certs: Vec<serde_json::Value> = tls_certs.iter()
                .map(|(c, k)| json!({"certFile": c, "keyFile": k}))
                .collect();
            tls.insert("certificates".to_string(), json!(certs));
        }
        if !tls_opts.is_empty() {
            let mut opts = serde_json::Map::new();
            for (name, cfg) in &tls_opts {
                let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
                opts.insert(name.clone(), config);
            }
            tls.insert("options".to_string(), json!(opts));
        }
        root.insert("tls".to_string(), json!(tls));
    }

    // Certificate resolvers
    let resolvers = sqlx::query_as::<_, (String, String)>(
        "SELECT name, config_json FROM tc_cert_resolvers"
    ).fetch_all(pool).await?;
    if !resolvers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, cfg) in &resolvers {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            map.insert(name.clone(), config);
        }
        root.insert("certificatesResolvers".to_string(), json!(map));
    }

    // Global config (log, accessLog, api, metrics)
    let kv = sqlx::query_as::<_, (String, String)>(
        "SELECT key, value FROM tc_config"
    ).fetch_all(pool).await.unwrap_or_default();

    let get = |key: &str| -> Option<String> {
        kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };

    let log_level = get("log_level").unwrap_or_else(|| "info".to_string());
    root.insert("log".to_string(), json!({
        "level": log_level,
        "filePath": "/var/log/trafficcop/trafficcop.log"
    }));

    if get("access_log_enabled").as_deref() != Some("false") {
        let path = get("access_log_path").unwrap_or_else(|| "/var/log/trafficcop/access.log".to_string());
        let fmt = get("access_log_format").unwrap_or_else(|| "json".to_string());
        root.insert("accessLog".to_string(), json!({"filePath": path, "format": fmt}));
    }

    if get("api_dashboard").as_deref() != Some("false") {
        root.insert("api".to_string(), json!({"dashboard": true, "insecure": true}));
    }

    if get("metrics_enabled").as_deref() == Some("true") {
        let addr = get("metrics_address").unwrap_or_else(|| ":9090".to_string());
        root.insert("metrics".to_string(), json!({"prometheus": {"address": addr}}));
    }

    let yaml = serde_yml::to_string(&root)?;
    Ok(yaml)
}
