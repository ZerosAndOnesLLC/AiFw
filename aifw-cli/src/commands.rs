use aifw_common::{
    Action, Address, Bandwidth, CountryCode, Direction, GeoIpAction, GeoIpRule, Interface,
    IpsecMode, IpsecProtocol, IpsecSa, NatRedirect, NatRule, NatType, PortRange, Protocol,
    QueueConfig, QueueType, RateLimitRule, Rule, RuleMatch, TrafficClass, WgPeer, WgTunnel,
};
use aifw_core::{
    Database, GatewayEngine, GeoIpEngine, GroupEngine, InstanceEngine, LeakEngine, NatEngine,
    PolicyEngine, RuleEngine, ShapingEngine, VpnEngine,
};
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
    println!(
        "pf running:     {}",
        if stats.running { "yes" } else { "no" }
    );
    println!("pf states:      {}", stats.states_count);
    println!("pf rules (pf):  {}", stats.rules_count);
    println!("aifw rules:     {} ({} active)", rules.len(), active_rules);
    match check_pf_anchors_present().await {
        Some(true) => println!("pf anchor hooks: present"),
        Some(false) => println!("pf anchor hooks: MISSING (run `aifw reconcile`)"),
        None => println!("pf anchor hooks: unknown (pfctl probe failed)"),
    }
    if let Ok(pool) =
        sqlx::sqlite::SqlitePool::connect(&format!("sqlite://{}", db_path.display())).await
    {
        match check_dns_backend_drift(&pool).await {
            Some(msg) => println!("dns backend:    DRIFT — {msg}"),
            None => println!("dns backend:    ok"),
        }
        pool.close().await;
    }
    println!("packets in:     {}", stats.packets_in);
    println!("packets out:    {}", stats.packets_out);
    println!("bytes in:       {}", stats.bytes_in);
    println!("bytes out:      {}", stats.bytes_out);

    Ok(())
}

/// True if the running kernel pf main ruleset references the aifw anchors.
/// When this is false the whole aifw firewall config is effectively
/// bypassed — see #153.
///
/// Returns `Some(bool)` only if the probe actually succeeded. Returns
/// `None` if we couldn't tell (e.g. pfctl permission denied) — callers
/// must NOT interpret that as "drift detected" or we recreate the v5.55.1
/// regression.
async fn check_pf_anchors_present() -> Option<bool> {
    let out = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/sbin/pfctl", "-sn"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Some(s.contains("aifw-nat") || s.contains("anchor \"aifw\""))
}

/// Returns `Some(message)` if the DB's configured DNS backend doesn't
/// match what rc.conf says is enabled. See #154.
async fn check_dns_backend_drift(pool: &sqlx::SqlitePool) -> Option<String> {
    let backend = sqlx::query_scalar::<_, String>(
        "SELECT value FROM dns_resolver_config WHERE key = 'backend'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;

    let (want_key, other_key) = match backend.as_str() {
        "rdns" => ("rdns_enable", "local_unbound_enable"),
        "unbound" => ("local_unbound_enable", "rdns_enable"),
        _ => return None,
    };

    let want_val = sysrc_read_local(want_key).await;
    let other_val = sysrc_read_local(other_key).await;

    if want_val.as_deref() != Some("YES") {
        return Some(format!("db={backend} but {want_key} is not YES"));
    }
    if other_val.as_deref() == Some("YES") {
        return Some(format!("db={backend} but {other_key} is also YES"));
    }
    None
}

async fn sysrc_read_local(key: &str) -> Option<String> {
    let out = tokio::process::Command::new("/usr/sbin/sysrc")
        .args(["-n", key])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
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

/// Heal drift between running kernel state and the source of truth
/// (pf.conf.aifw + DB). Run this on demand when `aifw status` reports
/// "pf anchor hooks: MISSING" or "dns backend: DRIFT".
///
/// Must run as root (or a user with sudo for pfctl/sysrc) — the aifw
/// user can't probe pf directly. Order matters: populate anchors BEFORE
/// reloading main pf.conf so there's no window where main hooks point
/// at empty anchors.
pub async fn reconcile(db_path: &Path) -> anyhow::Result<()> {
    // 1. Repopulate anchors from DB first — same work `aifw reload` does.
    let engine = create_engine(db_path).await?;
    engine.apply_rules().await?;
    let nat = create_nat_engine(db_path).await?;
    nat.apply_rules().await?;
    println!("  anchors repopulated from db");

    // 2. Reload main pf ruleset if anchor hooks are missing.
    const PF_CONF: &str = "/usr/local/etc/aifw/pf.conf.aifw";
    if std::path::Path::new(PF_CONF).exists() {
        match check_pf_anchors_present().await {
            Some(true) => println!("  pf main ruleset ok (anchor hooks present)"),
            Some(false) => {
                let out = tokio::process::Command::new("/usr/local/bin/sudo")
                    .args(["/sbin/pfctl", "-f", PF_CONF])
                    .output()
                    .await?;
                if out.status.success() {
                    println!("  pf main ruleset reloaded from {PF_CONF}");
                } else {
                    eprintln!(
                        "  WARNING: pfctl -f {PF_CONF} failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
            }
            None => eprintln!("  WARNING: could not probe pf (try running as root with sudo)"),
        }
    } else {
        println!("  {PF_CONF} not present; skipped");
    }

    // 3. Fix rc.conf DNS backend flags to match DB.
    if let Ok(pool) =
        sqlx::sqlite::SqlitePool::connect(&format!("sqlite://{}", db_path.display())).await
    {
        let backend = sqlx::query_scalar::<_, String>(
            "SELECT value FROM dns_resolver_config WHERE key = 'backend'",
        )
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        let (want_key, other_key) = match backend.as_str() {
            "rdns" => (Some("rdns_enable"), Some("local_unbound_enable")),
            "unbound" => (Some("local_unbound_enable"), Some("rdns_enable")),
            _ => (None, None),
        };
        if let (Some(want), Some(other)) = (want_key, other_key) {
            let want_val = sysrc_read_local(want).await;
            let other_val = sysrc_read_local(other).await;
            if want_val.as_deref() != Some("YES") {
                sudo_sysrc_set(want, "YES").await?;
                println!("  set {want}=YES");
            }
            if other_val.as_deref() == Some("YES") {
                sudo_sysrc_set(other, "NO").await?;
                println!("  set {other}=NO");
            }
            if want_val.as_deref() == Some("YES") && other_val.as_deref() != Some("YES") {
                println!("  dns backend rc.conf already matches db (backend={backend})");
            }
        } else {
            println!("  db backend is unset or unknown; skipping dns reconciliation");
        }
        pool.close().await;
    }

    println!("reconcile complete");
    Ok(())
}

async fn sudo_sysrc_set(key: &str, value: &str) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/sysrc", &format!("{key}={value}")])
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "sysrc {key}={value} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
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
        "{:<38} {:<15} {:<8} {:<8} {:<12} {:<12} DEFAULT",
        "ID", "NAME", "IFACE", "TYPE", "BANDWIDTH", "CLASS"
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
        "{:<38} {:<15} {:<6} {:<10} {:<8} {:<20} FLUSH",
        "ID", "NAME", "PROTO", "MAX_CONN", "WINDOW", "TABLE"
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
    println!(
        "  Endpoint: {}",
        peer.endpoint.as_deref().unwrap_or("(none)")
    );
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
                        p.allowed_ips
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
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
        "{:<38} {:<8} {:<8} {:<20} LABEL",
        "ID", "COUNTRY", "ACTION", "TABLE"
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

    println!(
        "\n{} rule(s) | DB: {} countries, {} CIDRs loaded",
        rules.len(),
        countries,
        entries
    );
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
    let version = mgr
        .save_version(
            &config,
            "cli-import",
            Some(&format!("imported from {file}")),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    mgr.mark_applied(version)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

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

    println!(
        "{:<8} {:<10} {:<12} {:<22} {:<10} COMMENT",
        "VERSION", "STATUS", "RESOURCES", "CREATED", "BY"
    );
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
        println!(
            "  Rules:     {} -> {} (+{} -{})",
            diff.rules_diff.v1_count,
            diff.rules_diff.v2_count,
            diff.rules_diff.added,
            diff.rules_diff.removed
        );
        println!(
            "  NAT:       {} -> {} (+{} -{})",
            diff.nat_diff.v1_count,
            diff.nat_diff.v2_count,
            diff.nat_diff.added,
            diff.nat_diff.removed
        );
        println!("  Total:     {} -> {}", diff.total_v1, diff.total_v2);
    }
    Ok(())
}

// ============================================================
// Static routes
// ============================================================

pub async fn routes_add(
    db_path: &Path,
    dest: &str,
    gateway: &str,
    interface: Option<&str>,
    metric: i32,
    desc: Option<&str>,
) -> anyhow::Result<()> {
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
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    if let Some((dest, gw, enabled)) = row {
        if enabled {
            let _ = std::process::Command::new("route")
                .args(["delete", &dest, &gw])
                .output();
        }
        sqlx::query("DELETE FROM static_routes WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await?;
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

    println!(
        "{:<36} {:<20} {:<16} {:<8} {:<8} Status",
        "ID", "Destination", "Gateway", "Iface", "Metric"
    );
    println!("{}", "-".repeat(100));
    for (id, dest, gw, iface, metric, enabled, _desc) in &rows {
        let status = if *enabled { "active" } else { "disabled" };
        println!(
            "{:<36} {:<20} {:<16} {:<8} {:<8} {}",
            id,
            dest,
            gw,
            iface.as_deref().unwrap_or("-"),
            metric,
            status
        );
    }
    Ok(())
}

pub async fn routes_system() -> anyhow::Result<()> {
    let output = std::process::Command::new("netstat")
        .args(["-rn"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

// ============================================================
// DNS
// ============================================================

pub async fn dns_list() -> anyhow::Result<()> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let servers: Vec<&str> = content
        .lines()
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
    let content: String = servers
        .iter()
        .map(|s| format!("nameserver {s}"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write("/etc/resolv.conf", &content)?;
    println!("DNS servers updated:");
    for s in &servers {
        println!("  {}", s);
    }
    Ok(())
}

pub async fn dns_probe_set(db_path: &Path, enabled: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    sqlx::query(
        "INSERT OR REPLACE INTO dns_resolver_config (key, value) VALUES ('probe_enabled', ?1)",
    )
    .bind(if enabled { "true" } else { "false" })
    .execute(db.pool())
    .await?;
    println!(
        "DNS resolver probe: {}",
        if enabled {
            "ENABLED (auto-rollback on :53 silence)"
        } else {
            "DISABLED (trust service restart exit code only)"
        }
    );
    println!("Takes effect on the next apply/start/restart of the resolver.");
    Ok(())
}

pub async fn dns_probe_status(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let row = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM dns_resolver_config WHERE key = 'probe_enabled'",
    )
    .fetch_optional(db.pool())
    .await?;
    let enabled = row.map(|(v,)| v == "true").unwrap_or(true); // default ON
    println!(
        "DNS resolver probe: {}",
        if enabled { "enabled" } else { "disabled" }
    );
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
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

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

    println!(
        "{:<36} {:<16} {:<10} {:<6} Status",
        "ID", "Username", "Role", "MFA"
    );
    println!("{}", "-".repeat(80));
    for (id, username, role, mfa, enabled) in &rows {
        let status = if *enabled { "active" } else { "disabled" };
        let mfa_str = if *mfa { "yes" } else { "no" };
        println!(
            "{:<36} {:<16} {:<10} {:<6} {}",
            id, username, role, mfa_str, status
        );
    }
    Ok(())
}

pub async fn users_add(
    db_path: &Path,
    username: &str,
    password: &str,
    role: &str,
) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    use argon2::{
        Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng,
    };
    let salt = SaltString::generate(&mut OsRng);
    let pw_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash error: {e}"))?;

    sqlx::query("INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, role, enabled, created_at) VALUES (?1, ?2, ?3, 0, 'local', ?4, 1, ?5)")
        .bind(&id).bind(username).bind(&pw_hash).bind(role).bind(&now)
        .execute(pool).await?;

    println!(
        "Created user: {} (role: {}, id: {})",
        username,
        role,
        &id[..8]
    );
    Ok(())
}

pub async fn users_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?1")
        .bind(id)
        .execute(pool)
        .await;
    println!("Deleted user {}", id);
    Ok(())
}

pub async fn users_set_enabled(db_path: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let result = sqlx::query("UPDATE users SET enabled = ?2 WHERE id = ?1")
        .bind(id)
        .bind(enabled)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("User {} not found", id);
    }
    println!(
        "User {} {}",
        id,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

// ============================================================
// Interfaces
// ============================================================

pub async fn interfaces_list() -> anyhow::Result<()> {
    let output = std::process::Command::new("ifconfig").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!(
        "{:<12} {:<18} {:<18} {:<6}",
        "Interface", "IPv4", "MAC", "Status"
    );
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
    let running = std::process::Command::new("service")
        .args(["rdhcpd", "status"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    let subnets: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dhcp_subnets")
        .fetch_one(pool)
        .await
        .map(|r| r.0)
        .unwrap_or(0);
    let reservations: i64 = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dhcp_reservations")
        .fetch_one(pool)
        .await
        .map(|r| r.0)
        .unwrap_or(0);

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

    if rows.is_empty() {
        println!("No DHCP subnets.");
        return Ok(());
    }
    println!(
        "{:<36} {:<20} {:<16} {:<16} {:<16} Status",
        "ID", "Network", "Pool Start", "Pool End", "Gateway"
    );
    println!("{}", "-".repeat(110));
    for (id, net, ps, pe, gw, en) in &rows {
        println!(
            "{:<36} {:<20} {:<16} {:<16} {:<16} {}",
            id,
            net,
            ps,
            pe,
            gw,
            if *en { "active" } else { "disabled" }
        );
    }
    Ok(())
}

pub async fn dhcp_subnet_add(
    db_path: &Path,
    network: &str,
    pool_start: &str,
    pool_end: &str,
    gateway: &str,
    dns: Option<&str>,
    domain: Option<&str>,
    lease_time: Option<u32>,
    desc: Option<&str>,
) -> anyhow::Result<()> {
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
    let result = sqlx::query("DELETE FROM dhcp_subnets WHERE id = ?1")
        .bind(id)
        .execute(db.pool())
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("Subnet {} not found", id);
    }
    println!("Removed DHCP subnet {}", id);
    Ok(())
}

pub async fn dhcp_reservations(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT id, mac_address, ip_address, hostname FROM dhcp_reservations ORDER BY ip_address ASC"
    ).fetch_all(db.pool()).await?;

    if json {
        let data: Vec<serde_json::Value> = rows
            .iter()
            .map(|(id, mac, ip, hn)| serde_json::json!({"id":id,"mac":mac,"ip":ip,"hostname":hn}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!("No DHCP reservations.");
        return Ok(());
    }
    println!("{:<36} {:<20} {:<16} Hostname", "ID", "MAC", "IP");
    println!("{}", "-".repeat(80));
    for (id, mac, ip, hn) in &rows {
        println!(
            "{:<36} {:<20} {:<16} {}",
            id,
            mac,
            ip,
            hn.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

pub async fn dhcp_reservation_add(
    db_path: &Path,
    mac: &str,
    ip: &str,
    hostname: Option<&str>,
    subnet: Option<&str>,
    desc: Option<&str>,
) -> anyhow::Result<()> {
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
    let result = sqlx::query("DELETE FROM dhcp_reservations WHERE id = ?1")
        .bind(id)
        .execute(db.pool())
        .await?;
    if result.rows_affected() == 0 {
        anyhow::bail!("Reservation {} not found", id);
    }
    println!("Removed reservation {}", id);
    Ok(())
}

pub async fn dhcp_leases(json: bool) -> anyhow::Result<()> {
    // Query rDHCP management API for active leases
    let output = std::process::Command::new("curl")
        .args([
            "-sf",
            "--max-time",
            "3",
            "http://127.0.0.1:9967/api/v1/leases?state=bound&limit=10000",
        ])
        .output();

    let body = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            println!("No active DHCP leases (rDHCP may not be running).");
            return Ok(());
        }
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
    if leases.is_empty() {
        println!("No active DHCP leases.");
        return Ok(());
    }

    println!(
        "{:<16} {:<20} {:<20} {:<20} State",
        "IP", "MAC", "Hostname", "Subnet"
    );
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

pub async fn update_install(auto_restart: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    println!("Checking for AiFw updates...");
    let info = updater::check_for_update().await?;

    if !info.update_available {
        println!(
            "Already running the latest version (v{}).",
            info.current_version
        );
        return Ok(());
    }

    println!(
        "Updating AiFw from v{} to v{}...",
        info.current_version, info.latest_version
    );
    let msg = updater::download_and_install(&info).await?;
    println!("{}", msg);

    if info.reboot_recommended {
        println!();
        println!(
            "  ⚠ Reboot recommended for this release: {}",
            info.reboot_reason
                .as_deref()
                .unwrap_or("changes service-supervision tooling")
        );
        println!("  Use 'aifw update reboot' instead of 'aifw update restart'.");
        println!();
    }

    if auto_restart || prompt_restart_yes()? {
        println!("Restarting services...");
        updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!("Update installed. Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it.");
    }
    Ok(())
}

pub async fn update_rollback(auto_restart: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    let msg = updater::rollback().await?;
    println!("{}", msg);

    if auto_restart || prompt_restart_yes()? {
        println!("Restarting services...");
        updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!("Rollback installed. Run 'aifw update restart' when ready to activate it.");
    }
    Ok(())
}

pub async fn update_restart() -> anyhow::Result<()> {
    use aifw_core::updater;
    println!("Restarting AiFw services...");
    updater::restart_services_sync().await;
    println!("Done.");
    Ok(())
}

pub async fn update_reboot() -> anyhow::Result<()> {
    use aifw_core::updater;
    updater::schedule_reboot().await?;
    println!("System reboot scheduled in 1 minute.");
    println!("Cancel with `shutdown -c` if needed.");
    Ok(())
}

/// Interactive confirmation. Returns true on y/yes (case-insensitive).
/// Defaults to no on bare Enter — restarts are user-visible outages, the
/// safe answer when the operator hasn't decided is "don't bounce yet".
fn prompt_restart_yes() -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    print!("Restart services now to activate? [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub async fn update_os_check() -> anyhow::Result<()> {
    println!("Checking for OS and package updates...");

    let pkg = tokio::process::Command::new("/usr/local/bin/sudo")
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

    let os = tokio::process::Command::new("/usr/local/bin/sudo")
        .args([
            "/usr/sbin/freebsd-update",
            "fetch",
            "--not-running-from-cron",
        ])
        .output()
        .await?;
    if os.status.success() {
        println!("  OS update check complete.");
    } else {
        println!(
            "  OS update check: {}",
            String::from_utf8_lossy(&os.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
    }

    // Show pending
    let pending = tokio::process::Command::new("/usr/local/bin/sudo")
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

    let pkg = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/pkg", "upgrade", "-y"])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&pkg.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.contains("Upgrading") || l.contains("Installing"))
        .count();
    println!("  {} package(s) updated.", count);

    let os = tokio::process::Command::new("/usr/local/bin/sudo")
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
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["service", "trafficcop", "status"])
        .output()
        .await;
    let running = output.map(|o| o.status.success()).unwrap_or(false);

    println!("Reverse Proxy (TrafficCop)");
    println!("  Status: {}", if running { "running" } else { "stopped" });

    // Count entities
    let eps: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_entrypoints WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_services WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hm: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_middlewares WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let tr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_tcp_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let ur: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_udp_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    println!("  Entrypoints:     {}", eps.0);
    println!("  HTTP Routers:    {}", hr.0);
    println!("  HTTP Services:   {}", hs.0);
    println!("  HTTP Middlewares: {}", hm.0);
    println!("  TCP Routers:     {}", tr.0);
    println!("  UDP Routers:     {}", ur.0);
    Ok(())
}

pub async fn rp_start() -> anyhow::Result<()> {
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
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
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["service", "trafficcop", "stop"])
        .output()
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_restart() -> anyhow::Result<()> {
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
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
    let mut child = tokio::process::Command::new("/usr/local/bin/sudo")
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
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
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
        println!(
            "{:<20} {:<40} {:<20} {:<5} ENABLED",
            "NAME", "RULE", "SERVICE", "PRI"
        );
        println!("{}", "-".repeat(95));
        for (n, r, s, _, p, e) in &rows {
            let rule_display = if r.len() > 38 {
                format!("{}...", &r[..35])
            } else {
                r.clone()
            };
            println!(
                "{:<20} {:<40} {:<20} {:<5} {}",
                n,
                rule_display,
                s,
                p,
                if *e == 1 { "yes" } else { "no" }
            );
        }
    }
    Ok(())
}

pub async fn rp_services(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, service_type, enabled FROM tc_http_services ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, t, e)| serde_json::json!({"name": n, "type": t, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<20} ENABLED", "NAME", "TYPE");
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
        "SELECT name, middleware_type, enabled FROM tc_http_middlewares ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, t, e)| serde_json::json!({"name": n, "type": t, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<25} ENABLED", "NAME", "TYPE");
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
        "SELECT name, address, enabled FROM tc_entrypoints ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, a, e)| serde_json::json!({"name": n, "address": a, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<20} {:<20} ENABLED", "NAME", "ADDRESS");
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
        "SELECT name, address, config_json FROM tc_entrypoints WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
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
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if !mws.is_empty() {
                rv["middlewares"] = json!(mws);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            if let Some(t) = tls
                && let Ok(tv) = serde_json::from_str::<serde_json::Value>(t)
            {
                rv["tls"] = tv;
            }
            map.insert(name.clone(), rv);
        }
        http.insert("routers".to_string(), json!(map));
    }

    let services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_http_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
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
        "SELECT name, middleware_type, config_json FROM tc_http_middlewares WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
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

    if !http.is_empty() {
        root.insert("http".to_string(), json!(http));
    }

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
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            if let Some(t) = tls
                && let Ok(tv) = serde_json::from_str::<serde_json::Value>(t)
            {
                rv["tls"] = tv;
            }
            map.insert(name.clone(), rv);
        }
        tcp.insert("routers".to_string(), json!(map));
    }
    let tcp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_tcp_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
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
    if !tcp.is_empty() {
        root.insert("tcp".to_string(), json!(tcp));
    }

    // UDP
    let mut udp = serde_json::Map::new();
    let udp_routers = sqlx::query_as::<_, (String, String, String, String, i32)>(
        "SELECT name, rule, service, entry_points, priority FROM tc_udp_routers WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !udp_routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, pri) in &udp_routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            map.insert(name.clone(), rv);
        }
        udp.insert("routers".to_string(), json!(map));
    }
    let udp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_udp_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
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
    if !udp.is_empty() {
        root.insert("udp".to_string(), json!(udp));
    }

    // TLS
    let tls_certs =
        sqlx::query_as::<_, (String, String)>("SELECT cert_file, key_file FROM tc_tls_certs")
            .fetch_all(pool)
            .await?;
    let tls_opts =
        sqlx::query_as::<_, (String, String)>("SELECT name, config_json FROM tc_tls_options")
            .fetch_all(pool)
            .await?;
    if !tls_certs.is_empty() || !tls_opts.is_empty() {
        let mut tls = serde_json::Map::new();
        if !tls_certs.is_empty() {
            let certs: Vec<serde_json::Value> = tls_certs
                .iter()
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
    let resolvers =
        sqlx::query_as::<_, (String, String)>("SELECT name, config_json FROM tc_cert_resolvers")
            .fetch_all(pool)
            .await?;
    if !resolvers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, cfg) in &resolvers {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            map.insert(name.clone(), config);
        }
        root.insert("certificatesResolvers".to_string(), json!(map));
    }

    // Global config (log, accessLog, api, metrics)
    let kv = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM tc_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let get =
        |key: &str| -> Option<String> { kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()) };

    let log_level = get("log_level").unwrap_or_else(|| "info".to_string());
    root.insert(
        "log".to_string(),
        json!({
            "level": log_level,
            "filePath": "/var/log/trafficcop/trafficcop.log"
        }),
    );

    if get("access_log_enabled").as_deref() != Some("false") {
        let path =
            get("access_log_path").unwrap_or_else(|| "/var/log/trafficcop/access.log".to_string());
        let fmt = get("access_log_format").unwrap_or_else(|| "json".to_string());
        root.insert(
            "accessLog".to_string(),
            json!({"filePath": path, "format": fmt}),
        );
    }

    if get("api_dashboard").as_deref() != Some("false") {
        root.insert(
            "api".to_string(),
            json!({"dashboard": true, "insecure": true}),
        );
    }

    if get("metrics_enabled").as_deref() == Some("true") {
        let addr = get("metrics_address").unwrap_or_else(|| ":9090".to_string());
        root.insert(
            "metrics".to_string(),
            json!({"prometheus": {"address": addr}}),
        );
    }

    let yaml = serde_yaml_ng::to_string(&root)?;
    Ok(yaml)
}

// ============================================================
// Multi-WAN CLI commands (#132)
// ============================================================

async fn open_pf() -> Arc<dyn aifw_pf::PfBackend> {
    Arc::from(aifw_pf::create_backend())
}

pub async fn multiwan_instances(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = InstanceEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<6} {:<8} STATUS",
        "ID", "NAME", "FIB", "MGMT"
    );
    for i in list {
        println!(
            "{:<36} {:<16} {:<6} {:<8} {}",
            i.id,
            i.name,
            i.fib_number,
            if i.mgmt_reachable { "yes" } else { "no" },
            i.status.as_str(),
        );
    }
    Ok(())
}

pub async fn multiwan_gateways(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GatewayEngine::new(pool);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<8} {:<16} {:<12} {:<8} MOS",
        "ID", "NAME", "STATE", "NEXT-HOP", "IFACE", "RTT"
    );
    for g in list {
        println!(
            "{:<36} {:<16} {:<8} {:<16} {:<12} {:<8} {}",
            g.id,
            g.name,
            g.state.as_str(),
            g.next_hop,
            g.interface,
            g.last_rtt_ms
                .map(|v| format!("{v:.1}ms"))
                .unwrap_or_else(|| "-".into()),
            g.last_mos
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
        );
    }
    Ok(())
}

pub async fn multiwan_groups(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GroupEngine::new(pool);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<14} {:<8} STICKY",
        "ID", "NAME", "POLICY", "PREEMPT"
    );
    for g in list {
        let members = engine.list_members(g.id).await.unwrap_or_default();
        println!(
            "{:<36} {:<16} {:<14} {:<8} {:<10} ({} members)",
            g.id,
            g.name,
            g.policy.as_str(),
            if g.preempt { "yes" } else { "no" },
            g.sticky.as_str(),
            members.len(),
        );
    }
    Ok(())
}

pub async fn multiwan_policies(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = PolicyEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<5} {:<20} {:<10} {:<12} MATCH",
        "ID", "PRI", "NAME", "STATUS", "ACTION"
    );
    for p in list {
        println!(
            "{:<36} {:<5} {:<20} {:<10} {:<12} {} → {}:{}",
            p.id,
            p.priority,
            p.name,
            p.status,
            p.action_kind,
            p.src_addr,
            p.dst_addr,
            p.dst_port.as_deref().unwrap_or("*"),
        );
    }
    Ok(())
}

pub async fn multiwan_leaks(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = LeakEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<20} {:<20} {:<8} DIRECTION",
        "ID", "NAME", "PREFIX", "ENABLED"
    );
    for l in list {
        println!(
            "{:<36} {:<20} {:<20} {:<8} {}",
            l.id,
            l.name,
            l.prefix,
            if l.enabled { "yes" } else { "no" },
            l.direction
        );
    }
    Ok(())
}

pub async fn multiwan_flows() -> anyhow::Result<()> {
    let pf = open_pf().await;
    let states = pf.get_states().await?;
    println!(
        "{:<8} {:<8} {:<28} {:<28} {:<6} BYTES",
        "PROTO", "IFACE", "SRC", "DST", "FIB"
    );
    for s in states.into_iter().take(100) {
        println!(
            "{:<8} {:<8} {:<28} {:<28} {:<6} {}",
            s.protocol,
            s.iface.as_deref().unwrap_or("-"),
            format!("{}:{}", s.src_addr, s.src_port),
            format!("{}:{}", s.dst_addr, s.dst_port),
            s.rtable
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            s.bytes_in + s.bytes_out,
        );
    }
    Ok(())
}

pub async fn multiwan_fib_info() -> anyhow::Result<()> {
    let pf = open_pf().await;
    let n = pf.list_fibs().await?;
    println!("available FIBs: {n}");
    Ok(())
}

pub async fn multiwan_apply(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;

    let inst_engine = InstanceEngine::new(pool.clone(), pf.clone());
    let gw_engine = GatewayEngine::new(pool.clone());
    let grp_engine = GroupEngine::new(pool.clone());
    let policy_engine = PolicyEngine::new(pool.clone(), pf.clone());
    let leak_engine = LeakEngine::new(pool.clone(), pf.clone());
    inst_engine.migrate().await?;
    gw_engine.migrate().await?;
    grp_engine.migrate().await?;
    policy_engine.migrate().await?;
    leak_engine.migrate().await?;

    let instances = inst_engine.list().await?;
    let gateways = gw_engine.list().await?;
    let groups = grp_engine.list().await?;
    let mut members = std::collections::HashMap::new();
    for g in &groups {
        members.insert(g.id, grp_engine.list_members(g.id).await?);
    }
    policy_engine
        .apply(&instances, &gateways, &groups, &members)
        .await?;
    leak_engine.apply(&instances).await?;
    println!("multi-WAN anchors reloaded");
    Ok(())
}

pub async fn multiwan_seed_mgmt(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let inst_engine = InstanceEngine::new(pool.clone(), pf.clone());
    let leak_engine = LeakEngine::new(pool.clone(), pf);
    inst_engine.migrate().await?;
    leak_engine.migrate().await?;
    let instances = inst_engine.list().await?;
    leak_engine.seed_mgmt_escapes(&instances).await?;
    leak_engine.apply(&instances).await?;
    println!("mgmt-escape leaks seeded");
    Ok(())
}

pub async fn multiwan_probe(db_path: &Path, id: &str, outcome: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GatewayEngine::new(pool);
    engine.migrate().await?;
    let uuid: Uuid = id.parse()?;
    let success = matches!(outcome, "ok" | "success" | "up");
    let sample = aifw_core::multiwan::ProbeOutcome {
        success,
        rtt_ms: if success { Some(10.0) } else { None },
        error: if success {
            None
        } else {
            Some("cli-fail".into())
        },
    };
    engine.inject_sample(uuid, sample).await?;
    let gw = engine.get(uuid).await?;
    println!("gateway {} → {}", gw.name, gw.state.as_str());
    Ok(())
}

pub async fn multiwan_export(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let inst = InstanceEngine::new(pool.clone(), pf.clone());
    let gw = GatewayEngine::new(pool.clone());
    let grp = GroupEngine::new(pool.clone());
    let pol = PolicyEngine::new(pool.clone(), pf.clone());
    let lk = LeakEngine::new(pool, pf);
    inst.migrate().await?;
    gw.migrate().await?;
    grp.migrate().await?;
    pol.migrate().await?;
    lk.migrate().await?;
    let bundle = serde_json::json!({
        "instances": inst.list().await?,
        "gateways": gw.list().await?,
        "groups": grp.list().await?,
        "policies": pol.list().await?,
        "leaks": lk.list().await?,
    });
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}

pub async fn multiwan_import(db_path: &Path, file: &str) -> anyhow::Result<()> {
    let content = tokio::fs::read_to_string(file).await?;
    let bundle: serde_json::Value = serde_json::from_str(&content)?;
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;

    let inst = InstanceEngine::new(pool.clone(), pf.clone());
    let gw = GatewayEngine::new(pool.clone());
    let grp = GroupEngine::new(pool.clone());
    let pol = PolicyEngine::new(pool.clone(), pf.clone());
    let lk = LeakEngine::new(pool.clone(), pf.clone());
    inst.migrate().await?;
    gw.migrate().await?;
    grp.migrate().await?;
    pol.migrate().await?;
    lk.migrate().await?;

    let mut n = (0usize, 0usize, 0usize, 0usize, 0usize);
    if let Some(arr) = bundle.get("instances").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(i) = serde_json::from_value::<aifw_common::RoutingInstance>(v.clone()) {
                if i.mgmt_reachable {
                    continue;
                }
                if inst.get(i.id).await.is_ok() {
                    let _ = inst.update(i).await;
                } else {
                    let _ = inst.add(i).await;
                }
                n.0 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("gateways").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(g) = serde_json::from_value::<aifw_common::Gateway>(v.clone()) {
                if gw.get(g.id).await.is_ok() {
                    let _ = gw.update(g).await;
                } else {
                    let _ = gw.add(g).await;
                }
                n.1 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("groups").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(g) = serde_json::from_value::<aifw_common::GatewayGroup>(v.clone()) {
                if grp.get(g.id).await.is_ok() {
                    let _ = grp.update(g).await;
                } else {
                    let _ = grp.add(g).await;
                }
                n.2 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("policies").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(p) = serde_json::from_value::<aifw_common::PolicyRule>(v.clone()) {
                if pol.get(p.id).await.is_ok() {
                    let _ = pol.update(p).await;
                } else {
                    let _ = pol.add(p).await;
                }
                n.3 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("leaks").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(l) = serde_json::from_value::<aifw_common::RouteLeak>(v.clone()) {
                if lk.get(l.id).await.is_ok() {
                    let _ = lk.update(l).await;
                } else {
                    let _ = lk.add(l).await;
                }
                n.4 += 1;
            }
        }
    }
    println!(
        "imported: instances={} gateways={} groups={} policies={} leaks={}",
        n.0, n.1, n.2, n.3, n.4
    );
    Ok(())
}

// ============================================================
// Cluster / HA commands — loopback HTTP client helpers
// ============================================================

/// Base URL for the local AiFw API.
/// Uses HTTP on loopback (TLS termination is handled by the appliance's
/// reverse proxy on the public interface; loopback is trusted).
const AIFW_API_BASE: &str = "http://127.0.0.1:8080";
// Note: DEFAULT_LOOPBACK_API_BASE is HTTPS (for daemon-to-daemon use with
// self-signed cert acceptance). CLI uses plain HTTP on loopback since it
// runs interactively on the appliance itself.

/// Returns the bearer token for authenticating to the local API.
///
/// Resolution order:
///   1. `AIFW_TOKEN` env var (preferred for interactive shells / scripts)
///   2. `/var/db/aifw/cli.token` (reserved for future per-host token provisioning;
///      nothing currently writes this file — see #225 / #217 for follow-up)
///
/// Returns empty string if neither source is available; protected endpoints
/// will respond 401 in that case.
fn read_api_token() -> String {
    if let Ok(t) = std::env::var("AIFW_TOKEN") {
        if !t.is_empty() {
            return t;
        }
    }
    std::fs::read_to_string("/var/db/aifw/cli.token")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn api_client() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    Ok(client)
}

async fn api_get(path: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET {path} returned {status}: {body}");
    }
    Ok(resp.json().await?)
}

async fn api_post(path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.post(&url).json(body);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {path} returned {status}: {body_text}");
    }
    // Some POST endpoints return 204 No Content
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::Value::Null);
    }
    Ok(resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn api_put(path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.put(&url).json(body);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("PUT {path} returned {status}: {body_text}");
    }
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::Value::Null);
    }
    Ok(resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn api_delete(path: &str) -> anyhow::Result<()> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.delete(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("DELETE {path} returned {status}: {body}");
    }
    Ok(())
}

// ---- cluster status ----

pub async fn cluster_status(json: bool) -> anyhow::Result<()> {
    let s: serde_json::Value = api_get("/api/v1/cluster/status").await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
    } else {
        println!("Role:                 {}", s["role"].as_str().unwrap_or("?"));
        println!("Peer reachable:       {}", s["peer_reachable"]);
        println!("pfsync state count:   {}", s["pfsync_state_count"]);
        if let Some(h) = s["last_snapshot_hash"].as_str() {
            println!("Last snapshot hash:   {h}");
        }
    }
    Ok(())
}

// ---- CARP ----

pub async fn cluster_carp_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/carp").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_show(id: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = api_get(&format!("/api/v1/cluster/carp/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_add(
    vhid: u8,
    interface: &str,
    vip: &str,
    password: &str,
) -> anyhow::Result<()> {
    let (ip_str, prefix_str) = vip
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("--vip must be in 'addr/prefix' form, e.g. 192.0.2.1/24"))?;
    let virtual_ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid IP {ip_str}: {e}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix {prefix_str}: {e}"))?;
    let body = serde_json::json!({
        "vhid": vhid,
        "virtual_ip": virtual_ip,
        "prefix": prefix,
        "interface": interface,
        "password": password,
    });
    let v: serde_json::Value = api_post("/api/v1/cluster/carp", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/carp/{id}")).await?;
    println!("Removed CARP VIP {id}");
    Ok(())
}

// ---- pfsync ----

pub async fn cluster_pfsync_get() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/pfsync").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_pfsync_set(
    sync_interface: &str,
    sync_peer: Option<&str>,
    defer: bool,
    latency_profile: &str,
    dhcp_link: bool,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "sync_interface": sync_interface,
        "sync_peer": sync_peer,
        "defer": defer,
        "enabled": true,
        "latency_profile": latency_profile,
        "heartbeat_iface": null,
        "heartbeat_interval_ms": null,
        "dhcp_link": dhcp_link,
    });
    let v: serde_json::Value = api_put("/api/v1/cluster/pfsync", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

// ---- nodes ----

pub async fn cluster_nodes_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/nodes").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_show(id: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = api_get(&format!("/api/v1/cluster/nodes/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_add(name: &str, address: &str, role: &str) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": name, "address": address, "role": role });
    let v: serde_json::Value = api_post("/api/v1/cluster/nodes", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/nodes/{id}")).await?;
    println!("Removed node {id}");
    Ok(())
}

// ---- health checks ----

pub async fn cluster_health_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/health").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_health_add(
    name: &str,
    check_type: &str,
    target: &str,
    interval_secs: u32,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "name": name,
        "check_type": check_type,
        "target": target,
        "interval_secs": interval_secs,
    });
    let v: serde_json::Value = api_post("/api/v1/cluster/health", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_health_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/health/{id}")).await?;
    println!("Removed health check {id}");
    Ok(())
}

pub async fn cluster_health_run() -> anyhow::Result<()> {
    // POST to the trigger endpoint; the daemon still probes on its own 1-second
    // tick. This returns 202 Accepted — the actual out-of-band probe mechanism
    // is a future enhancement. See aifw-api/src/cluster.rs::run_health_checks.
    let r = api_post("/api/v1/cluster/health/run", &serde_json::json!({})).await;
    match r {
        Ok(_) => println!("Health-check run requested (daemon probes on its own 1s tick)."),
        Err(e) => eprintln!("Failed: {e}"),
    }
    Ok(())
}

// ---- promote / demote / sync ----

pub async fn cluster_promote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/promote", &serde_json::json!({})).await?;
    println!("Promoted (sysctl carp.demotion=0)");
    Ok(())
}

pub async fn cluster_demote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/demote", &serde_json::json!({})).await?;
    println!("Demoted (sysctl carp.demotion=240)");
    Ok(())
}

pub async fn cluster_sync() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/snapshot/force", &serde_json::json!({})).await?;
    println!("Snapshot pulled from peer");
    Ok(())
}

// ---- verify ----

/// Run local-side cluster verification checks.
/// Exits 0 when healthy, 1 on any failure.
/// Designed to be called by scripts/ha-verify.sh (Commit 11 / #223).
pub async fn cluster_verify(as_json: bool) -> anyhow::Result<()> {
    let mut failures: Vec<String> = Vec::new();

    // 1. pf state-policy floating
    match tokio::process::Command::new("pfctl")
        .args(["-sr"])
        .output()
        .await
    {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("set state-policy floating") {
                failures.push("pf state-policy is not floating".into());
            }
        }
        Err(_) => failures.push("pfctl -sr failed (not on FreeBSD or pf disabled?)".into()),
    }

    // 2. pfsync0 UP
    match tokio::process::Command::new("ifconfig")
        .arg("pfsync0")
        .output()
        .await
    {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("UP") {
                failures.push("pfsync0 not UP".into());
            }
        }
        Err(_) => failures.push("pfsync0 not present (kernel module loaded?)".into()),
    }

    // 3. Some CARP VIPs configured (any interface) — only meaningful on FreeBSD
    match tokio::process::Command::new("ifconfig").output().await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("carp:") {
                if std::env::consts::OS == "freebsd" {
                    failures.push(
                        "no CARP VIPs configured (no 'carp:' lines in ifconfig)".into(),
                    );
                } else {
                    failures.push(format!(
                        "CARP check skipped: not running on FreeBSD (host OS is {})",
                        std::env::consts::OS
                    ));
                }
            }
        }
        Err(_) => failures.push("ifconfig failed".into()),
    }

    // 4+5. Status from API: peer_reachable and snapshot hash present
    let status: serde_json::Value = match api_get("/api/v1/cluster/status").await {
        Ok(s) => s,
        Err(e) => {
            failures.push(format!("/cluster/status failed: {e}"));
            serde_json::json!({})
        }
    };
    if !status
        .get("peer_reachable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        failures.push("peer unreachable".into());
    }
    if status
        .get("last_snapshot_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        failures.push("no config snapshot on record (replication may be stalled)".into());
    }

    if as_json {
        let body = serde_json::json!({
            "ok": failures.is_empty(),
            "failures": failures,
            "status": status,
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else if failures.is_empty() {
        println!("OK — cluster healthy");
    } else {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
