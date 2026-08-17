use aifw_common::{
    Action, Address, Bandwidth, CountryCode, Direction, GeoIpAction, GeoIpRule, Interface,
    NatRedirect, NatRule, NatType, PortRange, Protocol, QueueConfig, QueueType, RateLimitRule,
    Rule, RuleMatch, TrafficClass, WgPeer, WgTunnel,
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
    Ok(RuleEngine::new(db.pool().clone(), pf))
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
    // "aifw-nat" — must match the API/daemon anchor; NAT loads replace every
    // rule class in their anchor since #531.
    Ok(NatEngine::new(db.pool().clone(), pf).with_anchor("aifw-nat".to_string()))
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
    let kv = format!("{key}={value}");
    let out = aifw_core::sudo::sysrc(&[&kv]).await?;
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
    static_port: bool,
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
        let redir = match rule.nat_type {
            NatType::Nat64 => format!("v6->v4 via {}", rule.redirect.address),
            NatType::Nat46 => format!("v4->v6 via {}", rule.redirect.address),
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
    engine.apply_queues().await?;
    println!("Added queue {}", config.id);
    println!("  pf: {}", config.to_pf_queue());
    Ok(())
}

pub async fn queue_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_shaping_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete_queue(uuid).await?;
    engine.apply_queues().await?;
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
    )?;
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

async fn create_ipsec_engine(db_path: &Path) -> anyhow::Result<aifw_core::IpsecEngine> {
    let db = Database::new(db_path).await?;
    let engine = aifw_core::IpsecEngine::new(
        db.pool().clone(),
        aifw_core::create_ike_control(),
        aifw_core::create_conf_store(),
    );
    engine.migrate().await?;
    Ok(engine)
}

fn split_ts(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub async fn vpn_ipsec_add(
    db_path: &Path,
    name: &str,
    remote: &str,
    psk: &str,
    local_ts: &str,
    remote_ts: &str,
    local: Option<&str>,
) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;

    let mut tunnel = aifw_common::IpsecTunnel::new(
        name.to_string(),
        remote.to_string(),
        psk.to_string(),
        split_ts(local_ts),
        split_ts(remote_ts),
    );
    if let Some(local) = local {
        tunnel.local_addr = local.to_string();
    }
    let tunnel = engine.create_tunnel_applied(tunnel).await?;
    println!("Added IPsec tunnel {}", tunnel.id);
    println!("  Name:      {}", tunnel.name);
    println!("  Remote:    {}", tunnel.remote_addr);
    println!("  Local TS:  {}", tunnel.local_ts.join(","));
    println!("  Remote TS: {}", tunnel.remote_ts.join(","));
    println!("  IKE:       v2, {}", tunnel.ike_proposal);
    println!("  ESP:       {}", tunnel.esp_proposal);
    Ok(())
}

pub async fn vpn_ipsec_start(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.start_tunnel(uuid).await?;
    println!("IPsec tunnel {id} initiated");
    Ok(())
}

pub async fn vpn_ipsec_stop(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.stop_tunnel(uuid).await?;
    println!("IPsec tunnel {id} terminated");
    Ok(())
}

pub async fn vpn_ipsec_status(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let statuses = engine.live_status().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&statuses)?);
        return Ok(());
    }
    if statuses.is_empty() {
        println!("No IPsec tunnels configured");
        return Ok(());
    }
    println!(
        "{:<38} {:<14} {:<20} {:<10}",
        "TUNNEL", "IKE STATE", "REMOTE", "UPTIME"
    );
    println!("{}", "-".repeat(85));
    for s in &statuses {
        let uptime = s
            .established_secs
            .map(|secs| format!("{}m{}s", secs / 60, secs % 60))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38} {:<14} {:<20} {:<10}",
            s.tunnel_id,
            s.ike_state,
            s.remote_host.as_deref().unwrap_or("-"),
            uptime,
        );
        for c in &s.child_sas {
            println!(
                "  child {}: {} in={}B out={}B rekey_in={}s ts={} <-> {}",
                c.name,
                c.state,
                c.bytes_in,
                c.bytes_out,
                c.rekey_in_secs.unwrap_or(0),
                c.local_ts.join(","),
                c.remote_ts.join(","),
            );
        }
    }
    Ok(())
}

pub async fn vpn_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;

    // Try WG tunnel first, then IPsec tunnel, legacy SA, WG peer
    if engine.delete_wg_tunnel(uuid).await.is_ok() {
        println!("Removed WireGuard tunnel {id}");
    } else if let Ok(ipsec) = create_ipsec_engine(db_path).await
        && ipsec.delete_tunnel_applied(uuid).await.is_ok()
    {
        println!("Removed IPsec tunnel {id}");
    } else if engine.delete_ipsec_sa(uuid).await.is_ok() {
        println!("Removed legacy IPsec SA record {id}");
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
    let ipsec_engine = create_ipsec_engine(db_path).await?;
    let ipsec_tunnels = ipsec_engine.list_tunnels().await?;

    if json {
        let data = serde_json::json!({
            "wireguard": tunnels,
            "ipsec_tunnels": ipsec_tunnels
                .iter()
                .map(|t| t.redacted())
                .collect::<Vec<_>>(),
            "ipsec_legacy_sas": sas,
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

    // IPsec tunnels (#530 real data plane)
    if ipsec_tunnels.is_empty() {
        println!("No IPsec tunnels configured");
    } else {
        println!("IPsec Tunnels:");
        println!(
            "{:<38} {:<14} {:<20} {:<8} {:<6} {:<24}",
            "ID", "NAME", "REMOTE", "AUTH", "ON", "TRAFFIC"
        );
        println!("{}", "-".repeat(115));
        for t in &ipsec_tunnels {
            println!(
                "{:<38} {:<14} {:<20} {:<8} {:<6} {:<24}",
                t.id,
                t.name,
                t.remote_addr,
                t.auth_method,
                if t.enabled { "yes" } else { "no" },
                format!("{} <-> {}", t.local_ts.join(","), t.remote_ts.join(",")),
            );
        }
        println!("\n{} tunnel(s)", ipsec_tunnels.len());
    }

    println!();

    // Legacy IPsec SA records (configuration-only, no data plane)
    if sas.is_empty() {
        println!("No legacy IPsec SA records");
    } else {
        println!("Legacy IPsec SA records (inactive — no data plane):");
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

/// DDL for the `static_routes` table, shared by every routes_* command so the
/// schema can't drift between call sites.
const STATIC_ROUTES_DDL: &str = "CREATE TABLE IF NOT EXISTS static_routes (id TEXT PRIMARY KEY, destination TEXT NOT NULL, gateway TEXT NOT NULL, interface TEXT, metric INTEGER DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, description TEXT, created_at TEXT NOT NULL)";

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
    sqlx::query(STATIC_ROUTES_DDL).execute(pool).await?;

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
    let _ = sqlx::query(STATIC_ROUTES_DDL).execute(pool).await;

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

    // Same pinned Argon2id parameters as the API and setup wizard (SEC-M4 #301).
    let pw_hash = aifw_common::password::hash_password(password)
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

pub async fn update_check(pre: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    println!(
        "Checking for AiFw updates{}...",
        if pre { " (including pre-releases)" } else { "" }
    );
    let info = updater::check_for_update(pre).await?;

    println!("  Current version: v{}", info.current_version);
    println!("  Latest version:  v{}", info.latest_version);
    if info.update_available {
        println!("  Update available!");
        if info.os_upgrade_required {
            println!(
                "  ⚠ Requires FreeBSD {} — upgrade the OS first:",
                info.required_os.as_deref().unwrap_or("newer")
            );
            println!(
                "    aifw update os-upgrade {}",
                info.required_os.as_deref().unwrap_or("<version>")
            );
        } else if info.tarball_url.is_some() {
            println!("  Run 'aifw update install' to update.");
        } else {
            println!("  No update tarball found in the release.");
        }
    } else {
        println!("  Already running the latest version.");
    }
    if let Some(blocked) = &info.blocked_version {
        println!(
            "  v{blocked} is also available and requires FreeBSD {} —",
            info.blocked_requires_os.as_deref().unwrap_or("newer")
        );
        println!(
            "  it unlocks after: aifw update os-upgrade {}",
            info.blocked_requires_os.as_deref().unwrap_or("<version>")
        );
    }
    if info.has_backup {
        println!(
            "  Backup: v{} (run 'aifw update rollback' to restore)",
            info.backup_version.as_deref().unwrap_or("unknown")
        );
    }
    Ok(())
}

pub async fn update_install(auto_restart: bool, pre: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    println!(
        "Checking for AiFw updates{}...",
        if pre { " (including pre-releases)" } else { "" }
    );
    let info = updater::check_for_update(pre).await?;

    if !info.update_available {
        println!(
            "Already running the latest version (v{}).",
            info.current_version
        );
        return Ok(());
    }

    // OS dependency gate (#612): don't download a release this OS can't
    // run. The tarball-level gate in the updater backstops this.
    if info.os_upgrade_required {
        let required = info.required_os.as_deref().unwrap_or("newer");
        anyhow::bail!(
            "AiFw v{} requires FreeBSD {required} but this system runs {}.\n\
             Upgrade the OS first: aifw update os-upgrade {required}",
            info.latest_version,
            updater::current_os_release()
                .await
                .unwrap_or_else(|| "unknown".to_string()),
        );
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
        println!(
            "Update installed. Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it."
        );
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

/// Install AiFw from a local tarball by uploading it to the API's
/// install-local endpoint.  The API streams the file to disk, optionally
/// verifies the sha256 sidecar, and runs the same extract+install path
/// as remote installs.
pub async fn update_install_local(
    path: std::path::PathBuf,
    skip_checksum: bool,
    auto_restart: bool,
) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("tarball not found: {}", path.display());
    }
    if !path.extension().map(|e| e == "xz").unwrap_or(false) {
        anyhow::bail!("expected a .tar.xz file, got: {}", path.display());
    }

    let meta = tokio::fs::metadata(&path).await?;
    let size_mb = meta.len() / (1024 * 1024);

    if !auto_restart {
        use std::io::{BufRead, Write};
        println!(
            "Install from local tarball: {} ({} MB)",
            path.display(),
            size_mb
        );
        print!("Proceed? [y/N] ");
        // best-effort prompt flush; a broken stdout pipe is unactionable here
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let answer = line.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!(
        "Uploading {} ({} MB) to API...",
        path.file_name().unwrap_or_default().to_string_lossy(),
        size_mb
    );

    // Build a multipart form.  Load the tarball into memory (50-100 MB is
    // fine for local use) to avoid pulling in a streaming-body dependency
    // beyond what reqwest multipart already provides.
    let tarball_bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read tarball: {e}"))?;

    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut form = reqwest::multipart::Form::new().part(
        "tarball",
        reqwest::multipart::Part::bytes(tarball_bytes).file_name(filename),
    );

    if !skip_checksum {
        // Expect <file>.sha256 next to the tarball.
        let sha_path = {
            let mut p = path.clone();
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            p.set_file_name(format!("{}.sha256", name));
            p
        };
        if !sha_path.exists() {
            anyhow::bail!(
                "sha256 sidecar not found: {} — use --skip-checksum to bypass",
                sha_path.display()
            );
        }
        let sha_content = tokio::fs::read_to_string(&sha_path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read sha256 sidecar: {e}"))?;
        form = form.text("sha256", sha_content);
    }

    if auto_restart {
        form = form.text("restart", "true");
    }

    let client = reqwest::Client::builder()
        // Use a longer timeout for the upload — 50-100 MB over localhost
        // is fast, but give headroom for slow test VMs.
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let token = read_api_token();
    let url = format!("{AIFW_API_BASE}/api/v1/updates/aifw/install-local");
    let mut req = client.post(&url).multipart(form);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("install-local failed: {} {}", status, body);
    }

    let data: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let msg = data["message"].as_str().unwrap_or("install accepted");
    println!("{}", msg);
    println!("Check `aifw update history` for status.");

    if auto_restart {
        println!("Restarting services...");
        aifw_core::updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!("Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it.");
    }

    Ok(())
}

/// Interactive confirmation. Returns true on y/yes (case-insensitive).
/// Defaults to no on bare Enter — restarts are user-visible outages, the
/// safe answer when the operator hasn't decided is "don't bounce yet".
fn prompt_restart_yes() -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    print!("Restart services now to activate? [y/N] ");
    // best-effort prompt flush; a broken stdout pipe is unactionable here
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub async fn update_os_check() -> anyhow::Result<()> {
    println!("Checking for OS and package updates...");

    let pkg = aifw_core::sudo::pkg("update", &[]).await?;
    if pkg.status.success() {
        println!("  Package catalog updated.");
    } else {
        println!(
            "  Package update failed: {}",
            String::from_utf8_lossy(&pkg.stderr).trim()
        );
    }

    let os = aifw_core::sudo::freebsd_update("fetch", &["--not-running-from-cron"]).await?;
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
    let pending = aifw_core::sudo::pkg("upgrade", &["-n"]).await?;
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

    let pkg = aifw_core::sudo::pkg("upgrade", &["-y"]).await?;
    let stdout = String::from_utf8_lossy(&pkg.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.contains("Upgrading") || l.contains("Installing"))
        .count();
    println!("  {} package(s) updated.", count);

    let os = aifw_core::sudo::freebsd_update("install", &[]).await?;
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

/// FreeBSD release upgrade (#613): fetch + stage the target release,
/// install the new kernel, then hand back to the operator for the reboot.
/// The remaining install passes run automatically when aifw-api starts on
/// the new kernel (or manually via 'aifw update os-install').
pub async fn update_os_upgrade(target: &str, yes: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    let current = updater::current_os_release()
        .await
        .ok_or_else(|| anyhow::anyhow!("cannot determine the running FreeBSD release"))?;
    if updater::os_satisfies(&current, target) {
        println!("Already on FreeBSD {current}; {target} is not newer. Nothing to do.");
        return Ok(());
    }

    println!("FreeBSD release upgrade: {current} → {target}-RELEASE");
    println!("  1. Download and stage the release (can take a while)");
    println!("  2. Install the new kernel");
    println!("  3. Reboot — the remaining install finishes after boot");
    if !yes && !prompt_yes("Proceed with the OS upgrade?")? {
        println!("Aborted.");
        return Ok(());
    }

    println!("Downloading FreeBSD {target}-RELEASE (this is the long part)...");
    let fetch = aifw_core::sudo::freebsd_update_upgrade(target).await?;
    if !fetch.status.success() {
        anyhow::bail!(
            "release fetch failed: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        );
    }
    println!("Release staged. Installing the new kernel...");
    let install = aifw_core::sudo::freebsd_update("install", &[]).await?;
    if !install.status.success() {
        anyhow::bail!(
            "kernel install failed: {}",
            String::from_utf8_lossy(&install.stderr).trim()
        );
    }

    println!();
    println!("Kernel for {target}-RELEASE installed.");
    println!("Reboot now with 'aifw update reboot'. After boot, the remaining");
    println!("userland install runs automatically; check progress on the");
    println!("Updates page or with 'aifw update os-check'.");
    Ok(())
}

fn prompt_yes(question: &str) -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    print!("{question} [y/N] ");
    // best-effort prompt flush; a broken stdout pipe is unactionable here
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

// ============================================================
// Reverse Proxy (TrafficCop) commands
// ============================================================

pub async fn rp_status(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    // Check service status
    let output = aifw_core::sudo::service("trafficcop", "status").await;
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
    let output = aifw_core::sudo::service("trafficcop", "start").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

pub async fn rp_stop() -> anyhow::Result<()> {
    let output = aifw_core::sudo::service("trafficcop", "stop").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_restart() -> anyhow::Result<()> {
    let output = aifw_core::sudo::service("trafficcop", "restart").await?;
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

    // Write config through the narrow `aifw-sudo-write` helper rather
    // than the broad `sudo tee` grant (#204).
    aifw_core::sudo::write_file(
        std::path::Path::new("/usr/local/etc/trafficcop/config.yaml"),
        yaml.as_bytes(),
    )
    .await?;

    println!("Config written. Restarting service...");
    let output = aifw_core::sudo::service("trafficcop", "restart").await?;
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
    if let Ok(t) = std::env::var("AIFW_TOKEN")
        && !t.is_empty()
    {
        return t;
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
        println!(
            "Role:                 {}",
            s["role"].as_str().unwrap_or("?")
        );
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
                    failures.push("no CARP VIPs configured (no 'carp:' lines in ifconfig)".into());
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

/// Delete every stored IDS alert and reclaim the disk space. A bare DELETE
/// only frees pages to SQLite's freelist (#601: a 2.9GB file holding 34
/// rows), so this follows up with VACUUM + a TRUNCATE WAL checkpoint.
/// "no such table" means the IDS subsystem has never initialized this DB —
/// for read/purge paths that's simply "nothing stored", not an error.
fn ids_table_missing(e: &sqlx::Error) -> bool {
    e.to_string().contains("no such table")
}

pub async fn ids_purge_alerts(db_path: &Path, yes: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let (count,): (i64,) = match sqlx::query_as("SELECT COUNT(*) FROM ids_alerts")
        .fetch_one(pool)
        .await
    {
        Ok(row) => row,
        Err(e) if ids_table_missing(&e) => {
            println!("No IDS alerts stored.");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    if count == 0 {
        println!("No IDS alerts stored.");
        return Ok(());
    }
    if !yes {
        use std::io::Write;
        print!("Delete ALL {count} IDS alerts? This cannot be undone. [y/N] ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }
    sqlx::query("DELETE FROM ids_alerts").execute(pool).await?;
    println!("Deleted {count} alerts; reclaiming disk space (may take a moment)...");
    sqlx::query("VACUUM").execute(pool).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(pool)
        .await?;
    println!("Done.");
    Ok(())
}

/// Show or set the alert retention window (days). The hourly retention
/// sweep in aifw-ids prunes past it and reclaims space after big purges.
pub async fn ids_retention(db_path: &Path, days: Option<u32>) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    match days {
        None => {
            let cur: Option<(String,)> = match sqlx::query_as(
                "SELECT value FROM ids_config WHERE key = 'alert_retention_days'",
            )
            .fetch_optional(pool)
            .await
            {
                Ok(row) => row,
                Err(e) if ids_table_missing(&e) => None,
                Err(e) => return Err(e.into()),
            };
            match cur {
                Some((v,)) => println!("Alert retention: {v} days"),
                None => println!("Alert retention: 7 days (default)"),
            }
        }
        Some(d) => {
            anyhow::ensure!(
                (1..=365).contains(&d),
                "retention must be between 1 and 365 days"
            );
            if let Err(e) = sqlx::query(
                "INSERT INTO ids_config (key, value, updated_at) VALUES ('alert_retention_days', ?1, datetime('now')) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
            )
            .bind(d.to_string())
            .execute(pool)
            .await
            {
                if ids_table_missing(&e) {
                    anyhow::bail!(
                        "IDS database not initialized yet — start aifw-api/aifw-ids once, then retry"
                    );
                }
                return Err(e.into());
            }
            println!("Alert retention set to {d} day(s).");
            println!(
                "  The running aifw-ids applies it after an IDS reload (UI) or 'service aifw_ids restart'."
            );
        }
    }
    Ok(())
}

// ============================================================================
// Remote syslog forwarding (aifw syslog ...)
// ============================================================================

/// Optional field updates for `aifw syslog set`; `None` = keep current value.
pub struct SyslogSetOpts {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<String>,
    pub format: Option<String>,
    pub facility: Option<String>,
    pub hostname: Option<String>,
    pub pf: Option<bool>,
    pub ids: Option<bool>,
    pub app: Option<bool>,
    pub app_min_level: Option<String>,
    pub disable_local: Option<bool>,
}

// ============================================================
// Log rotation (#205)
// ============================================================

fn human_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    let b = b as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{b} B")
    }
}

pub async fn logrotate_show(db_path: &Path, json: bool) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    let db = Database::new(db_path).await?;
    let cfg = lr::load(db.pool()).await;
    let logs = lr::status().await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "config": cfg,
                "logs": logs,
                "conf_path": lr::CONF_PATH,
            }))?
        );
        return Ok(());
    }
    println!("Log rotation policy (all AiFw-managed service logs)");
    println!("  Rotate above:   {} MB", cfg.max_size_mb);
    println!("  Keep:           {} rotated generation(s)", cfg.keep);
    println!("  Compression:    {}", cfg.compression.as_str());
    println!("  newsyslog conf: {}", lr::CONF_PATH);
    println!();
    println!(
        "  {:<13} {:<36} {:>10} {:>8} {:>10}",
        "SERVICE", "LOG", "SIZE", "ROTATED", "TOTAL"
    );
    for l in &logs {
        println!(
            "  {:<13} {:<36} {:>10} {:>8} {:>10}",
            l.service,
            l.path,
            l.size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "-".to_string()),
            l.rotated,
            human_bytes(l.total_bytes)
        );
    }
    Ok(())
}

pub async fn logrotate_set(
    db_path: &Path,
    max_size: Option<u32>,
    keep: Option<u32>,
    compression: Option<&str>,
) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    if max_size.is_none() && keep.is_none() && compression.is_none() {
        anyhow::bail!("nothing to change — pass --max-size, --keep and/or --compression");
    }
    let db = Database::new(db_path).await?;
    let mut cfg = lr::load(db.pool()).await;
    if let Some(v) = max_size {
        cfg.max_size_mb = v;
    }
    if let Some(v) = keep {
        cfg.keep = v;
    }
    if let Some(c) = compression {
        cfg.compression = lr::Compression::parse(c).ok_or_else(|| {
            anyhow::anyhow!("unknown compression {c:?} (gzip, bzip2, xz, zstd, none)")
        })?;
    }
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    lr::save(db.pool(), &cfg).await?;
    println!(
        "Saved: rotate above {} MB, keep {}, compression {}.",
        cfg.max_size_mb,
        cfg.keep,
        cfg.compression.as_str()
    );
    if cfg!(target_os = "freebsd") {
        lr::write_conf(&cfg).await?;
        match lr::run_now().await {
            Ok(msg) => println!("{msg}"),
            Err(e) => println!("Policy written; immediate newsyslog pass failed: {e}"),
        }
    }
    Ok(())
}

pub async fn logrotate_rotate(db_path: &Path, path: Option<&str>) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    if !cfg!(target_os = "freebsd") {
        anyhow::bail!("log rotation is only available on the FreeBSD appliance");
    }
    // Make sure the fragment reflects the stored policy before rotating.
    let db = Database::new(db_path).await?;
    let cfg = lr::load(db.pool()).await;
    lr::write_conf(&cfg).await?;
    let msg = match path {
        Some(p) => lr::rotate_now(p).await?,
        None => lr::run_now().await?,
    };
    println!("{msg}");
    Ok(())
}

async fn syslog_load(
    db_path: &Path,
) -> anyhow::Result<(Database, aifw_common::syslog::SyslogConfig)> {
    let db = Database::new(db_path).await?;
    aifw_common::syslog::migrate(db.pool()).await?;
    let cfg = aifw_common::syslog::load(db.pool()).await;
    Ok((db, cfg))
}

fn syslog_print_effect() {
    println!("Change takes effect within 60 seconds (all AiFw services poll for syslog config).");
}

pub async fn syslog_show(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let (_db, cfg) = syslog_load(db_path).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg)?);
        return Ok(());
    }
    let facility_label = aifw_common::syslog::facility_name(cfg.facility)
        .map(|n| format!("{} ({n})", cfg.facility))
        .unwrap_or_else(|| cfg.facility.to_string());
    println!("Remote syslog forwarding");
    println!(
        "  Enabled:        {}",
        if cfg.enabled { "yes" } else { "no" }
    );
    println!(
        "  Server:         {}",
        if cfg.host.is_empty() {
            "(not configured)".to_string()
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        }
    );
    println!("  Transport:      {}", cfg.transport.as_str());
    println!("  Format:         {}", cfg.format.as_str());
    println!("  Facility:       {facility_label}");
    println!(
        "  Hostname:       {}",
        if cfg.hostname_override.is_empty() {
            "(system hostname)"
        } else {
            &cfg.hostname_override
        }
    );
    println!("  Categories:");
    println!(
        "    pf logs:      {}",
        if cfg.pf_enabled { "on" } else { "off" }
    );
    println!(
        "    IDS alerts:   {}",
        if cfg.ids_enabled { "on" } else { "off" }
    );
    println!(
        "    app logs:     {}{}",
        if cfg.app_enabled { "on" } else { "off" },
        if cfg.app_enabled {
            format!(" (min level {})", cfg.app_min_level)
        } else {
            String::new()
        }
    );
    println!(
        "  Local storage:  {}",
        if cfg.disable_local {
            "disabled while forwarding"
        } else {
            "kept"
        }
    );
    Ok(())
}

pub async fn syslog_enable(db_path: &Path, enabled: bool) -> anyhow::Result<()> {
    let (db, mut cfg) = syslog_load(db_path).await?;
    cfg.enabled = enabled;
    if let Err(e) = cfg.validate() {
        anyhow::bail!("{e} — set one with: aifw syslog set --host <server>");
    }
    aifw_common::syslog::save(db.pool(), &cfg).await?;
    if enabled {
        println!(
            "Remote syslog forwarding enabled ({}:{} over {}).",
            cfg.host,
            cfg.port,
            cfg.transport.as_str()
        );
        if !cfg.pf_enabled && !cfg.ids_enabled && !cfg.app_enabled {
            println!(
                "  Note: no categories are on yet — enable some with e.g. 'aifw syslog set --pf true'."
            );
        }
    } else {
        println!("Remote syslog forwarding disabled.");
    }
    syslog_print_effect();
    Ok(())
}

pub async fn syslog_set(db_path: &Path, opts: SyslogSetOpts) -> anyhow::Result<()> {
    let (db, mut cfg) = syslog_load(db_path).await?;
    if let Some(h) = opts.host {
        cfg.host = h;
    }
    if let Some(p) = opts.port {
        cfg.port = p;
    }
    if let Some(t) = opts.transport {
        cfg.transport = match t.to_ascii_lowercase().as_str() {
            "udp" => aifw_common::syslog::Transport::Udp,
            "tcp" => aifw_common::syslog::Transport::Tcp,
            other => anyhow::bail!("transport must be udp or tcp (got '{other}')"),
        };
    }
    if let Some(f) = opts.format {
        cfg.format = match f.to_ascii_lowercase().as_str() {
            "rfc3164" | "bsd" => aifw_common::syslog::SyslogFormat::Rfc3164,
            "rfc5424" => aifw_common::syslog::SyslogFormat::Rfc5424,
            other => anyhow::bail!("format must be rfc3164 (bsd) or rfc5424 (got '{other}')"),
        };
    }
    if let Some(f) = opts.facility {
        cfg.facility = aifw_common::syslog::facility_from_name(&f).ok_or_else(|| {
            anyhow::anyhow!("unknown facility '{f}' (use a name like local0 or a number 0-23)")
        })?;
    }
    if let Some(h) = opts.hostname {
        cfg.hostname_override = h;
    }
    if let Some(v) = opts.pf {
        cfg.pf_enabled = v;
    }
    if let Some(v) = opts.ids {
        cfg.ids_enabled = v;
    }
    if let Some(v) = opts.app {
        cfg.app_enabled = v;
    }
    if let Some(l) = opts.app_min_level {
        cfg.app_min_level = l.to_ascii_lowercase();
    }
    if let Some(v) = opts.disable_local {
        cfg.disable_local = v;
    }
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    aifw_common::syslog::save(db.pool(), &cfg).await?;
    println!("Syslog settings updated.");
    if !cfg.enabled {
        println!("  Forwarding is currently disabled — turn it on with 'aifw syslog enable'.");
    }
    syslog_print_effect();
    Ok(())
}

pub async fn syslog_test(
    db_path: &Path,
    host: Option<String>,
    port: Option<u16>,
) -> anyhow::Result<()> {
    let (_db, mut cfg) = syslog_load(db_path).await?;
    if let Some(h) = host {
        cfg.host = h;
    }
    if let Some(p) = port {
        cfg.port = p;
    }
    anyhow::ensure!(
        !cfg.host.trim().is_empty(),
        "no syslog server configured — set one with 'aifw syslog set --host <server>' or pass --host"
    );
    match aifw_common::syslog::test_send(&cfg, "AiFw remote syslog test message (CLI)").await {
        Ok(()) => {
            println!(
                "Test message sent to {}:{} over {} ({}).",
                cfg.host,
                cfg.port,
                cfg.transport.as_str(),
                cfg.format.as_str()
            );
            if cfg.transport == aifw_common::syslog::Transport::Udp {
                println!("  UDP is fire-and-forget — check the server received it.");
            }
        }
        Err(e) => anyhow::bail!("test send failed: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod syslog_cli_tests {
    use super::*;

    #[tokio::test]
    async fn set_and_show_round_trip() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-syslog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");

        syslog_set(
            &db_path,
            SyslogSetOpts {
                host: Some("192.0.2.20".into()),
                port: Some(1514),
                transport: Some("tcp".into()),
                format: Some("rfc5424".into()),
                facility: Some("local3".into()),
                hostname: None,
                pf: Some(true),
                ids: None,
                app: None,
                app_min_level: None,
                disable_local: None,
            },
        )
        .await
        .unwrap();

        let (_db, cfg) = syslog_load(&db_path).await.unwrap();
        assert_eq!(cfg.host, "192.0.2.20");
        assert_eq!(cfg.port, 1514);
        assert_eq!(cfg.transport, aifw_common::syslog::Transport::Tcp);
        assert_eq!(cfg.format, aifw_common::syslog::SyslogFormat::Rfc5424);
        assert_eq!(cfg.facility, 19);
        assert!(cfg.pf_enabled);
        assert!(!cfg.enabled);

        syslog_enable(&db_path, true).await.unwrap();
        let (_db, cfg) = syslog_load(&db_path).await.unwrap();
        assert!(cfg.enabled);

        // Invalid facility is rejected before anything is saved.
        let bad = syslog_set(
            &db_path,
            SyslogSetOpts {
                host: None,
                port: None,
                transport: None,
                format: None,
                facility: Some("nope".into()),
                hostname: None,
                pf: None,
                ids: None,
                app: None,
                app_min_level: None,
                disable_local: None,
            },
        )
        .await;
        assert!(bad.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
