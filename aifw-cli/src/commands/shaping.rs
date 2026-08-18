//! `aifw queue …` and `aifw ratelimit …`.

use aifw_common::{
    Bandwidth, Interface, Protocol, QueueConfig, QueueType, RateLimitRule, TrafficClass,
};
use aifw_core::{Database, ShapingEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

use super::common::*;

// --- Queue commands ---

pub(super) async fn create_shaping_engine(db_path: &Path) -> anyhow::Result<ShapingEngine> {
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
