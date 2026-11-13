//! `aifw ratelimit …` — connection rate limits. There is no API for these
//! yet, so they stay a local (root, on-box) operation on the database + pf.

use aifw_common::{Interface, PortRange, Protocol, RateLimitRule};
use aifw_core::{Database, ShapingEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

pub(super) async fn create_shaping_engine(db_path: &Path) -> anyhow::Result<ShapingEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    let engine = ShapingEngine::new(db.pool().clone(), pf);
    engine.migrate().await?;
    Ok(engine)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_single_and_range() {
        assert_eq!(parse_port("22").unwrap(), PortRange { start: 22, end: 22 });
        assert_eq!(
            parse_port("8000:8080").unwrap(),
            PortRange {
                start: 8000,
                end: 8080
            }
        );
        assert!(parse_port("x").is_err());
        assert!(parse_port("70000").is_err(), "u16 overflow rejected");
        assert!(parse_port("1:2:3").is_err());
    }
}
