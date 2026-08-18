//! `aifw geoip …`.

use aifw_common::{CountryCode, GeoIpAction, GeoIpRule};
use aifw_core::{Database, GeoIpEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

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
    let rule = engine.add(rule).await?;
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
    engine.delete(uuid).await?;
    println!("Removed geo-ip rule {id}");
    Ok(())
}

pub async fn geoip_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let rules = engine.list().await?;

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
