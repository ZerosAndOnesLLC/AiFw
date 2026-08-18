//! `aifw dns …`.

use aifw_core::Database;
use std::path::Path;

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
