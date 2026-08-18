//! `aifw dhcp …`.

use aifw_core::Database;
use std::path::Path;
use uuid::Uuid;

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
