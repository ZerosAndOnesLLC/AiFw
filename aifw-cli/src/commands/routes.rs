//! `aifw routes …`.

use aifw_core::Database;
use std::path::Path;
use uuid::Uuid;

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
            // #325: a failed kernel-route delete leaves a stale route the
            // DB no longer knows about — say so instead of hiding it.
            match std::process::Command::new("route")
                .args(["delete", &dest, &gw])
                .output()
            {
                Ok(o) if o.status.success() => {}
                Ok(o) => eprintln!(
                    "warning: route delete {dest} {gw} exited {}: {}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                Err(e) => eprintln!("warning: route delete {dest} {gw} failed to run: {e}"),
            }
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
