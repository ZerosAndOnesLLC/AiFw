//! `aifw ids …`.

use aifw_core::Database;
use std::path::Path;

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
