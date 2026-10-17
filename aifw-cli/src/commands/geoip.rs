//! `aifw geoip …`. Rule commands write the database directly; the running
//! API re-applies the anchor within a minute. Database commands
//! (`database`, `refresh`, `import`) ask the API, which owns the loaded
//! index, and need a token (`AIFW_TOKEN`).

use aifw_common::{CountryCode, GeoIpAction, GeoIpRule};
use aifw_core::{Database, GeoIpEngine};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

use super::plugins::api;

const APPLY_NOTE: &str = "The running aifw-api applies the change within a minute.";

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
    println!("{APPLY_NOTE}");
    Ok(())
}

pub async fn geoip_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_geoip_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.delete(uuid).await?;
    println!("Removed geo-ip rule {id}. {APPLY_NOTE}");
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

    // The index lives in the API process; this process's engine is empty.
    let live = api(reqwest::Method::GET, "/api/v1/geoip", None).await.ok();
    let cidrs_of = |country: &str| -> Option<i64> {
        live.as_ref()?["data"]
            .as_array()?
            .iter()
            .find(|r| r["country"] == country)?["cidr_count"]
            .as_i64()
    };

    println!(
        "{:<38} {:<8} {:<8} {:<20} {:>8} LABEL",
        "ID", "COUNTRY", "ACTION", "TABLE", "CIDRS"
    );
    println!("{}", "-".repeat(85));

    for r in &rules {
        let status = match r.status {
            aifw_common::GeoIpRuleStatus::Active => "",
            aifw_common::GeoIpRuleStatus::Disabled => " [disabled]",
        };
        println!(
            "{:<38} {:<8} {:<8} {:<20} {:>8} {}{}",
            r.id,
            r.country,
            r.action,
            r.table_name(),
            cidrs_of(&r.country.0)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            r.label.as_deref().unwrap_or(""),
            status,
        );
    }

    println!("\n{} rule(s)", rules.len());
    match api(reqwest::Method::GET, "/api/v1/geoip/database", None).await {
        Ok(st) => println!("{}", database_line(&st)),
        Err(e) => println!("Database status unavailable: {e}."),
    }
    Ok(())
}

fn database_line(st: &Value) -> String {
    if st["loaded"].as_bool() != Some(true) {
        return "Database: not loaded — add a MaxMind license key (aifw geoip database --license-key-stdin) or import the GeoLite2 Country CSV release (aifw geoip import FILE.zip)".into();
    }
    format!(
        "Database: {} countries, {} CIDRs ({}, updated {})",
        st["countries"],
        st["cidrs"],
        st["source"].as_str().unwrap_or("?"),
        st["updated_at"].as_str().unwrap_or("?")
    )
}

/// Database status, settings, and the refresh schedule.
pub async fn geoip_database(
    license_key_stdin: bool,
    clear_license_key: bool,
    account_id: Option<&str>,
    update_interval_hours: Option<u32>,
    json_out: bool,
) -> anyhow::Result<()> {
    let mut body = serde_json::Map::new();
    if let Some(a) = account_id {
        body.insert(
            "account_id".into(),
            if a.is_empty() {
                Value::Null
            } else {
                Value::String(a.to_string())
            },
        );
    }
    if license_key_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let key = line.trim();
        if key.is_empty() {
            anyhow::bail!("--license-key-stdin: nothing was read from stdin");
        }
        body.insert("license_key".into(), Value::String(key.to_string()));
    } else if clear_license_key {
        body.insert("license_key".into(), Value::Null);
    }
    if let Some(h) = update_interval_hours {
        body.insert("update_interval_hours".into(), json!(h));
    }
    let st = if body.is_empty() {
        api(reqwest::Method::GET, "/api/v1/geoip/database", None).await
    } else {
        api(
            reqwest::Method::PUT,
            "/api/v1/geoip/database",
            Some(&Value::Object(body)),
        )
        .await
    }
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&st)?);
        return Ok(());
    }
    println!("{}", database_line(&st));
    println!(
        "  Directory:      {}",
        st["db_path"].as_str().unwrap_or("?")
    );
    println!(
        "  Account ID:     {}",
        st["account_id"].as_str().unwrap_or("not set")
    );
    println!(
        "  License key:    {}",
        if st["has_license_key"] == true {
            "set"
        } else {
            "not set"
        }
    );
    let hours = st["update_interval_hours"].as_u64().unwrap_or(0);
    println!(
        "  Auto-refresh:   {}",
        if hours == 0 {
            "off".to_string()
        } else {
            format!("every {hours} h")
        }
    );
    if let Some(n) = st["next_refresh"].as_str() {
        println!("  Next refresh:   {n}");
    }
    if let Some(a) = st["last_refresh_attempt"].as_str() {
        println!("  Last attempt:   {a}");
    }
    if let Some(e) = st["last_error"].as_str() {
        println!("  Last error:     {e}");
    }
    Ok(())
}

/// Download the GeoLite2 release from MaxMind now.
pub async fn geoip_refresh() -> anyhow::Result<()> {
    let v = api(
        reqwest::Method::POST,
        "/api/v1/geoip/database/refresh",
        Some(&Value::Null),
    )
    .await
    .map_err(|e| anyhow::anyhow!("refresh failed: {e}"))?;
    println!("Downloaded and applied: {} networks.", v["cidrs"]);
    println!("{}", database_line(&v["status"]));
    Ok(())
}

/// Upload a GeoLite2 Country CSV zip (or a single .csv) to the API.
pub async fn geoip_import(files: &[std::path::PathBuf]) -> anyhow::Result<()> {
    use super::cluster::{AIFW_API_BASE, read_api_token};
    if files.is_empty() {
        anyhow::bail!("pass the GeoLite2 Country CSV zip, or the .csv files");
    }
    let mut form = reqwest::multipart::Form::new();
    for f in files {
        let name = f
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("{}: not a valid file name", f.display()))?
            .to_string();
        let bytes = std::fs::read(f).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        form = form.part(
            name.clone(),
            reqwest::multipart::Part::bytes(bytes).file_name(name),
        );
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let mut req = client.post(format!("{AIFW_API_BASE}/api/v1/geoip/database/upload"));
    let token = read_api_token();
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.multipart(form).send().await?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        anyhow::bail!(
            "import failed: {}",
            v["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("HTTP {status}"))
        );
    }
    println!("Imported and applied: {} networks.", v["cidrs"]);
    println!("{}", database_line(&v["status"]));
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
