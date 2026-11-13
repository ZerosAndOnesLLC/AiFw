//! `aifw geoip …` — country rules and the GeoLite2 database (via the API;
//! rule writes are applied to pf immediately by the API).

use std::path::PathBuf;
use std::time::Duration;

use aifw_client::{Upload, UploadFile};
use clap::Subcommand;
use serde_json::{Map, Value, json};

use crate::cli::body::Fields;
use crate::cli::exit::CliError;
use crate::cli::{Ctx, Format, col, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum GeoipCmd {
    /// Add a country rule
    Add {
        /// ISO country code, e.g. CN
        #[arg(long)]
        country: String,
        /// block or allow
        #[arg(long)]
        action: String,
        #[arg(long)]
        label: Option<String>,
        /// Create it disabled
        #[arg(long)]
        disabled: bool,
    },
    /// Change a country rule
    Edit {
        id: String,
        #[arg(long)]
        country: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Delete a country rule
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Enable a country rule
    Enable { id: String },
    /// Disable a country rule
    Disable { id: String },
    /// List country rules (and the database status)
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Which country an IP belongs to
    Lookup { ip: String },
    /// Show or configure the GeoLite2 database source and refresh schedule
    #[command(after_help = "\
EXAMPLES:
    aifw geoip database                                  # status, schedule, last refresh
    aifw geoip database --account-id 123456              # MaxMind account ID (pairs with the key)
    printf '%s' \"$KEY\" | aifw geoip database --license-key-stdin
    aifw geoip database --update-interval-hours 168      # weekly (0 turns auto-refresh off)
    aifw geoip database --clear-license-key")]
    Database {
        /// Read the MaxMind license key from stdin
        #[arg(long)]
        license_key_stdin: bool,
        /// Remove the stored license key
        #[arg(long, conflicts_with = "license_key_stdin")]
        clear_license_key: bool,
        /// MaxMind account ID ("" clears it)
        #[arg(long, value_name = "ID")]
        account_id: Option<String>,
        /// Hours between automatic refreshes (0 = off)
        #[arg(long)]
        update_interval_hours: Option<u32>,
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Download the database now
    Refresh,
    /// Upload a GeoLite2 Country CSV release (the zip, or its .csv files)
    Import {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("COUNTRY", "/country"),
    col("ACTION", "/action"),
    col("STATUS", "/status"),
    col("CIDRS", "/cidr_count"),
    col("LABEL", "/label"),
    wide("TABLE", "/table"),
    wide("UPDATED", "/updated_at"),
];

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

fn print_database(ctx: &mut Ctx, st: &Value) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        return ctx.raw(st);
    }
    ctx.io.println(&database_line(st));
    let hours = st["update_interval_hours"].as_u64().unwrap_or(0);
    let mut v = st.clone();
    v["_key"] = json!(if st["has_license_key"] == true {
        "set"
    } else {
        "not set"
    });
    v["_refresh"] = json!(if hours == 0 {
        "off".to_string()
    } else {
        format!("every {hours} h")
    });
    let d = crate::cli::output::detail(
        &v,
        &[
            ("  Directory", "/db_path"),
            ("  Account ID", "/account_id"),
            ("  License key", "/_key"),
            ("  Auto-refresh", "/_refresh"),
            ("  Next refresh", "/next_refresh"),
            ("  Last attempt", "/last_refresh_attempt"),
            ("  Last error", "/last_error"),
        ],
    );
    ctx.io.println(&d);
    Ok(())
}

async fn find(client: &aifw_client::Client, id: &str) -> anyhow::Result<Value> {
    let all = client.get("/geoip").await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|r| r["id"] == json!(id))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("geoip rule {id}")).into())
}

fn to_request(r: &Value) -> Value {
    json!({
        "country_code": r["country"],
        "action": r["action"],
        "status": r["status"],
        "label": r["label"],
    })
}

pub async fn run(ctx: &mut Ctx, cmd: GeoipCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        GeoipCmd::List { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/geoip").await?;
            ctx.list(&v, COLS)?;
            if !ctx.format().is_structured()
                && let Ok(st) = client.get("/geoip/database").await
            {
                ctx.io.println(&database_line(&st));
            }
            Ok(())
        }
        GeoipCmd::Add {
            country,
            action,
            label,
            disabled,
        } => {
            let body = Fields::new()
                .set("country_code", country.to_ascii_uppercase())
                .set("action", action)
                .opt("label", label)
                .flag("status", disabled, "disabled")
                .into_value();
            let v = client.post("/geoip", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let r = crate::cli::output::item(&v);
            ctx.io.println(&format!(
                "Added geoip rule {} ({} {})",
                r["id"].as_str().unwrap_or("?"),
                r["action"].as_str().unwrap_or("?"),
                r["country"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        GeoipCmd::Edit {
            id,
            country,
            action,
            label,
        } => {
            let current = to_request(&find(&client, &id).await?);
            let flags = Fields::new()
                .opt("country_code", country.map(|c| c.to_ascii_uppercase()))
                .opt("action", action)
                .opt("label", label);
            let body = crate::cli::body::for_update(&mut ctx.io, current, None, flags)?;
            let v = client.put(&format!("/geoip/{id}"), &body).await?;
            ctx.message(&v, &format!("Updated geoip rule {id}"))
        }
        GeoipCmd::Enable { id } => set_status(ctx, &client, &id, "active").await,
        GeoipCmd::Disable { id } => set_status(ctx, &client, &id, "disabled").await,
        GeoipCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete geoip rule {id}?"), yes)?;
            let v = client.delete(&format!("/geoip/{id}")).await?;
            ctx.message(&v, &format!("Removed geoip rule {id}"))
        }
        GeoipCmd::Lookup { ip } => {
            let v = client.get(&format!("/geoip/lookup/{ip}")).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let line = match v["country"].as_str() {
                Some(c) => format!("{ip}: {c} ({})", v["network"].as_str().unwrap_or("?")),
                None => format!("{ip}: no country match"),
            };
            ctx.io.println(&line);
            Ok(())
        }
        GeoipCmd::Database {
            license_key_stdin,
            clear_license_key,
            account_id,
            update_interval_hours,
            json,
        } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let mut body = Map::new();
            if let Some(a) = account_id {
                body.insert(
                    "account_id".into(),
                    if a.is_empty() { Value::Null } else { json!(a) },
                );
            }
            if license_key_stdin {
                let key = prompt::read_line_raw(&mut ctx.io)?.trim().to_string();
                if key.is_empty() {
                    return Err(CliError::Usage(
                        "--license-key-stdin: nothing was read from stdin".into(),
                    )
                    .into());
                }
                body.insert("license_key".into(), json!(key));
            } else if clear_license_key {
                body.insert("license_key".into(), Value::Null);
            }
            if let Some(h) = update_interval_hours {
                body.insert("update_interval_hours".into(), json!(h));
            }
            let st = if body.is_empty() {
                client.get("/geoip/database").await?
            } else {
                client.put("/geoip/database", &Value::Object(body)).await?
            };
            print_database(ctx, &st)
        }
        GeoipCmd::Refresh => {
            let timeout = ctx.slow_timeout(Duration::from_secs(600));
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/geoip/database/refresh",
                    None,
                    timeout,
                )
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io
                .println(&format!("Refreshed: {} networks.", v["cidrs"]));
            ctx.io.println(&database_line(&v["status"]));
            Ok(())
        }
        GeoipCmd::Import { files } => {
            let mut parts = Vec::new();
            for f in &files {
                let name = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| {
                        CliError::Usage(format!("{}: not a valid file name", f.display()))
                    })?
                    .to_string();
                let bytes = std::fs::read(f)
                    .map_err(|e| CliError::Usage(format!("{}: {e}", f.display())))?;
                parts.push(UploadFile {
                    field: name.clone(),
                    file_name: name,
                    bytes,
                });
            }
            let timeout = ctx.slow_timeout(Duration::from_secs(600));
            let v = client
                .upload(
                    "/geoip/database/upload",
                    Upload {
                        files: parts,
                        fields: vec![],
                    },
                    timeout,
                )
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io
                .println(&format!("Imported and applied: {} networks.", v["cidrs"]));
            ctx.io.println(&database_line(&v["status"]));
            Ok(())
        }
    }
}

async fn set_status(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    id: &str,
    status: &str,
) -> anyhow::Result<()> {
    let mut body = to_request(&find(client, id).await?);
    body["status"] = json!(status);
    let v = client.put(&format!("/geoip/{id}"), &body).await?;
    ctx.message(
        &v,
        &format!(
            "geoip rule {id} {}",
            if status == "active" {
                "enabled"
            } else {
                "disabled"
            }
        ),
    )
}
