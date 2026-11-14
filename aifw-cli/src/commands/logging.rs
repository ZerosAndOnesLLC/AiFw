//! `aifw syslog …` (remote syslog forwarding) and `aifw logrotate …`
//! (rotation policy for AiFw service logs), via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, Format, col};

#[derive(Debug, Subcommand)]
pub enum SyslogCmd {
    /// Show the forwarding configuration
    Show {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Turn forwarding on
    Enable,
    /// Turn forwarding off
    Disable,
    /// Change settings (only the flags you pass)
    #[command(after_help = "\
EXAMPLES:
    # Point at a syslog server and enable pf log forwarding
    aifw syslog set --host 192.168.1.10 --port 514 --pf true
    aifw syslog enable

    # Switch to TCP with RFC 5424 framing on facility local3
    aifw syslog set --transport tcp --format rfc5424 --facility local3

    # Forward everything, app logs at warn and above
    aifw syslog set --pf true --ids true --app true --app-min-level warn")]
    Set {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// udp or tcp
        #[arg(long)]
        transport: Option<String>,
        /// rfc3164 (bsd) or rfc5424
        #[arg(long)]
        format: Option<String>,
        /// Facility name (local0…local7, daemon, …) or number 0-23
        #[arg(long)]
        facility: Option<String>,
        /// Hostname to send ("" = the system hostname)
        #[arg(long)]
        hostname: Option<String>,
        /// Forward pf (firewall) logs
        #[arg(long)]
        pf: Option<bool>,
        /// Forward IDS alerts
        #[arg(long)]
        ids: Option<bool>,
        /// Forward AiFw application logs
        #[arg(long)]
        app: Option<bool>,
        /// Lowest application log level to forward (info, warn, error)
        #[arg(long)]
        app_min_level: Option<String>,
        /// Stop writing the forwarded logs locally
        #[arg(long)]
        disable_local: Option<bool>,
    },
    /// Send a test message (the saved config, or override host/port)
    #[command(after_help = "\
EXAMPLES:
    aifw syslog test                          # use the saved configuration
    aifw syslog test --host 10.0.0.9 --port 5514")]
    Test {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Forwarder delivery status
    Status,
}

#[derive(Debug, Subcommand)]
pub enum LogrotateCmd {
    /// Show the policy and the managed logs
    Show {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Change the policy (only the flags you pass)
    #[command(after_help = "\
EXAMPLES:
    # Rotate at 20 MB, keep 5 compressed generations
    aifw logrotate set --max-size 20 --keep 5

    # Switch rotated logs to zstd (gzip, bzip2, xz, zstd, none)
    aifw logrotate set --compression zstd")]
    Set {
        #[arg(long, value_name = "MB")]
        max_size: Option<u32>,
        #[arg(long)]
        keep: Option<u32>,
        #[arg(long)]
        compression: Option<String>,
    },
    /// Rotate now (one log, or all managed logs)
    Rotate {
        #[arg(long)]
        path: Option<String>,
    },
}

fn human_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn print_syslog(ctx: &mut Ctx, cfg: &Value) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        return ctx.raw(cfg);
    }
    let mut v = cfg.clone();
    if let Some(n) = cfg["facility"].as_u64() {
        let name = u8::try_from(n)
            .ok()
            .and_then(aifw_common::syslog::facility_name);
        v["facility"] = json!(name.map_or_else(|| n.to_string(), str::to_string));
    }
    ctx.detail(
        &v,
        &[
            ("Enabled", "/enabled"),
            ("Server", "/host"),
            ("Port", "/port"),
            ("Transport", "/transport"),
            ("Format", "/format"),
            ("Facility", "/facility"),
            ("Hostname", "/hostname_override"),
            ("pf logs", "/pf_enabled"),
            ("IDS alerts", "/ids_enabled"),
            ("App logs", "/app_enabled"),
            ("App min level", "/app_min_level"),
            ("Local logging off", "/disable_local"),
        ],
    )
}

pub async fn syslog(ctx: &mut Ctx, cmd: SyslogCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        SyslogCmd::Show { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let cfg = client.get("/settings/syslog").await?;
            print_syslog(ctx, &cfg)
        }
        SyslogCmd::Enable | SyslogCmd::Disable => {
            let on = matches!(cmd, SyslogCmd::Enable);
            let mut cfg = client.get("/settings/syslog").await?;
            if on && cfg["host"].as_str().is_none_or(str::is_empty) {
                return Err(CliError::Usage(
                    "no syslog server configured; set one with: aifw syslog set --host <server>"
                        .into(),
                )
                .into());
            }
            cfg["enabled"] = json!(on);
            let saved = client.put("/settings/syslog", &cfg).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&saved);
            }
            ctx.io.println(&format!(
                "Remote syslog {}.",
                if on { "enabled" } else { "disabled" }
            ));
            Ok(())
        }
        SyslogCmd::Set {
            host,
            port,
            transport,
            format,
            facility,
            hostname,
            pf,
            ids,
            app,
            app_min_level,
            disable_local,
        } => {
            let mut cfg = client.get("/settings/syslog").await?;
            let before = cfg.clone();
            let mut set = |k: &str, v: Option<Value>| {
                if let Some(v) = v {
                    cfg[k] = v;
                }
            };
            set("host", host.map(|v| json!(v)));
            set("port", port.map(|v| json!(v)));
            set(
                "transport",
                transport.map(|v| json!(v.to_ascii_lowercase())),
            );
            set(
                "format",
                format.map(|f| {
                    json!(match f.to_ascii_lowercase().as_str() {
                        "bsd" => "rfc3164".to_string(),
                        other => other.to_string(),
                    })
                }),
            );
            if let Some(f) = facility {
                let n = f
                    .parse::<u8>()
                    .ok()
                    .filter(|n| *n <= 23)
                    .or_else(|| aifw_common::syslog::facility_from_name(&f))
                    .ok_or_else(|| {
                        CliError::Usage(format!(
                            "unknown facility '{f}' (local0…local7, daemon, user, … or 0-23)"
                        ))
                    })?;
                set("facility", Some(json!(n)));
            }
            set(
                "hostname_override",
                // "" = use the system hostname (the field is a plain string).
                hostname.map(|h| json!(h)),
            );
            set("pf_enabled", pf.map(|v| json!(v)));
            set("ids_enabled", ids.map(|v| json!(v)));
            set("app_enabled", app.map(|v| json!(v)));
            set("app_min_level", app_min_level.map(|v| json!(v)));
            set("disable_local", disable_local.map(|v| json!(v)));
            if cfg == before {
                return Err(
                    CliError::Usage("nothing to change: pass at least one flag".into()).into(),
                );
            }
            let saved = client.put("/settings/syslog", &cfg).await?;
            print_syslog(ctx, &saved)
        }
        SyslogCmd::Test { host, port } => {
            let body = if host.is_some() || port.is_some() {
                let mut cfg = client.get("/settings/syslog").await?;
                if let Some(h) = host {
                    cfg["host"] = json!(h);
                }
                if let Some(p) = port {
                    cfg["port"] = json!(p);
                }
                cfg
            } else {
                // No body = test the saved configuration.
                Value::Null
            };
            let v = client.post("/settings/syslog/test", &body).await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io.println(v["message"].as_str().unwrap_or(""));
            }
            if v["ok"] == json!(false) {
                return Err(CliError::CheckFailed("test message was not delivered".into()).into());
            }
            Ok(())
        }
        SyslogCmd::Status => {
            let v = client.get("/settings/syslog/status").await?;
            ctx.raw(&v)
        }
    }
}

fn print_rotation(ctx: &mut Ctx, v: &Value) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        return ctx.raw(v);
    }
    let c = &v["config"];
    ctx.io.println(&format!(
        "Rotate at {} MB, keep {}, compression {} ({})",
        c["max_size_mb"],
        c["keep"],
        c["compression"].as_str().unwrap_or("?"),
        v["conf_path"].as_str().unwrap_or("?")
    ));
    let rows: Vec<Value> = crate::cli::output::rows(&json!({ "data": v["logs"] }))
        .into_iter()
        .map(|l| {
            let mut r = l.clone();
            r["_size"] = json!(l["size_bytes"].as_u64().map_or("-".into(), human_bytes));
            r["_total"] = json!(l["total_bytes"].as_u64().map_or("-".into(), human_bytes));
            r
        })
        .collect();
    let t = crate::cli::output::table(
        &rows.iter().collect::<Vec<_>>(),
        &[
            col("SERVICE", "/service"),
            col("SIZE", "/_size"),
            col("ROTATED", "/rotated"),
            col("TOTAL", "/_total"),
            col("PATH", "/path"),
        ],
        ctx.format(),
    );
    ctx.io.println(&t);
    Ok(())
}

pub async fn logrotate(ctx: &mut Ctx, cmd: LogrotateCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        LogrotateCmd::Show { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/settings/log-rotation").await?;
            print_rotation(ctx, &v)
        }
        LogrotateCmd::Set {
            max_size,
            keep,
            compression,
        } => {
            if max_size.is_none() && keep.is_none() && compression.is_none() {
                return Err(CliError::Usage(
                    "nothing to change: pass --max-size, --keep or --compression".into(),
                )
                .into());
            }
            let cur = client.get("/settings/log-rotation").await?;
            let mut cfg = cur["config"].clone();
            if let Some(m) = max_size {
                cfg["max_size_mb"] = json!(m);
            }
            if let Some(k) = keep {
                cfg["keep"] = json!(k);
            }
            if let Some(c) = compression {
                cfg["compression"] = json!(c.to_ascii_lowercase());
            }
            let v = client.put("/settings/log-rotation", &cfg).await?;
            print_rotation(ctx, &v)
        }
        LogrotateCmd::Rotate { path } => {
            let body = path.map_or_else(|| json!({}), |p| json!({ "path": p }));
            let v = client.post("/settings/log-rotation/rotate", &body).await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io.println(v["message"].as_str().unwrap_or(""));
            }
            if v["ok"] == json!(false) {
                return Err(CliError::CheckFailed("rotation failed".into()).into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn bytes() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
