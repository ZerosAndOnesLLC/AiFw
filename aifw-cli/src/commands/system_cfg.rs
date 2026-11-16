//! `aifw system …` — hostname/timezone, banner, SSH, console, system info;
//! `aifw reboot` / `aifw shutdown`. The settings PUTs replace the whole
//! object, so edits send the current values merged with the flags.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::Ctx;
use crate::cli::body::Fields;
use crate::cli::exit::CliError;

#[derive(Debug, Subcommand)]
pub enum SystemCmd {
    /// Hardware, OS, load, memory, disk
    Info,
    /// Hostname, domain, timezone
    General {
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        timezone: Option<String>,
    },
    /// Login banner and message of the day
    Banner {
        #[arg(long)]
        login_banner: Option<String>,
        #[arg(long)]
        motd: Option<String>,
    },
    /// SSH server
    Ssh {
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        password_auth: Option<bool>,
        #[arg(long)]
        permit_root_login: Option<bool>,
    },
    /// Console (video, serial, dual)
    Console {
        #[arg(long)]
        kind: Option<String>,
        #[arg(long)]
        baud: Option<u32>,
    },
    /// Valid timezone names
    Timezones,
}

async fn section(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    name: &str,
    flags: Fields,
) -> anyhow::Result<()> {
    let path = format!("/system/{name}");
    let cur = client.get(&path).await?;
    if flags.is_empty() {
        return ctx.raw(&cur);
    }
    let mut body = cur;
    crate::cli::body::merge(&mut body, &flags.into_value());
    let r = client.put(&path, &body).await?;
    if ctx.format().is_structured() {
        ctx.raw(&r)?;
    } else {
        let mut line = format!("{name} settings applied");
        if r["requires_reboot"] == json!(true) {
            line.push_str(" — reboot required");
        }
        ctx.io.println(&line);
        if let Some(w) = r["warning"].as_str() {
            ctx.io.eprintln(&format!("warning: {w}"));
        }
    }
    if r["ok"] == json!(false) {
        return Err(CliError::CheckFailed(
            r["warning"].as_str().unwrap_or("apply failed").to_string(),
        )
        .into());
    }
    Ok(())
}

pub async fn run(ctx: &mut Ctx, cmd: SystemCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        SystemCmd::Info => {
            let v = client.get("/system/info").await?;
            let mut d = v.clone();
            let gib = |b: &Value| {
                b.as_f64()
                    .map(|x| format!("{:.1} GiB", x / 1_073_741_824.0))
            };
            d["_mem"] = json!(format!(
                "{} / {}",
                gib(&v["mem_used_bytes"]).unwrap_or_default(),
                gib(&v["mem_total_bytes"]).unwrap_or_default()
            ));
            d["_disk"] = json!(format!(
                "{} / {}",
                gib(&v["disk_used_bytes"]).unwrap_or_default(),
                gib(&v["disk_total_bytes"]).unwrap_or_default()
            ));
            ctx.detail(
                &d,
                &[
                    ("Hostname", "/hostname"),
                    ("OS", "/os_version"),
                    ("Kernel", "/kernel"),
                    ("Uptime (s)", "/uptime_secs"),
                    ("Load", "/load_avg"),
                    ("CPU", "/cpu_model"),
                    ("CPUs", "/cpu_count"),
                    ("CPU %", "/cpu_usage_pct"),
                    ("Memory", "/_mem"),
                    ("Disk", "/_disk"),
                ],
            )
        }
        SystemCmd::General {
            hostname,
            domain,
            timezone,
        } => {
            section(
                ctx,
                &client,
                "general",
                Fields::new()
                    .opt("hostname", hostname)
                    .opt("domain", domain)
                    .opt("timezone", timezone),
            )
            .await
        }
        SystemCmd::Banner { login_banner, motd } => {
            section(
                ctx,
                &client,
                "banner",
                Fields::new()
                    .opt("login_banner", login_banner)
                    .opt("motd", motd),
            )
            .await
        }
        SystemCmd::Ssh {
            enabled,
            port,
            password_auth,
            permit_root_login,
        } => {
            section(
                ctx,
                &client,
                "ssh",
                Fields::new()
                    .opt("enabled", enabled)
                    .opt("port", port)
                    .opt("password_auth", password_auth)
                    .opt("permit_root_login", permit_root_login),
            )
            .await
        }
        SystemCmd::Console { kind, baud } => {
            section(
                ctx,
                &client,
                "console",
                Fields::new().opt("kind", kind).opt("baud", baud),
            )
            .await
        }
        SystemCmd::Timezones => {
            let v = client.get("/system/timezones").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            for t in crate::cli::output::rows(&v) {
                ctx.io.println(t.as_str().unwrap_or_default());
            }
            Ok(())
        }
    }
}

/// `aifw reboot` / `aifw shutdown` (10 s delay).
pub async fn power(ctx: &mut Ctx, shutdown: bool, yes: bool) -> anyhow::Result<()> {
    let what = if shutdown { "Shut down" } else { "Reboot" };
    ctx.confirm(&format!("{what} the firewall in 10 seconds?"), yes)?;
    let client = ctx.client()?;
    let v = client
        .post_empty(if shutdown {
            "/updates/shutdown"
        } else {
            "/updates/reboot"
        })
        .await?;
    ctx.message(&v, &format!("{what} scheduled"))
}
