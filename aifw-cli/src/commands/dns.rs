//! `aifw dns …` — upstream DNS servers the resolver forwards to, and the
//! resolver's backend probe (via the API).

use clap::Subcommand;
use serde_json::json;

use crate::cli::Ctx;
use crate::cli::exit::CliError;

#[derive(Debug, Subcommand)]
pub enum DnsCmd {
    /// List upstream DNS servers
    #[command(visible_alias = "ls")]
    List,
    /// Replace the upstream DNS servers (comma-separated)
    Set { servers: String },
    /// Resolver health probe (switches backends when the active one fails)
    Probe {
        #[arg(value_parser = ["on", "off", "status"])]
        state: String,
    },
    /// Resolver status (backend, listeners, last switch)
    Status,
    /// Write the resolver config and reload it
    Apply,
}

pub async fn run(ctx: &mut Ctx, cmd: DnsCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        DnsCmd::List => {
            let v = client.get("/dns").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let servers = crate::cli::output::rows(&v);
            if servers.is_empty() {
                ctx.io.eprintln("No upstream DNS servers configured.");
            }
            for s in servers {
                ctx.io.println(s.as_str().unwrap_or_default());
            }
            Ok(())
        }
        DnsCmd::Set { servers } => {
            let list: Vec<String> = servers
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            if list.is_empty() {
                return Err(CliError::Usage(
                    "give at least one server, e.g. 1.1.1.1,9.9.9.9".into(),
                )
                .into());
            }
            let v = client.put("/dns", &json!({ "servers": list })).await?;
            ctx.message(&v, "DNS servers updated")?;
            if !ctx.format().is_structured() {
                ctx.io
                    .eprintln("Run `aifw dns apply` to reload the resolver.");
            }
            Ok(())
        }
        DnsCmd::Probe { state } => {
            let mut cfg = client.get("/dns/resolver/config").await?;
            let cfg_obj = crate::cli::output::item(&cfg).clone();
            cfg = cfg_obj;
            if state == "status" {
                let on = cfg["probe_enabled"].as_bool().unwrap_or(true);
                if ctx.format().is_structured() {
                    return ctx.raw(&json!({ "probe_enabled": on }));
                }
                ctx.io.println(&format!(
                    "Resolver probe: {}",
                    if on { "on" } else { "off" }
                ));
                return Ok(());
            }
            cfg["probe_enabled"] = json!(state == "on");
            let v = client.put("/dns/resolver/config", &cfg).await?;
            ctx.message(&v, &format!("Resolver probe {state}"))?;
            if !ctx.format().is_structured() {
                ctx.io
                    .eprintln("Takes effect on the next `aifw dns apply` (or resolver restart).");
            }
            Ok(())
        }
        DnsCmd::Status => {
            let v = client.get("/dns/resolver/status").await?;
            ctx.raw(&v)
        }
        DnsCmd::Apply => {
            let v = client.post_empty("/dns/resolver/apply").await?;
            ctx.message(&v, "Resolver config applied")
        }
    }
}
