//! `aifw dns …` — upstream DNS servers, the resolver (config, host and
//! domain overrides, ACLs, service control) and blocklists, via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use super::resource::{Coll, Resource};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

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
    /// Start the resolver
    Start,
    /// Stop the resolver
    Stop,
    /// Restart the resolver
    Restart,
    /// Show or replace the full resolver config (JSON/YAML)
    Config {
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Host overrides (A/AAAA/CNAME/MX…)
    Hosts(Coll),
    /// Add a host override
    AddHost {
        /// Host part, e.g. nas
        hostname: String,
        /// Domain, e.g. home.arpa
        domain: String,
        /// Address or target
        value: String,
        /// A (default), AAAA, CNAME, MX, …
        #[arg(long = "type", default_value = "A")]
        record_type: String,
    },
    /// Domain overrides (forward a zone to a specific server)
    Domains(Coll),
    /// Who may query the resolver
    Acls(Coll),
    /// Recent resolver log lines
    Logs {
        #[arg(long, default_value_t = 100)]
        lines: u32,
        #[arg(short = 'F', long)]
        follow: bool,
    },
    /// Live resolver statistics
    Stats,
    /// Blocklists
    #[command(subcommand)]
    Blocklists(BlocklistCmd),
    /// Domains never blocked
    Whitelist(Coll),
    /// Extra domains to block
    Customblocks(Coll),
}

#[derive(Debug, Subcommand)]
pub enum BlocklistCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Add a source (JSON/YAML: name, category, url, format)
    Add {
        #[arg(short = 'f', long = "file")]
        file: String,
    },
    /// Change a source (only the fields in the file)
    Edit {
        id: String,
        #[arg(short = 'f', long = "file")]
        file: String,
    },
    Enable {
        id: String,
    },
    Disable {
        id: String,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Download one source now
    Refresh {
        id: String,
    },
    /// Download every enabled source now
    RefreshAll,
    /// Show or replace the refresh schedule (JSON/YAML)
    Schedule {
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Turn blocking on or off globally
    Blocking {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

/// Resolver service endpoints answer 200 with a report; a rollback or a
/// failure message means it didn't work.
fn resolver_report(ctx: &mut Ctx, v: &Value, fallback: &str) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        ctx.raw(v)?;
    } else {
        ctx.io.println(v["message"].as_str().unwrap_or(fallback));
    }
    let msg = v["message"].as_str().unwrap_or_default();
    if v["rolled_back"] == json!(true)
        || crate::cli::ctx::message_reports_failure(msg)
        || msg.starts_with("unknown backend")
    {
        return Err(CliError::CheckFailed(msg.to_string()).into());
    }
    Ok(())
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
            ctx.detail(
                &v,
                &[
                    ("Running", "/running"),
                    ("Backend", "/backend"),
                    ("Version", "/version"),
                    ("Listening UDP", "/listening_udp"),
                    ("Listening TCP", "/listening_tcp"),
                    ("Probe", "/probe_enabled"),
                    ("Queries", "/queries_total"),
                    ("Cache hits", "/cache_hits"),
                    ("Last switch", "/last_switch_at"),
                    ("Last result", "/last_switch_result"),
                ],
            )
        }
        DnsCmd::Apply => {
            let v = client.post_empty("/dns/resolver/apply").await?;
            resolver_report(ctx, &v, "Resolver config applied")
        }
        DnsCmd::Start => resolver_report(
            ctx,
            &client.post_empty("/dns/resolver/start").await?,
            "Resolver started",
        ),
        DnsCmd::Stop => resolver_report(
            ctx,
            &client.post_empty("/dns/resolver/stop").await?,
            "Resolver stopped",
        ),
        DnsCmd::Restart => resolver_report(
            ctx,
            &client.post_empty("/dns/resolver/restart").await?,
            "Resolver restarted",
        ),
        DnsCmd::Config { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/dns/resolver/config", &body).await?
                }
                None => client.get("/dns/resolver/config").await?,
            };
            ctx.raw(&v)
        }
        DnsCmd::Hosts(c) => {
            let r = Resource {
                path: "/dns/resolver/hosts".into(),
                what: "host override",
                cols: vec![
                    col("ID", "/id"),
                    col("HOST", "/hostname"),
                    col("DOMAIN", "/domain"),
                    col("TYPE", "/record_type"),
                    col("VALUE", "/value"),
                    col("ENABLED", "/enabled"),
                    wide("DESCRIPTION", "/description"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DnsCmd::AddHost {
            hostname,
            domain,
            value,
            record_type,
        } => {
            let v = client
                .post("/dns/resolver/hosts", &json!({ "hostname": hostname, "domain": domain, "value": value, "record_type": record_type.to_ascii_uppercase() }))
                .await?;
            ctx.message(&v, "Host override added — run `aifw dns apply`")
        }
        DnsCmd::Domains(c) => {
            let r = Resource {
                path: "/dns/resolver/domains".into(),
                what: "domain override",
                cols: vec![
                    col("ID", "/id"),
                    col("DOMAIN", "/domain"),
                    col("SERVER", "/server"),
                    col("ENABLED", "/enabled"),
                    wide("DESCRIPTION", "/description"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DnsCmd::Acls(c) => {
            let r = Resource {
                path: "/dns/resolver/acls".into(),
                what: "ACL entry",
                cols: vec![
                    col("ID", "/id"),
                    col("NETWORK", "/network"),
                    col("ACTION", "/action"),
                    wide("DESCRIPTION", "/description"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DnsCmd::Logs { lines, follow } => {
            super::logs::tail(
                ctx,
                &client,
                &format!("/dns/resolver/logs?lines={lines}"),
                follow,
            )
            .await
        }
        DnsCmd::Stats => ctx.raw(&client.get("/dns/stats").await?),
        DnsCmd::Whitelist(c) => {
            let r = Resource {
                path: "/dns/whitelist".into(),
                what: "whitelist entry",
                cols: vec![
                    col("ID", "/id"),
                    col("PATTERN", "/pattern"),
                    col("NOTE", "/note"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DnsCmd::Customblocks(c) => {
            let r = Resource {
                path: "/dns/customblocks".into(),
                what: "custom block",
                cols: vec![
                    col("ID", "/id"),
                    col("PATTERN", "/pattern"),
                    col("NOTE", "/note"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DnsCmd::Blocklists(b) => blocklists(ctx, &client, b).await,
    }
}

async fn blocklists(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    cmd: BlocklistCmd,
) -> anyhow::Result<()> {
    let refresh_timeout = ctx.slow_timeout(std::time::Duration::from_secs(600));
    match cmd {
        BlocklistCmd::List => {
            let v = client.get("/dns/blocklists").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("CATEGORY", "/category"),
                    col("FORMAT", "/format"),
                    col("ENABLED", "/enabled"),
                    col("RULES", "/rule_count"),
                    col("ACTION", "/action"),
                    wide("URL", "/url"),
                    wide("LAST ERROR", "/last_error"),
                ],
            )
        }
        BlocklistCmd::Add { file } => {
            let body = crate::cli::body::read(&mut ctx.io, &file)?;
            let v = client.post("/dns/blocklists", &body).await?;
            ctx.message(&v, "Blocklist added")
        }
        BlocklistCmd::Edit { id, file } => {
            // PUT here patches: only the given fields change.
            let body = crate::cli::body::read(&mut ctx.io, &file)?;
            let v = client.put(&format!("/dns/blocklists/{id}"), &body).await?;
            ctx.message(&v, "Blocklist updated")
        }
        BlocklistCmd::Enable { id } => {
            let v = client
                .put(
                    &format!("/dns/blocklists/{id}"),
                    &json!({ "enabled": true }),
                )
                .await?;
            ctx.message(&v, "Blocklist enabled")
        }
        BlocklistCmd::Disable { id } => {
            let v = client
                .put(
                    &format!("/dns/blocklists/{id}"),
                    &json!({ "enabled": false }),
                )
                .await?;
            ctx.message(&v, "Blocklist disabled")
        }
        BlocklistCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete blocklist {id}?"), yes)?;
            client.delete(&format!("/dns/blocklists/{id}")).await?;
            ctx.message(&Value::Null, "Blocklist deleted")
        }
        BlocklistCmd::Refresh { id } => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    &format!("/dns/blocklists/{id}/refresh"),
                    None,
                    refresh_timeout,
                )
                .await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io
                    .println(&format!("{} rules ({} bytes)", v["rule_count"], v["bytes"]));
            }
            if v["ok"] == json!(false) {
                return Err(CliError::CheckFailed(
                    v["error"].as_str().unwrap_or("refresh failed").to_string(),
                )
                .into());
            }
            Ok(())
        }
        BlocklistCmd::RefreshAll => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/dns/blocklists/refresh-all",
                    None,
                    refresh_timeout,
                )
                .await?;
            ctx.list(
                &v,
                &[
                    col("SOURCE", "/source_id"),
                    col("OK", "/ok"),
                    col("RULES", "/rule_count"),
                    col("ERROR", "/error"),
                ],
            )?;
            let failed = crate::cli::output::rows(&v)
                .iter()
                .filter(|o| o["ok"] == json!(false))
                .count();
            if failed > 0 {
                return Err(CliError::CheckFailed(format!(
                    "{failed} blocklist(s) failed to refresh"
                ))
                .into());
            }
            Ok(())
        }
        BlocklistCmd::Schedule { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/dns/blocklists/schedule", &body).await?
                }
                None => client.get("/dns/blocklists/schedule").await?,
            };
            ctx.raw(&v)
        }
        BlocklistCmd::Blocking { state } => {
            let v = client
                .put(
                    "/dns/blocklists/enabled",
                    &json!({ "enabled": state == "on" }),
                )
                .await?;
            ctx.message(&v, &format!("DNS blocking {state}"))
        }
    }
}
