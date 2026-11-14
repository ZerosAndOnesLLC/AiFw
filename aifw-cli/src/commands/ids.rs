//! `aifw ids …` — the intrusion detection engine via the API (config,
//! alerts, rulesets, rules, suppressions). Config and stats go through the
//! API to the aifw-ids service, so they need it running.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::Fields;
use crate::cli::exit::CliError;
use crate::cli::output::Col;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum IdsCmd {
    /// Delete every stored alert (and reclaim the space)
    #[command(after_help = "\
EXAMPLES:
    aifw ids purge-alerts            # asks for confirmation first
    aifw ids purge-alerts --yes      # non-interactive (scripts/cron)")]
    PurgeAlerts {
        #[arg(short, long)]
        yes: bool,
    },
    /// Show or set how many days alerts are kept (1-365)
    #[command(after_help = "\
EXAMPLES:
    aifw ids retention               # show the current setting
    aifw ids retention 7             # keep one week (the default)
    aifw ids retention 30            # keep one month")]
    Retention { days: Option<u32> },
    /// Engine configuration
    Config {
        /// ids (detect) or ips (block)
        #[arg(long)]
        mode: Option<String>,
        /// HOME_NET, comma-separated CIDRs
        #[arg(long)]
        home_net: Option<String>,
        /// Interfaces to inspect, comma-separated
        #[arg(long)]
        interfaces: Option<String>,
        #[arg(long)]
        worker_count: Option<u32>,
        #[arg(long)]
        eve_log: Option<bool>,
        #[arg(long)]
        syslog_target: Option<String>,
    },
    /// Alerts (newest first)
    #[command(subcommand)]
    Alerts(AlertsCmd),
    /// Engine counters
    Stats,
    /// Reload rules into the engine
    Reload,
    /// Rule sources
    #[command(subcommand)]
    Rulesets(RulesetsCmd),
    /// Individual rules
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Alert suppressions
    #[command(subcommand)]
    Suppressions(SuppressCmd),
}

#[derive(Debug, Subcommand)]
pub enum AlertsCmd {
    /// List alerts
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// 1 (high) … 4 (low)
        #[arg(long)]
        severity: Option<u8>,
        #[arg(long)]
        src_ip: Option<String>,
        #[arg(long)]
        sid: Option<u32>,
        /// Only unacknowledged
        #[arg(long)]
        unacked: bool,
    },
    /// Show one alert
    Show { id: String },
    /// Acknowledge an alert
    Ack { id: String },
    /// Classify an alert: unreviewed, confirmed, false_positive, investigating
    Classify { id: String, classification: String },
}

#[derive(Debug, Subcommand)]
pub enum RulesetsCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Add a rule source
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: Option<String>,
        /// suricata, sigma, yara
        #[arg(long, default_value = "suricata")]
        format: String,
        #[arg(long)]
        auto_update: Option<bool>,
        #[arg(long)]
        update_interval_hours: Option<u32>,
    },
    /// Enable a rule source
    Enable { id: String },
    /// Disable a rule source
    Disable { id: String },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RulesCmd {
    /// Search rules by text / SID
    Search { query: String },
    /// Show one rule
    Show { id: String },
    /// Enable a rule
    Enable { id: String },
    /// Disable a rule
    Disable { id: String },
}

#[derive(Debug, Subcommand)]
pub enum SuppressCmd {
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
    /// Suppress a signature (optionally only for one address/CIDR)
    Add {
        #[arg(long)]
        sid: u32,
        /// Match on src, dst or both addresses
        #[arg(long = "type", default_value = "both", value_parser = ["src", "dst", "both"])]
        suppress_type: String,
        /// Limit to this address or CIDR (omit for every address)
        #[arg(long)]
        ip: Option<String>,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

const ALERT_COLS: &[Col] = &[
    col("ID", "/id"),
    col("TIME", "/timestamp"),
    col("SEV", "/severity"),
    col("SID", "/signature_id"),
    col("SIGNATURE", "/signature_msg"),
    col("SOURCE", "/_src"),
    col("DESTINATION", "/_dst"),
    col("ACTION", "/action"),
    wide("PROTO", "/protocol"),
    wide("ACK", "/acknowledged"),
];

fn alert_row(a: &Value) -> Value {
    let ep = |ip: &Value, port: &Value| match port.as_u64() {
        Some(p) => format!("{}:{p}", ip.as_str().unwrap_or("?")),
        None => ip.as_str().unwrap_or("?").to_string(),
    };
    let mut r = a.clone();
    r["_src"] = json!(ep(&a["src_ip"], &a["src_port"]));
    r["_dst"] = json!(ep(&a["dst_ip"], &a["dst_port"]));
    r
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn run(ctx: &mut Ctx, cmd: IdsCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        IdsCmd::PurgeAlerts { yes } => {
            ctx.confirm("Delete ALL stored IDS alerts? This cannot be undone.", yes)?;
            let timeout = ctx.slow_timeout(std::time::Duration::from_secs(300));
            let v = client
                .request_with_timeout(reqwest::Method::DELETE, "/ids/alerts", None, timeout)
                .await?;
            ctx.message(&v, "Alerts purged")
        }
        IdsCmd::Retention { days } => match days {
            None => {
                let v = client.get("/ids/config").await?;
                let cfg = crate::cli::output::item(&v);
                if ctx.format().is_structured() {
                    return ctx
                        .raw(&json!({ "alert_retention_days": cfg["alert_retention_days"] }));
                }
                let line = match cfg["alert_retention_days"].as_u64() {
                    Some(d) => format!("IDS alert retention: {d} days"),
                    None => "IDS alert retention: 7 days (default)".into(),
                };
                ctx.io.println(&line);
                Ok(())
            }
            Some(d) => {
                if !(1..=365).contains(&d) {
                    return Err(
                        CliError::Usage("retention must be between 1 and 365 days".into()).into(),
                    );
                }
                let v = client
                    .put("/ids/config", &json!({ "alert_retention_days": d }))
                    .await?;
                ctx.message(&v, &format!("IDS alert retention set to {d} days"))
            }
        },
        IdsCmd::Config {
            mode,
            home_net,
            interfaces,
            worker_count,
            eve_log,
            syslog_target,
        } => {
            let patch = Fields::new()
                .opt("mode", mode)
                .opt("home_net", home_net.as_deref().map(csv))
                .opt("interfaces", interfaces.as_deref().map(csv))
                .opt("worker_count", worker_count)
                .opt("eve_log_enabled", eve_log)
                .opt("syslog_target", syslog_target);
            let v = if patch.is_empty() {
                client.get("/ids/config").await?
            } else {
                client.put("/ids/config", &patch.into_value()).await?
            };
            ctx.raw(crate::cli::output::item(&v))
        }
        IdsCmd::Alerts(a) => match a {
            AlertsCmd::List {
                limit,
                offset,
                severity,
                src_ip,
                sid,
                unacked,
            } => {
                let mut q = format!("/ids/alerts?limit={limit}&offset={offset}");
                if let Some(s) = severity {
                    q.push_str(&format!("&severity={s}"));
                }
                if let Some(ip) = src_ip {
                    q.push_str(&format!("&src_ip={ip}"));
                }
                if let Some(s) = sid {
                    q.push_str(&format!("&signature_id={s}"));
                }
                if unacked {
                    q.push_str("&acknowledged=false");
                }
                let v = client.get(&q).await?;
                ctx.list_mapped(&v, ALERT_COLS, alert_row)
            }
            AlertsCmd::Show { id } => {
                let v = client.get(&format!("/ids/alerts/{id}")).await?;
                ctx.raw(crate::cli::output::item(&v))
            }
            AlertsCmd::Ack { id } => {
                let v = client
                    .put(&format!("/ids/alerts/{id}/acknowledge"), &json!({}))
                    .await?;
                ctx.message(&v, &format!("Acknowledged alert {id}"))
            }
            AlertsCmd::Classify { id, classification } => {
                let v = client
                    .put(
                        &format!("/ids/alerts/{id}/classify"),
                        &json!({ "classification": classification }),
                    )
                    .await?;
                ctx.message(&v, &format!("Classified alert {id}"))
            }
        },
        IdsCmd::Stats => {
            let v = client.get("/ids/stats").await?;
            ctx.raw(crate::cli::output::item(&v))
        }
        IdsCmd::Reload => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/ids/reload",
                    None,
                    ctx.slow_timeout(std::time::Duration::from_secs(180)),
                )
                .await?;
            ctx.message(&v, "IDS rules reloaded")
        }
        IdsCmd::Rulesets(r) => match r {
            RulesetsCmd::List => {
                let v = client.get("/ids/rulesets").await?;
                ctx.list(
                    &v,
                    &[
                        col("ID", "/id"),
                        col("NAME", "/name"),
                        col("FORMAT", "/rule_format"),
                        col("ENABLED", "/enabled"),
                        col("AUTO-UPDATE", "/auto_update"),
                        col("RULES", "/rule_count"),
                        wide("URL", "/source_url"),
                        wide("UPDATED", "/last_updated"),
                    ],
                )
            }
            RulesetsCmd::Add {
                name,
                url,
                format,
                auto_update,
                update_interval_hours,
            } => {
                let body = Fields::new()
                    .set("name", name)
                    .opt("source_url", url)
                    .set("rule_format", format)
                    .opt("auto_update", auto_update)
                    .opt("update_interval_hours", update_interval_hours)
                    .into_value();
                let v = client.post("/ids/rulesets", &body).await?;
                ctx.message(&v, "Ruleset added")
            }
            RulesetsCmd::Enable { id } => {
                let v = client
                    .request_with_timeout(
                        reqwest::Method::PUT,
                        &format!("/ids/rulesets/{id}"),
                        Some(&json!({ "enabled": true })),
                        ctx.slow_timeout(std::time::Duration::from_secs(180)),
                    )
                    .await?;
                ctx.message(&v, &format!("Ruleset {id} enabled"))
            }
            RulesetsCmd::Disable { id } => {
                let v = client
                    .request_with_timeout(
                        reqwest::Method::PUT,
                        &format!("/ids/rulesets/{id}"),
                        Some(&json!({ "enabled": false })),
                        ctx.slow_timeout(std::time::Duration::from_secs(180)),
                    )
                    .await?;
                ctx.message(&v, &format!("Ruleset {id} disabled"))
            }
            RulesetsCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Delete ruleset {id}?"), yes)?;
                let v = client.delete(&format!("/ids/rulesets/{id}")).await?;
                ctx.message(&v, &format!("Removed ruleset {id}"))
            }
        },
        IdsCmd::Rules(r) => match r {
            RulesCmd::Search { query } => {
                let q: String = url::form_urlencoded::byte_serialize(query.as_bytes()).collect();
                let v = client.get(&format!("/ids/rules/search?q={q}")).await?;
                ctx.list(
                    &v,
                    &[
                        col("ID", "/id"),
                        col("SID", "/sid"),
                        col("MSG", "/msg"),
                        col("ENABLED", "/enabled"),
                        wide("RULESET", "/ruleset_id"),
                    ],
                )
            }
            RulesCmd::Show { id } => {
                let v = client.get(&format!("/ids/rules/{id}")).await?;
                ctx.raw(crate::cli::output::item(&v))
            }
            RulesCmd::Enable { id } => {
                let v = client
                    .put(&format!("/ids/rules/{id}"), &json!({ "enabled": true }))
                    .await?;
                ctx.message(&v, &format!("Rule {id} enabled"))
            }
            RulesCmd::Disable { id } => {
                let v = client
                    .put(&format!("/ids/rules/{id}"), &json!({ "enabled": false }))
                    .await?;
                ctx.message(&v, &format!("Rule {id} disabled"))
            }
        },
        IdsCmd::Suppressions(s) => match s {
            SuppressCmd::List { limit, offset } => {
                let v = client
                    .get(&format!("/ids/suppressions?limit={limit}&offset={offset}"))
                    .await?;
                ctx.list(
                    &v,
                    &[
                        col("ID", "/id"),
                        col("SID", "/sid"),
                        col("TYPE", "/suppress_type"),
                        col("IP", "/ip_cidr"),
                        wide("CREATED", "/created_at"),
                    ],
                )
            }
            SuppressCmd::Add {
                sid,
                suppress_type,
                ip,
            } => {
                let body = Fields::new()
                    .set("sid", sid)
                    .set("suppress_type", suppress_type)
                    .opt("ip_cidr", ip)
                    .into_value();
                let v = client.post("/ids/suppressions", &body).await?;
                ctx.message(&v, &format!("Suppressed SID {sid}"))
            }
            SuppressCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Delete suppression {id}?"), yes)?;
                let v = client.delete(&format!("/ids/suppressions/{id}")).await?;
                ctx.message(&v, &format!("Removed suppression {id}"))
            }
        },
    }
}
