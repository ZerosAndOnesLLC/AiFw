//! `aifw rules …` — firewall filter rules (via the API; changes are staged
//! until `aifw apply`, or pass --apply).

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum RulesCmd {
    /// List rules in evaluation order
    #[command(visible_alias = "ls")]
    List {
        /// Same as -o json (kept for scripts)
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Show one rule
    Show { id: String },
    /// Add a rule
    Add(AddArgs),
    /// Change fields of a rule (only the flags you pass)
    Edit(EditArgs),
    /// Delete a rule
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
        /// Apply to pf right away
        #[arg(long)]
        apply: bool,
    },
    /// Enable a disabled rule
    Enable {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Disable a rule without deleting it
    Disable {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Set the evaluation order: rule ids, first evaluated first
    Reorder {
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Show the rules pf has actually loaded
    System,
    /// Turn logging of all block rules on or off
    BlockLogging {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

/// Fields shared by add and edit.
#[derive(Debug, Args)]
pub struct RuleFields {
    /// pass, block, block-drop, block-return
    #[arg(long)]
    pub action: Option<String>,
    /// in, out, any
    #[arg(long)]
    pub direction: Option<String>,
    /// tcp, udp, tcp/udp, icmp, icmp6, any
    #[arg(long)]
    pub proto: Option<String>,
    /// Source: any, an address, a CIDR, or <table>
    #[arg(long)]
    pub src: Option<String>,
    /// Source port or range (443, 8000:8080)
    #[arg(long)]
    pub src_port: Option<String>,
    /// Destination: any, an address, a CIDR, or <table>
    #[arg(long)]
    pub dst: Option<String>,
    /// Destination port or range
    #[arg(long)]
    pub dst_port: Option<String>,
    /// Interface (e.g. em0)
    #[arg(long)]
    pub interface: Option<String>,
    /// inet, inet6, both
    #[arg(long)]
    pub ip_version: Option<String>,
    /// Lower is evaluated first
    #[arg(long)]
    pub priority: Option<i32>,
    /// Log matches
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub log: Option<bool>,
    /// Stop evaluating on match (pf quick)
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub quick: Option<bool>,
    /// pf label
    #[arg(long)]
    pub label: Option<String>,
    /// none, keep_state, modulate_state, synproxy_state
    #[arg(long)]
    pub state: Option<String>,
    /// Schedule id
    #[arg(long)]
    pub schedule: Option<String>,
    /// Multi-WAN gateway id for policy routing ("" clears)
    #[arg(long)]
    pub gateway: Option<String>,
    /// Read the rule (JSON/YAML, API request shape) from a file, or - for stdin
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,
    /// Apply to pf right away
    #[arg(long)]
    pub apply: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub f: RuleFields,
    /// Create it disabled
    #[arg(long)]
    pub disabled: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    pub id: String,
    #[command(flatten)]
    pub f: RuleFields,
}

/// Map CLI vocabulary onto what the API accepts.
fn action_value(s: &str) -> Result<&'static str, CliError> {
    Ok(match s {
        "pass" => "pass",
        "block" => "block",
        "block-drop" | "block_drop" | "blockdrop" => "block_drop",
        "block-return" | "block_return" | "blockreturn" => "block_return",
        _ => {
            return Err(CliError::Usage(format!(
                "unknown action '{s}' (pass, block, block-drop, block-return)"
            )));
        }
    })
}

impl RuleFields {
    fn to_fields(&self) -> anyhow::Result<Fields> {
        let mut f = Fields::new()
            .opt(
                "action",
                self.action.as_deref().map(action_value).transpose()?,
            )
            .opt("direction", self.direction.clone())
            .opt("protocol", self.proto.clone())
            .opt("src_addr", self.src.clone())
            .opt("dst_addr", self.dst.clone())
            .opt("interface", self.interface.clone())
            .opt("ip_version", self.ip_version.clone())
            .opt("priority", self.priority)
            .opt("log", self.log)
            .opt("quick", self.quick)
            .opt("label", self.label.clone())
            .opt("state_tracking", self.state.clone())
            .opt("schedule_id", self.schedule.clone())
            .opt("gateway", self.gateway.clone());
        if let Some(p) = &self.src_port {
            let (a, b) = body::port_range(p)?;
            f = f.set("src_port_start", a).set("src_port_end", b);
        }
        if let Some(p) = &self.dst_port {
            let (a, b) = body::port_range(p)?;
            f = f.set("dst_port_start", a).set("dst_port_end", b);
        }
        Ok(f)
    }
}

/// A rule as the API returns it → the request shape `PUT /rules/{id}`
/// expects. The update replaces optional fields wholesale, so everything
/// the rule has must be carried over.
pub fn to_request(rule: &Value) -> Value {
    let action = match rule["action"].as_str().unwrap_or("pass") {
        "blockdrop" => "block_drop",
        "blockreturn" => "block_return",
        other => other,
    };
    let m = &rule["rule_match"];
    let port = |p: &Value, k: &str| p.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "action": action,
        "direction": rule["direction"],
        "protocol": rule["protocol"],
        "ip_version": rule["ip_version"],
        "src_addr": m["src_addr"],
        "src_port_start": port(&m["src_port"], "start"),
        "src_port_end": port(&m["src_port"], "end"),
        "dst_addr": m["dst_addr"],
        "dst_port_start": port(&m["dst_port"], "start"),
        "dst_port_end": port(&m["dst_port"], "end"),
        "interface": rule["interface"],
        "priority": rule["priority"],
        "log": rule["log"],
        "quick": rule["quick"],
        "label": rule["label"],
        "state_tracking": rule["state_options"]["tracking"],
        "status": rule["status"],
        "schedule_id": rule["schedule_id"],
        "gateway": rule["gateway"],
    })
}

/// `addr[:port]` for a table cell.
fn endpoint(addr: &Value, port: &Value) -> String {
    let a = addr.as_str().unwrap_or("any");
    match (
        port.get("start").and_then(Value::as_u64),
        port.get("end").and_then(Value::as_u64),
    ) {
        (Some(s), Some(e)) if s == e => format!("{a}:{s}"),
        (Some(s), Some(e)) => format!("{a}:{s}-{e}"),
        _ => a.to_string(),
    }
}

fn table_row(r: &Value) -> Value {
    let m = &r["rule_match"];
    let mut row = r.clone();
    row["_src"] = json!(endpoint(&m["src_addr"], &m["src_port"]));
    row["_dst"] = json!(endpoint(&m["dst_addr"], &m["dst_port"]));
    row
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("PRI", "/priority"),
    col("ACTION", "/action"),
    col("DIR", "/direction"),
    col("PROTO", "/protocol"),
    col("SOURCE", "/_src"),
    col("DESTINATION", "/_dst"),
    col("IFACE", "/interface"),
    col("STATUS", "/status"),
    col("LABEL", "/label"),
    wide("LOG", "/log"),
    wide("QUICK", "/quick"),
    wide("IPV", "/ip_version"),
    wide("GATEWAY", "/gateway"),
];

const DETAIL: &[(&str, &str)] = &[
    ("ID", "/id"),
    ("Priority", "/priority"),
    ("Action", "/action"),
    ("Direction", "/direction"),
    ("Protocol", "/protocol"),
    ("IP version", "/ip_version"),
    ("Interface", "/interface"),
    ("Source", "/rule_match/src_addr"),
    ("Source port", "/rule_match/src_port"),
    ("Destination", "/rule_match/dst_addr"),
    ("Dest port", "/rule_match/dst_port"),
    ("Log", "/log"),
    ("Quick", "/quick"),
    ("State", "/state_options/tracking"),
    ("Label", "/label"),
    ("Schedule", "/schedule_id"),
    ("Gateway", "/gateway"),
    ("Status", "/status"),
];

async fn set_status(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    id: &str,
    status: &str,
    apply: bool,
) -> anyhow::Result<()> {
    let current = client.get(&format!("/rules/{id}")).await?;
    let mut body = to_request(crate::cli::output::item(&current));
    body["status"] = json!(status);
    let v = client.put(&format!("/rules/{id}"), &body).await?;
    let verb = if status == "active" {
        "Enabled"
    } else {
        "Disabled"
    };
    ctx.message(&v, &format!("{verb} rule {id}"))?;
    after_write(ctx, apply).await
}

/// After a successful write: apply now, or remind that it's staged.
pub async fn after_write(ctx: &mut Ctx, apply: bool) -> anyhow::Result<()> {
    if apply {
        super::staging::apply(ctx).await
    } else {
        if !ctx.format().is_structured() {
            ctx.io
                .eprintln("Staged — run `aifw apply` to load it into pf.");
        }
        Ok(())
    }
}

pub async fn run(ctx: &mut Ctx, cmd: RulesCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        RulesCmd::List { json } => {
            let v = client.get("/rules").await?;
            if json {
                return ctx.legacy_json(&v, None);
            }
            ctx.list_mapped(&v, COLS, table_row)
        }
        RulesCmd::Show { id } => {
            let v = client.get(&format!("/rules/{id}")).await?;
            ctx.detail(&v, DETAIL)
        }
        RulesCmd::Add(a) => {
            let mut fields = a.f.to_fields()?;
            if a.disabled {
                fields = fields.set("status", "disabled");
            }
            let mut body = body::for_create(&mut ctx.io, a.f.file.as_deref(), fields)?;
            if body.get("action").is_none_or(Value::is_null) {
                return Err(CliError::Usage(
                    "--action is required (pass, block, block-drop, block-return)".into(),
                )
                .into());
            }
            // Same defaults as the CLI has always had.
            for (k, d) in [
                ("direction", json!("any")),
                ("protocol", json!("any")),
                ("priority", json!(100)),
            ] {
                if body.get(k).is_none_or(Value::is_null) {
                    body[k] = d;
                }
            }
            let v = client.post("/rules", &body).await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io.println(&format!(
                    "Added rule {}",
                    v["data"]["id"].as_str().unwrap_or("?")
                ));
            }
            after_write(ctx, a.f.apply).await
        }
        RulesCmd::Edit(a) => {
            let current = client.get(&format!("/rules/{}", a.id)).await?;
            let body = body::for_update(
                &mut ctx.io,
                to_request(crate::cli::output::item(&current)),
                a.f.file.as_deref(),
                a.f.to_fields()?,
            )?;
            let v = client.put(&format!("/rules/{}", a.id), &body).await?;
            ctx.message(&v, &format!("Updated rule {}", a.id))?;
            after_write(ctx, a.f.apply).await
        }
        RulesCmd::Remove { id, yes, apply } => {
            ctx.confirm(&format!("Delete rule {id}?"), yes)?;
            let v = client.delete(&format!("/rules/{id}")).await?;
            ctx.message(&v, &format!("Removed rule {id}"))?;
            after_write(ctx, apply).await
        }
        RulesCmd::Enable { id, apply } => set_status(ctx, &client, &id, "active", apply).await,
        RulesCmd::Disable { id, apply } => set_status(ctx, &client, &id, "disabled", apply).await,
        RulesCmd::Reorder { ids, apply } => {
            let v = client
                .put("/rules/reorder", &json!({ "rule_ids": ids }))
                .await?;
            ctx.message(&v, "Rules reordered")?;
            after_write(ctx, apply).await
        }
        RulesCmd::System => {
            let v = client.get("/rules/system").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            for line in crate::cli::output::rows(&v) {
                ctx.io.println(line.as_str().unwrap_or_default());
            }
            Ok(())
        }
        RulesCmd::BlockLogging { state } => {
            let v = client
                .post("/rules/block-logging", &json!({ "enabled": state == "on" }))
                .await?;
            ctx.message(&v, &format!("Block-rule logging {state}"))
        }
    }
}
