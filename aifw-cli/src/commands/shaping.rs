//! `aifw queue …` — traffic-shaping queues (via the API; queue writes are
//! applied to pf immediately by the API).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum QueueCmd {
    /// Add a queue
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        interface: String,
        /// Queue type: codel, hfsc, priq
        #[arg(long = "type", default_value = "codel", value_name = "TYPE")]
        queue_type: String,
        /// Bandwidth, e.g. 100Mb, 1Gb, 512Kb
        #[arg(long)]
        bandwidth: String,
        /// Traffic class: voip, interactive, default, bulk
        #[arg(long, default_value = "default")]
        class: String,
        /// Share of the parent bandwidth (percent)
        #[arg(long)]
        pct: Option<u8>,
        /// Make this the default queue
        #[arg(long)]
        default: bool,
    },
    /// Change a queue (only the flags you pass)
    Edit {
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        bandwidth: Option<String>,
        #[arg(long)]
        class: Option<String>,
        #[arg(long)]
        pct: Option<u8>,
        #[arg(long, num_args = 0..=1, default_missing_value = "true")]
        default: Option<bool>,
    },
    /// Delete a queue
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// List queues
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Enable a queue
    Enable { id: String },
    /// Disable a queue
    Disable { id: String },
    /// Re-apply all queues to pf
    Apply,
    /// Show whether shaping is configured and active
    Status,
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("IFACE", "/interface"),
    col("TYPE", "/queue_type"),
    col("BANDWIDTH", "/_bw"),
    col("CLASS", "/traffic_class"),
    col("PCT", "/bandwidth_pct"),
    col("DEFAULT", "/default"),
    col("STATUS", "/status"),
    wide("UPDATED", "/updated_at"),
];

fn table_row(q: &Value) -> Value {
    let mut r = q.clone();
    r["_bw"] = json!(format!(
        "{}{}",
        q["bandwidth"]["value"],
        q["bandwidth"]["unit"].as_str().unwrap_or("")
    ));
    r
}

/// Parse a CLI value into the wire form of an aifw-common enum/struct.
fn wire<T: serde::Serialize>(
    v: Result<T, aifw_common::AifwError>,
    what: &str,
) -> Result<Value, CliError> {
    v.map_err(|e| CliError::Usage(format!("invalid {what}: {e}")))
        .map(|t| serde_json::to_value(t).unwrap_or(Value::Null))
}

async fn find(client: &aifw_client::Client, id: &str) -> anyhow::Result<Value> {
    let all = client.get("/shaper/queues").await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|q| q["id"] == json!(id))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("queue {id}")).into())
}

pub async fn run(ctx: &mut Ctx, cmd: QueueCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        QueueCmd::List { json } => {
            let v = client.get("/shaper/queues").await?;
            if json {
                return ctx.legacy_json(&v, None);
            }
            ctx.list_mapped(&v, COLS, table_row)
        }
        QueueCmd::Add {
            name,
            interface,
            queue_type,
            bandwidth,
            class,
            pct,
            default,
        } => {
            use aifw_common::{Bandwidth, Interface, QueueConfig, QueueType, TrafficClass};
            let mut q = QueueConfig::new(
                Interface(interface),
                QueueType::parse(&queue_type)
                    .map_err(|e| CliError::Usage(format!("invalid --type: {e}")))?,
                Bandwidth::parse(&bandwidth)
                    .map_err(|e| CliError::Usage(format!("invalid --bandwidth: {e}")))?,
                name,
                TrafficClass::parse(&class)
                    .map_err(|e| CliError::Usage(format!("invalid --class: {e}")))?,
            );
            q.bandwidth_pct = pct;
            q.default = default;
            let v = client
                .post("/shaper/queues", &serde_json::to_value(&q)?)
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added queue {}",
                v["data"]["id"].as_str().unwrap_or("?")
            ));
            let pf = q.to_pf_queue();
            if !pf.trim().is_empty() {
                ctx.io.println(&format!("  pf: {pf}"));
            }
            Ok(())
        }
        QueueCmd::Edit {
            id,
            name,
            bandwidth,
            class,
            pct,
            default,
        } => {
            let mut q = find(&client, &id).await?;
            let before = q.clone();
            if let Some(n) = name {
                q["name"] = json!(n);
            }
            if let Some(b) = bandwidth {
                q["bandwidth"] = wire(aifw_common::Bandwidth::parse(&b), "--bandwidth")?;
            }
            if let Some(c) = class {
                q["traffic_class"] = wire(aifw_common::TrafficClass::parse(&c), "--class")?;
            }
            if let Some(p) = pct {
                q["bandwidth_pct"] = json!(p);
            }
            if let Some(d) = default {
                q["default"] = json!(d);
            }
            if q == before {
                return Err(CliError::Usage("nothing to change: pass a field flag".into()).into());
            }
            let v = client.put(&format!("/shaper/queues/{id}"), &q).await?;
            ctx.message(&v, &format!("Updated queue {id}"))
        }
        QueueCmd::Enable { id } => set_status(ctx, &client, &id, "active").await,
        QueueCmd::Disable { id } => set_status(ctx, &client, &id, "disabled").await,
        QueueCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete queue {id}?"), yes)?;
            let v = client.delete(&format!("/shaper/queues/{id}")).await?;
            ctx.message(&v, &format!("Removed queue {id}"))
        }
        QueueCmd::Apply => {
            let v = client.post_empty("/shaper/apply").await?;
            ctx.message(&v, "Queues applied")
        }
        QueueCmd::Status => {
            let v = client.get("/shaper/status").await?;
            ctx.detail(
                &v,
                &[
                    ("Configured", "/configured"),
                    ("Active", "/active"),
                    ("Backend", "/backend"),
                    ("Verified", "/verified"),
                ],
            )
        }
    }
}

async fn set_status(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    id: &str,
    status: &str,
) -> anyhow::Result<()> {
    let mut q = find(client, id).await?;
    q["status"] = json!(status);
    let v = client.put(&format!("/shaper/queues/{id}"), &q).await?;
    ctx.message(
        &v,
        &format!(
            "Queue {id} {}",
            if status == "active" {
                "enabled"
            } else {
                "disabled"
            }
        ),
    )
}
