//! `aifw routes …` — static routes (via the API).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::{Ctx, Format, col, wide};

#[derive(Debug, Subcommand)]
pub enum RoutesCmd {
    /// Add a static route
    Add {
        /// Destination network, e.g. 10.20.0.0/16
        #[arg(long)]
        dest: String,
        /// Next-hop gateway
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long, default_value = "0")]
        metric: i32,
        /// Description
        #[arg(long)]
        desc: Option<String>,
        /// Routing table (multi-WAN FIB)
        #[arg(long)]
        fib: Option<u32>,
        /// Create it disabled
        #[arg(long)]
        disabled: bool,
    },
    /// Change a static route
    Edit {
        id: String,
        #[arg(long)]
        dest: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long)]
        metric: Option<i32>,
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        fib: Option<u32>,
    },
    /// Delete a static route
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Enable a static route
    Enable { id: String },
    /// Disable a static route
    Disable { id: String },
    /// List static routes
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Show the kernel routing table (IPv4)
    System {
        /// Routing table (FIB) to show
        #[arg(long)]
        fib: Option<u32>,
    },
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("DESTINATION", "/destination"),
    col("GATEWAY", "/gateway"),
    col("IFACE", "/interface"),
    col("METRIC", "/metric"),
    col("ENABLED", "/enabled"),
    col("DESCRIPTION", "/description"),
    wide("FIB", "/fib"),
];

fn to_request(r: &Value) -> Value {
    json!({
        "destination": r["destination"],
        "gateway": r["gateway"],
        "interface": r["interface"],
        "metric": r["metric"],
        "enabled": r["enabled"],
        "description": r["description"],
        "fib": r["fib"],
    })
}

async fn find(client: &aifw_client::Client, id: &str) -> anyhow::Result<Value> {
    let all = client.get("/routes").await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|r| r["id"] == json!(id))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("route {id}")).into())
}

pub async fn run(ctx: &mut Ctx, cmd: RoutesCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        RoutesCmd::List { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/routes").await?;
            ctx.list(&v, COLS)
        }
        RoutesCmd::Add {
            dest,
            gateway,
            interface,
            metric,
            desc,
            fib,
            disabled,
        } => {
            let body = Fields::new()
                .set("destination", dest)
                .set("gateway", gateway)
                .opt("interface", interface)
                .set("metric", metric)
                .opt("description", desc)
                .opt("fib", fib)
                .set("enabled", !disabled)
                .into_value();
            let v = client.post("/routes", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added route {}",
                crate::cli::output::item(&v)["id"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        RoutesCmd::Edit {
            id,
            dest,
            gateway,
            interface,
            metric,
            desc,
            fib,
        } => {
            let current = to_request(&find(&client, &id).await?);
            let flags = Fields::new()
                .opt("destination", dest)
                .opt("gateway", gateway)
                .opt("interface", interface)
                .opt("metric", metric)
                .opt("description", desc)
                .opt("fib", fib);
            let body = body::for_update(&mut ctx.io, current, None, flags)?;
            let v = client.put(&format!("/routes/{id}"), &body).await?;
            ctx.message(&v, &format!("Updated route {id}"))
        }
        RoutesCmd::Enable { id } => set_enabled(ctx, &client, &id, true).await,
        RoutesCmd::Disable { id } => set_enabled(ctx, &client, &id, false).await,
        RoutesCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete route {id}?"), yes)?;
            let v = client.delete(&format!("/routes/{id}")).await?;
            ctx.message(&v, &format!("Removed route {id}"))
        }
        RoutesCmd::System { fib } => {
            let path = match fib {
                Some(f) => format!("/routes/system?fib={f}"),
                None => "/routes/system".into(),
            };
            let v = client.get(&path).await?;
            ctx.list(
                &v,
                &[
                    col("DESTINATION", "/destination"),
                    col("GATEWAY", "/gateway"),
                    col("FLAGS", "/flags"),
                    col("IFACE", "/interface"),
                ],
            )
        }
    }
}

async fn set_enabled(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    id: &str,
    on: bool,
) -> anyhow::Result<()> {
    let mut body = to_request(&find(client, id).await?);
    body["enabled"] = json!(on);
    let v = client.put(&format!("/routes/{id}"), &body).await?;
    ctx.message(
        &v,
        &format!("Route {id} {}", if on { "enabled" } else { "disabled" }),
    )
}
