//! `aifw time …` — the rTime NTP/PTP service via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use super::resource::{Coll, Resource};
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum TimeCmd {
    /// Service status
    Status,
    /// Show or replace the full service config (JSON/YAML)
    Config {
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Upstream time sources
    Sources(Coll),
    /// Add an upstream NTP server
    AddSource {
        address: String,
        /// Use NTS (authenticated NTP)
        #[arg(long)]
        nts: bool,
    },
    Start,
    Stop,
    Restart,
    /// Write the config and restart the service
    Apply,
    /// Recent log lines
    Logs {
        #[arg(long, default_value_t = 100)]
        lines: u32,
        #[arg(short = 'F', long)]
        follow: bool,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: TimeCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        TimeCmd::Status => {
            let v = client.get("/time/status").await?;
            ctx.detail(
                &v,
                &[
                    ("Running", "/running"),
                    ("Version", "/version"),
                    ("Sources", "/sources_count"),
                ],
            )
        }
        TimeCmd::Config { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/time/config", &body).await?
                }
                None => client.get("/time/config").await?,
            };
            ctx.raw(&v)
        }
        TimeCmd::Sources(c) => {
            let r = Resource {
                path: "/time/sources".into(),
                what: "time source",
                cols: vec![
                    col("ID", "/id"),
                    col("ADDRESS", "/address"),
                    col("NTS", "/nts"),
                    col("ENABLED", "/enabled"),
                    wide("MIN POLL", "/min_poll"),
                    wide("MAX POLL", "/max_poll"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        TimeCmd::AddSource { address, nts } => {
            let v = client
                .post("/time/sources", &json!({ "address": address, "nts": nts }))
                .await?;
            ctx.message(&v, "Source added — run `aifw time apply`")
        }
        TimeCmd::Start => service(ctx, &client, "start").await,
        TimeCmd::Stop => service(ctx, &client, "stop").await,
        TimeCmd::Restart => service(ctx, &client, "restart").await,
        TimeCmd::Apply => service(ctx, &client, "apply").await,
        TimeCmd::Logs { lines, follow } => {
            super::logs::tail(ctx, &client, &format!("/time/logs?lines={lines}"), follow).await
        }
    }
}

async fn service(ctx: &mut Ctx, client: &aifw_client::Client, action: &str) -> anyhow::Result<()> {
    let v: Value = client.post_empty(&format!("/time/{action}")).await?;
    ctx.service_message(&v, &format!("Time service {action} done"))
}
