//! Read-only operational views: `aifw connections`, `blocked`, `logs`,
//! `metrics`, `about`.

use clap::Subcommand;
use serde_json::json;

use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum MetricsCmd {
    /// Current counters
    Show,
    /// Names of the recorded time series
    List,
    /// One time series
    Series {
        name: String,
        /// How far back, in seconds
        #[arg(long, default_value_t = 1800)]
        range: u64,
        #[arg(long)]
        limit: Option<u32>,
    },
}

pub async fn connections(ctx: &mut Ctx, limit: u32, offset: u32) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client
        .get(&format!("/connections?limit={limit}&offset={offset}"))
        .await?;
    ctx.list_mapped(
        &v,
        &[
            col("PROTO", "/protocol"),
            col("SOURCE", "/_src"),
            col("DESTINATION", "/_dst"),
            col("STATE", "/state"),
            col("BYTES IN", "/bytes_in"),
            col("BYTES OUT", "/bytes_out"),
            col("AGE (s)", "/age_secs"),
            wide("IFACE", "/iface"),
            wide("FIB", "/rtable"),
        ],
        |s| {
            let mut r = s.clone();
            r["_src"] = json!(format!(
                "{}:{}",
                s["src_addr"].as_str().unwrap_or("?"),
                s["src_port"]
            ));
            r["_dst"] = json!(format!(
                "{}:{}",
                s["dst_addr"].as_str().unwrap_or("?"),
                s["dst_port"]
            ));
            r
        },
    )
}

pub async fn blocked(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/blocked").await?;
    ctx.list(
        &v,
        &[
            col("TIME", "/timestamp"),
            col("ACTION", "/action"),
            col("DIR", "/direction"),
            col("IFACE", "/interface"),
            col("PROTO", "/protocol"),
            col("SOURCE", "/src_addr"),
            col("SPORT", "/src_port"),
            col("DESTINATION", "/dst_addr"),
            col("DPORT", "/dst_port"),
            wide("REASON", "/reason"),
        ],
    )
}

/// Firewall audit log (rule changes, applies, daemon events).
pub async fn logs(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/logs").await?;
    ctx.list(
        &v,
        &[
            col("TIME", "/timestamp"),
            col("ACTION", "/action"),
            col("SOURCE", "/source"),
            col("DETAILS", "/details"),
            wide("RULE", "/rule_id"),
        ],
    )
}

pub async fn metrics(ctx: &mut Ctx, cmd: Option<MetricsCmd>) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd.unwrap_or(MetricsCmd::Show) {
        MetricsCmd::Show => ctx.raw(&client.get("/metrics").await?),
        MetricsCmd::List => {
            let v = client.get("/metrics/list").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            for n in v["names"].as_array().into_iter().flatten() {
                ctx.io.println(n.as_str().unwrap_or_default());
            }
            Ok(())
        }
        MetricsCmd::Series { name, range, limit } => {
            let mut path = format!("/metrics/series?name={name}&range_secs={range}");
            if let Some(l) = limit {
                path.push_str(&format!("&limit={l}"));
            }
            let v = client.get(&path).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.list(
                &json!({ "data": v["points"] }),
                &[
                    col("T", "/t"),
                    col("VALUE", "/v"),
                    col("MIN", "/min"),
                    col("MAX", "/max"),
                ],
            )
        }
    }
}

pub async fn about(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/about").await?;
    ctx.detail(
        &v,
        &[
            ("Version", "/version"),
            ("Commit", "/git_commit"),
            ("Built", "/built_at"),
            ("API RSS (MB)", "/memory/api_rss_mb"),
            ("Daemon RSS (MB)", "/memory/daemon_rss_mb"),
            ("pf states", "/memory/pf_states"),
            ("DB size (MB)", "/memory/db_size_mb"),
        ],
    )
}

/// One `top` frame from `/status` + `/metrics`.
fn top_frame(status: &serde_json::Value, metrics: &serde_json::Value) -> String {
    let n = |v: &serde_json::Value| crate::cli::output::cell(Some(v));
    format!(
        "AiFw — pf {} | states {} | rules {} (aifw {}/{} active) | nat {}\n\
         packets in {} out {} | bytes in {} out {}\n\
         api tasks {} | worker threads {}",
        if status["pf_running"] == json!(true) {
            "running"
        } else {
            "STOPPED"
        },
        n(&status["pf_states"]),
        n(&status["pf_rules"]),
        n(&status["aifw_active_rules"]),
        n(&status["aifw_rules"]),
        n(&status["nat_rules"]),
        n(&status["packets_in"]),
        n(&status["packets_out"]),
        n(&status["bytes_in"]),
        n(&status["bytes_out"]),
        n(&metrics["runtime"]["alive_tasks"]),
        n(&metrics["runtime"]["worker_threads"]),
    )
}

/// `aifw top`: refresh status and counters every `interval` seconds.
pub async fn top(ctx: &mut Ctx, interval: u64, once: bool) -> anyhow::Result<()> {
    let client = ctx.client()?;
    loop {
        let status = client.get("/status").await?;
        let metrics = client.get("/metrics").await?;
        if ctx.format().is_structured() {
            ctx.raw(&json!({ "status": status, "metrics": metrics }))?;
        } else {
            if ctx.io.tty && !once {
                // Clear screen + home, like top(1).
                ctx.io.eprint("\x1b[2J\x1b[H");
            }
            ctx.io.println(&top_frame(&status, &metrics));
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval.max(1))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_renders() {
        let f = top_frame(
            &json!({"pf_running": true, "pf_states": 12, "pf_rules": 3, "aifw_rules": 2, "aifw_active_rules": 2, "nat_rules": 1}),
            &json!({"runtime": {"alive_tasks": 40, "worker_threads": 4}}),
        );
        assert!(f.contains("pf running") && f.contains("states 12") && f.contains("api tasks 40"));
    }
}
