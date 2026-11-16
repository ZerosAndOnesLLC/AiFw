//! `aifw multiwan …` — routing instances, gateways, groups, policies and
//! leaks via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum MultiwanCmd {
    /// List routing instances (FIBs)
    Instances,
    /// List gateways with live health state
    Gateways,
    /// List gateway groups
    Groups,
    /// List policy-routing rules
    Policies,
    /// List route leaks
    Leaks,
    /// Show live pf flows with iface/FIB
    Flows,
    /// Available FIBs and which are in use
    FibInfo,
    /// What a set of policy rules would change (blast radius), before
    /// applying it: -f takes the proposed policies (JSON/YAML list, API shape)
    Preview {
        #[arg(short = 'f', long = "file")]
        file: String,
    },
    /// Recompile and apply all multi-WAN pf anchors
    Apply,
    /// Seed management-escape leaks for non-default instances (then apply)
    SeedMgmt,
    /// Force a manual probe outcome for a gateway (for testing)
    Probe {
        /// Gateway UUID
        id: String,
        /// "ok" or "fail"
        #[arg(default_value = "ok")]
        outcome: String,
    },
    /// Export the full multi-WAN config as JSON
    Export,
    /// Import multi-WAN config from a JSON/YAML file (- for stdin)
    Import { file: String },
}

pub async fn run(ctx: &mut Ctx, cmd: MultiwanCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        MultiwanCmd::Instances => {
            let v = client.get("/multiwan/instances").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("FIB", "/fib_number"),
                    col("MGMT", "/mgmt_reachable"),
                    col("STATUS", "/status"),
                ],
            )
        }
        MultiwanCmd::Gateways => {
            let v = client.get("/multiwan/gateways").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("STATE", "/state"),
                    col("NEXT HOP", "/next_hop"),
                    col("IFACE", "/interface"),
                    col("RTT (ms)", "/last_rtt_ms"),
                    wide("MOS", "/last_mos"),
                    wide("INSTANCE", "/instance_id"),
                ],
            )
        }
        MultiwanCmd::Groups => {
            let v = client.get("/multiwan/groups").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("POLICY", "/policy"),
                    col("PREEMPT", "/preempt"),
                    col("STICKY", "/sticky"),
                ],
            )
        }
        MultiwanCmd::Policies => {
            let v = client.get("/multiwan/policies").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("PRI", "/priority"),
                    col("NAME", "/name"),
                    col("STATUS", "/status"),
                    col("ACTION", "/action_kind"),
                    col("SOURCE", "/src_addr"),
                    col("DESTINATION", "/dst_addr"),
                    wide("DST PORT", "/dst_port"),
                ],
            )
        }
        MultiwanCmd::Leaks => {
            let v = client.get("/multiwan/leaks").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("PREFIX", "/prefix"),
                    col("DIRECTION", "/direction"),
                    col("ENABLED", "/enabled"),
                ],
            )
        }
        MultiwanCmd::Flows => {
            let v = client.get("/multiwan/flows").await?;
            ctx.list(
                &v,
                &[
                    col("PROTO", "/protocol"),
                    col("SOURCE", "/src"),
                    col("DESTINATION", "/dst"),
                    col("IFACE", "/iface"),
                    col("FIB", "/rtable"),
                    col("BYTES", "/bytes"),
                    col("AGE (s)", "/age_secs"),
                ],
            )
        }
        MultiwanCmd::FibInfo => {
            let v = client.get("/multiwan/fibs").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let d = crate::cli::output::item(&v);
            ctx.io.println(&format!(
                "Available FIBs: {}  in use: {}",
                d["net_fibs"],
                crate::cli::output::cell(d.get("used"))
            ));
            Ok(())
        }
        MultiwanCmd::Preview { file } => {
            let proposed = crate::cli::body::read(&mut ctx.io, &file)?;
            // Accept a bare list, `{policies: [...]}`, or an export.
            let policies = match proposed {
                Value::Array(_) => proposed,
                other => crate::cli::output::item(&other)["policies"].clone(),
            };
            if !policies.is_array() {
                return Err(
                    CliError::Usage(format!("{file}: expected a list of policy rules")).into(),
                );
            }
            ctx.raw(
                &client
                    .post("/multiwan/preview", &json!({ "policies": policies }))
                    .await?,
            )
        }
        MultiwanCmd::Apply => {
            let v = client.post_empty("/multiwan/apply").await?;
            ctx.message(&v, "Multi-WAN anchors applied")
        }
        MultiwanCmd::SeedMgmt => {
            let v = client.post_empty("/multiwan/leaks/seed-mgmt").await?;
            ctx.message(&v, "Management leaks seeded")?;
            let a = client.post_empty("/multiwan/apply").await?;
            ctx.message(&a, "Multi-WAN anchors applied")
        }
        MultiwanCmd::Probe { id, outcome } => {
            let ok = matches!(outcome.as_str(), "ok" | "success" | "up");
            let body = if ok {
                json!({ "success": true, "rtt_ms": 10.0 })
            } else {
                json!({ "success": false, "error": "cli-fail" })
            };
            let v = client
                .post(&format!("/multiwan/gateways/{id}/probe-now"), &body)
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Gateway {id}: injected {} sample; state now {}",
                if ok { "ok" } else { "failed" },
                crate::cli::output::item(&v)["state"]
                    .as_str()
                    .unwrap_or("?")
            ));
            Ok(())
        }
        MultiwanCmd::Export => {
            let v = client.get("/multiwan/config.yaml").await?;
            ctx.raw(crate::cli::output::item(&v))
        }
        MultiwanCmd::Import { file } => {
            let mut cfg = crate::cli::body::read(&mut ctx.io, &file)?;
            let cfg_inner = crate::cli::output::item(&cfg).clone();
            cfg = cfg_inner;
            let obj = cfg.as_object_mut().ok_or_else(|| {
                CliError::Usage(format!(
                    "{file}: expected an object with instances/gateways/groups/policies/leaks"
                ))
            })?;
            // The API wants all five sections; a missing one means "nothing to import".
            for k in ["instances", "gateways", "groups", "policies", "leaks"] {
                obj.entry(k).or_insert_with(|| Value::Array(vec![]));
            }
            let v = client.post("/multiwan/apply-yaml", &cfg).await?;
            ctx.message(&v, "Multi-WAN config imported")
        }
    }
}
