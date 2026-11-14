//! `aifw ai …` — AI classification of IDS alerts.

use clap::Subcommand;
use serde_json::json;

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum AiCmd {
    /// Classify recent unclassified IDS alerts now
    Analyze,
    /// What the AI was asked and answered
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: AiCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        AiCmd::Analyze => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/ai/analyze",
                    None,
                    ctx.slow_timeout(std::time::Duration::from_secs(600)),
                )
                .await?;
            ctx.message(&v, "Analysis finished")?;
            if v.get("error").is_some_and(|e| !e.is_null()) {
                return Err(CliError::CheckFailed(
                    v["error"]
                        .as_str()
                        .unwrap_or("AI analysis failed")
                        .to_string(),
                )
                .into());
            }
            Ok(())
        }
        AiCmd::Audit { limit } => {
            let v = client.get(&format!("/ai/audit-log?limit={limit}")).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.list(
                &json!({ "data": v["entries"] }),
                &[
                    col("TIME", "/created_at"),
                    col("SIGNATURE", "/signature_msg"),
                    col("PROVIDER", "/provider"),
                    col("CLASSIFICATION", "/classification"),
                    wide("MODEL", "/model"),
                    wide("MS", "/duration_ms"),
                ],
            )
        }
    }
}
