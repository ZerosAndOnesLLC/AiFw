//! Staged changes: `aifw pending`, `aifw apply`, `aifw confirm`.
//!
//! Writes through the API only stage changes (like the UI); `aifw apply`
//! loads them into pf. For risky remote changes, arm a commit-confirm
//! window *first*, make and apply the changes, then `aifw confirm accept`
//! — if you lose access and can't confirm, the appliance rolls back.

use std::time::Duration;

use clap::Subcommand;
use futures_util::StreamExt;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, parse};

#[derive(Debug, Subcommand)]
pub enum ConfirmCmd {
    /// Snapshot the current config and start the rollback timer
    Arm {
        /// How long you have to confirm (e.g. 300, 5m)
        #[arg(long, default_value = "5m")]
        timeout: String,
        /// What you're about to change
        #[arg(long, default_value = "CLI change")]
        description: String,
    },
    /// Show whether a window is open and how long is left
    Status,
    /// Keep the changes (cancel the rollback)
    Accept,
}

fn pending_names(v: &Value) -> Vec<String> {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter(|(_, v)| v.as_bool() == Some(true))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn print_pending(ctx: &mut Ctx, v: &Value) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        return ctx.raw(v);
    }
    let names = pending_names(v);
    if names.is_empty() {
        ctx.io.println("No unapplied changes.");
    } else {
        ctx.io.println(&format!(
            "Unapplied changes: {} (run `aifw apply`)",
            names.join(", ")
        ));
    }
    Ok(())
}

pub async fn pending(ctx: &mut Ctx, watch: bool) -> anyhow::Result<()> {
    let client = ctx.client()?;
    if !watch {
        let v = client.get("/pending").await?;
        return print_pending(ctx, &v);
    }
    // SSE: one `data: {json}` event on connect, then one per change.
    let resp = client.stream("/pending/stream").await?;
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("pending stream: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buf.find("\n\n") {
            let event: String = buf.drain(..end + 2).collect();
            for data in event.lines().filter_map(|l| l.strip_prefix("data:")) {
                if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                    print_pending(ctx, &v)?;
                }
            }
        }
    }
    Ok(())
}

pub async fn apply(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let timeout = ctx.slow_timeout(Duration::from_secs(120));
    let v = client
        .request_with_timeout(reqwest::Method::POST, "/reload", None, timeout)
        .await?;
    // The API answers 200 even when some steps failed; don't let a script
    // mistake that for success.
    if let Some(msg) = v["message"].as_str()
        && msg.starts_with("Partial reload")
    {
        return Err(anyhow::anyhow!("{msg}"));
    }
    ctx.message(&v, "Changes applied.")
}

pub async fn confirm(ctx: &mut Ctx, cmd: Option<ConfirmCmd>) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd.unwrap_or(ConfirmCmd::Accept) {
        ConfirmCmd::Arm {
            timeout,
            description,
        } => {
            let secs = parse::duration_secs(&timeout)?;
            let v = client
                .post(
                    "/config/commit-confirm",
                    &json!({ "timeout_secs": secs, "description": description }),
                )
                .await
                .map_err(|e| match e {
                    aifw_client::ClientError::Conflict(_) => anyhow::Error::new(CliError::Usage(
                        "a commit-confirm window is already open (`aifw confirm status`)".into(),
                    )),
                    other => other.into(),
                })?;
            ctx.message(&v, "Commit-confirm armed.")
        }
        ConfirmCmd::Status => {
            let v = client.get("/config/commit-confirm/status").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            if v["active"] == json!(true) {
                ctx.io.println(&format!(
                    "Commit-confirm open: {}s left to confirm \"{}\" (expires {}).",
                    v["seconds_remaining"],
                    v["description"].as_str().unwrap_or(""),
                    v["expires_at"].as_str().unwrap_or("?")
                ));
            } else {
                ctx.io.println("No commit-confirm window is open.");
            }
            Ok(())
        }
        ConfirmCmd::Accept => {
            let v = client.post_empty("/config/commit-confirm/confirm").await?;
            let msg = v["message"].as_str().unwrap_or_default();
            if msg.starts_with("No pending") {
                return Err(CliError::RolledBack(
                    "nothing to confirm — no window is open (it may have expired and rolled back)"
                        .into(),
                )
                .into());
            }
            ctx.message(&v, "Confirmed.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_flags() {
        assert!(pending_names(&json!({"firewall": false, "nat": false})).is_empty());
        assert_eq!(
            pending_names(&json!({"firewall": true, "nat": false, "dns": true})),
            vec!["dns", "firewall"]
        );
    }
}
