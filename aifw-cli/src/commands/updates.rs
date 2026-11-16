//! `aifw update …` — AiFw and OS updates through the API.
//!
//! The maintenance cron runs `aifw update os-check && aifw update
//! os-install; aifw update check && aifw update install` as root with no
//! TTY, so: every prompt answers "no" on EOF (install then just reports
//! that a restart is pending), and success/failure is the exit code. If the
//! API itself is broken, `aifw local update …` runs the updater directly.

use std::path::PathBuf;
use std::time::Duration;

use aifw_client::{ClientError, Upload, UploadFile};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, prompt};

#[derive(Debug, Subcommand)]
pub enum UpdateCmd {
    /// Check for an AiFw firmware update
    Check {
        /// Include pre-releases (the channel is set with `aifw update prerelease on`)
        #[arg(long)]
        pre: bool,
    },
    /// Download and install the AiFw update (or a local tarball with --from)
    ///
    /// Does NOT restart services unless you confirm, or pass --restart.
    Install {
        /// Restart services right after installing
        #[arg(long)]
        restart: bool,
        /// Same as --restart (and skips the --from confirmation)
        #[arg(short = 'y', long)]
        yes: bool,
        /// Install from a local .tar.xz instead of the latest release
        #[arg(long, value_name = "PATH")]
        from: Option<PathBuf>,
        /// Skip the .sha256 sidecar check (only with --from)
        #[arg(long, requires = "from")]
        skip_checksum: bool,
        #[arg(long)]
        pre: bool,
    },
    /// Roll back to the previous AiFw version
    Rollback {
        #[arg(long)]
        restart: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Restart all AiFw services to activate an installed update
    Restart,
    /// Reboot (recommended after updates that change service supervision)
    Reboot {
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Check for OS and package updates
    OsCheck,
    /// Install OS and package updates
    OsInstall,
    /// Upgrade FreeBSD to a newer release (e.g. 15.1)
    OsUpgrade {
        /// Target release, e.g. "15.1"; omit to show progress of a running upgrade
        target: Option<String>,
        #[arg(short = 'y', long)]
        yes: bool,
        /// Return right after starting instead of following progress
        /// until it finishes or needs a reboot
        #[arg(long)]
        no_wait: bool,
    },
    /// Update status (versions, pending OS packages, reboot needed)
    Status,
    /// Past updates
    History,
    /// Toggle the pre-release channel
    Prerelease {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Show or change the automatic update schedule
    Schedule {
        /// Read the schedule (JSON/YAML) from a file, or - for stdin
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}

const INSTALL_TIMEOUT: Duration = Duration::from_secs(1800);

/// Turn "API unreachable" into a pointer at the local fallback.
fn local_hint(e: ClientError, cmd: &str) -> anyhow::Error {
    if matches!(e, ClientError::Unreachable { .. }) {
        let hint = format!(
            "the API is down; as root on the appliance, `aifw local update {cmd}` runs the updater directly"
        );
        return anyhow::Error::new(e).context(hint);
    }
    e.into()
}

fn print_check(ctx: &mut Ctx, info: &Value) {
    let s = |k: &str| info[k].as_str().unwrap_or("?").to_string();
    let mut out = vec![
        format!("  Current version: v{}", s("current_version")),
        format!("  Latest version:  v{}", s("latest_version")),
    ];
    if info["update_available"] == true {
        out.push("  Update available!".into());
        if info["os_upgrade_required"] == true {
            let os = info["required_os"].as_str().unwrap_or("newer");
            out.push(format!("  ⚠ Requires FreeBSD {os} — upgrade the OS first:"));
            out.push(format!("    aifw update os-upgrade {os}"));
        } else if info["tarball_url"].is_string() {
            out.push("  Run 'aifw update install' to update.".into());
        } else {
            out.push("  No update tarball found in the release.".into());
        }
    } else {
        out.push("  Already running the latest version.".into());
    }
    if let Some(b) = info["blocked_version"].as_str() {
        let os = info["blocked_requires_os"].as_str().unwrap_or("newer");
        out.push(format!(
            "  v{b} is also available and requires FreeBSD {os} —"
        ));
        out.push(format!("  it unlocks after: aifw update os-upgrade {os}"));
    }
    if info["has_backup"] == true {
        out.push(format!(
            "  Backup: v{} (run 'aifw update rollback' to restore)",
            info["backup_version"].as_str().unwrap_or("unknown")
        ));
    }
    if info["restart_pending"] == true {
        out.push("  An installed update is waiting: run 'aifw update restart'.".into());
    }
    ctx.io.println(&out.join("\n"));
}

/// `--pre` used to be per call; the API keeps the channel as a setting.
fn check_channel(info: &Value, pre: bool) -> Result<(), CliError> {
    if pre && info["include_prereleases"] != true {
        return Err(CliError::Usage(
            "the pre-release channel is off; turn it on with `aifw update prerelease on`".into(),
        ));
    }
    Ok(())
}

/// After install/rollback: restart now (flag or confirmed) or say how.
async fn maybe_restart(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    v: &Value,
    restart: bool,
) -> anyhow::Result<()> {
    if v["reboot_recommended"] == true {
        ctx.io.println(&format!(
            "  ⚠ Reboot recommended for this release: {}\n  Use 'aifw update reboot' instead of 'aifw update restart'.",
            v["reboot_reason"].as_str().unwrap_or("changes service-supervision tooling")
        ));
    }
    let no_input = ctx.g.no_input;
    let go = restart
        || (!no_input
            && prompt::confirm(
                &mut ctx.io,
                "Restart services now to activate?",
                false,
                false,
                "--restart",
            )?);
    if go {
        client.post_empty("/updates/aifw/restart").await?;
        ctx.io
            .println("Restarting services (the API comes back in a few seconds).");
    } else {
        ctx.io.println("Update installed. Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it.");
    }
    Ok(())
}

pub async fn run(ctx: &mut Ctx, cmd: UpdateCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        UpdateCmd::Check { pre } => {
            if !ctx.format().is_structured() {
                ctx.io.println("Checking for AiFw updates...");
            }
            let info = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/updates/aifw/check",
                    None,
                    ctx.slow_timeout(Duration::from_secs(120)),
                )
                .await
                .map_err(|e| local_hint(e, "check"))?;
            check_channel(&info, pre)?;
            if ctx.format().is_structured() {
                return ctx.raw(&info);
            }
            print_check(ctx, &info);
            Ok(())
        }
        UpdateCmd::Install {
            restart,
            yes,
            from: Some(path),
            skip_checksum,
            ..
        } => {
            let restart = restart || yes;
            if path.extension().is_none_or(|e| e != "xz") {
                return Err(CliError::Usage(format!(
                    "expected a .tar.xz file, got: {}",
                    path.display()
                ))
                .into());
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| CliError::Usage(format!("{}: {e}", path.display())))?;
            let size_mb = bytes.len() / (1024 * 1024);
            // --restart or --yes both mean "non-interactive", as before.
            if !restart {
                ctx.io.println(&format!(
                    "Install from local tarball: {} ({size_mb} MB)",
                    path.display()
                ));
                let no_input = ctx.g.no_input;
                if !prompt::confirm(&mut ctx.io, "Proceed?", false, no_input, "--yes")? {
                    ctx.io.println("Aborted.");
                    return Ok(());
                }
            }
            let mut fields = Vec::new();
            if !skip_checksum {
                let sha = path.with_file_name(format!(
                    "{}.sha256",
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                ));
                let text = std::fs::read_to_string(&sha).map_err(|_| {
                    CliError::Usage(format!(
                        "sha256 sidecar not found: {} — use --skip-checksum to bypass",
                        sha.display()
                    ))
                })?;
                fields.push(("sha256".to_string(), text));
            }
            if restart {
                fields.push(("restart".to_string(), "true".to_string()));
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("update.tar.xz")
                .to_string();
            ctx.io
                .println(&format!("Uploading {name} ({size_mb} MB)..."));
            let v = client
                .upload(
                    "/updates/aifw/install-local",
                    Upload {
                        files: vec![UploadFile {
                            field: "tarball".into(),
                            file_name: name,
                            bytes,
                        }],
                        fields,
                    },
                    ctx.slow_timeout(INSTALL_TIMEOUT),
                )
                .await
                .map_err(|e| local_hint(e, "install"))?;
            ctx.message(&v, "Install accepted")?;
            if !restart {
                ctx.io.println("Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it.");
            }
            Ok(())
        }
        UpdateCmd::Install {
            restart, yes, pre, ..
        } => {
            let timeout = ctx.slow_timeout(Duration::from_secs(120));
            let info = client
                .request_with_timeout(reqwest::Method::POST, "/updates/aifw/check", None, timeout)
                .await
                .map_err(|e| local_hint(e, "install"))?;
            check_channel(&info, pre)?;
            if info["update_available"] != true {
                ctx.io.println(&format!(
                    "Already running the latest version (v{}).",
                    info["current_version"].as_str().unwrap_or("?")
                ));
                return Ok(());
            }
            if info["os_upgrade_required"] == true {
                let os = info["required_os"].as_str().unwrap_or("newer");
                return Err(anyhow::anyhow!(
                    "AiFw v{} requires FreeBSD {os}. Upgrade the OS first: aifw update os-upgrade {os}",
                    info["latest_version"].as_str().unwrap_or("?")
                ));
            }
            ctx.io.println(&format!(
                "Updating AiFw from v{} to v{}...",
                info["current_version"].as_str().unwrap_or("?"),
                info["latest_version"].as_str().unwrap_or("?")
            ));
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/updates/aifw/install",
                    None,
                    ctx.slow_timeout(INSTALL_TIMEOUT),
                )
                .await?;
            if let Some(m) = v["message"].as_str() {
                ctx.io.println(m);
            }
            maybe_restart(ctx, &client, &v, restart || yes).await
        }
        UpdateCmd::Rollback { restart, yes } => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/updates/aifw/rollback",
                    None,
                    ctx.slow_timeout(INSTALL_TIMEOUT),
                )
                .await
                .map_err(|e| local_hint(e, "rollback"))?;
            if let Some(m) = v["message"].as_str() {
                ctx.io.println(m);
            }
            maybe_restart(ctx, &client, &v, restart || yes).await
        }
        UpdateCmd::Restart => {
            client
                .post_empty("/updates/aifw/restart")
                .await
                .map_err(|e| local_hint(e, "restart"))?;
            ctx.message(
                &Value::Null,
                "Restarting services (the API comes back in a few seconds).",
            )
        }
        UpdateCmd::Reboot { yes } => {
            ctx.confirm("Reboot the firewall in one minute?", yes)?;
            client
                .post_empty("/updates/aifw/reboot")
                .await
                .map_err(|e| local_hint(e, "reboot"))?;
            ctx.message(&Value::Null, "Reboot scheduled in one minute.")
        }
        UpdateCmd::OsCheck => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/updates/check",
                    None,
                    ctx.slow_timeout(Duration::from_secs(600)),
                )
                .await
                .map_err(|e| local_hint(e, "os-check"))?;
            ctx.service_message(&v, "OS update check finished")
        }
        UpdateCmd::OsInstall => {
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/updates/install",
                    None,
                    ctx.slow_timeout(INSTALL_TIMEOUT),
                )
                .await
                .map_err(|e| local_hint(e, "os-install"))?;
            ctx.service_message(&v, "OS updates installed")
        }
        UpdateCmd::OsUpgrade {
            target,
            yes,
            no_wait,
        } => {
            // Starting an upgrade follows it (as the pre-API command did);
            // with no target this just shows where a running one is.
            let wait = target.is_some() && !no_wait;
            if let Some(t) = target {
                ctx.confirm(
                    &format!(
                        "Upgrade FreeBSD to {t}? This installs a new kernel and needs a reboot."
                    ),
                    yes,
                )?;
                let v = client
                    .post("/updates/os/upgrade", &json!({ "target": t }))
                    .await?;
                ctx.message(&v, &format!("OS upgrade to {t} started"))?;
            }
            follow_os_upgrade(ctx, &client, wait).await
        }
        UpdateCmd::Status => {
            let v = client.get("/updates/status").await?;
            ctx.raw(&v)
        }
        UpdateCmd::History => {
            let v = client.get("/updates/history").await?;
            ctx.list(
                &v,
                &[
                    col("TIME", "/created_at"),
                    col("ACTION", "/action"),
                    col("RESULT", "/status"),
                    col("DETAILS", "/details"),
                ],
            )
        }
        UpdateCmd::Prerelease { state } => {
            let v = client
                .post(
                    "/updates/aifw/prerelease",
                    &json!({ "enabled": state == "on" }),
                )
                .await?;
            ctx.message(&v, &format!("Pre-release channel {state}"))
        }
        UpdateCmd::Schedule { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/updates/schedule", &body).await?
                }
                None => client.get("/updates/schedule").await?,
            };
            ctx.raw(&v)
        }
    }
}

/// Phases after which there is nothing more to wait for.
fn is_terminal_phase(p: &str) -> bool {
    matches!(p, "done" | "failed" | "reboot_required" | "idle")
}

async fn follow_os_upgrade(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    wait: bool,
) -> anyhow::Result<()> {
    let mut last = String::new();
    loop {
        let v = client.get("/updates/os/upgrade").await?;
        let phase = v["state"]["phase"].as_str().unwrap_or("idle").to_string();
        let line = format!(
            "OS {} → {}: {}{}",
            v["current_os"].as_str().unwrap_or("?"),
            v["state"]["target"].as_str().unwrap_or("-"),
            phase,
            v["state"]["detail"]
                .as_str()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default()
        );
        if ctx.format().is_structured() {
            if !wait || is_terminal_phase(&phase) {
                return ctx.raw(&v);
            }
        } else if line != last {
            ctx.io.println(&line);
            last = line;
        }
        if !wait || is_terminal_phase(&phase) {
            if phase == "failed" {
                return Err(CliError::CheckFailed("OS upgrade failed".into()).into());
            }
            if phase == "reboot_required" && !ctx.format().is_structured() {
                ctx.io.println("Reboot to continue: aifw update reboot");
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_check() {
        assert!(check_channel(&json!({"include_prereleases": false}), true).is_err());
        assert!(check_channel(&json!({"include_prereleases": true}), true).is_ok());
        assert!(check_channel(&json!({}), false).is_ok());
    }

    #[test]
    fn terminal_phases() {
        for p in ["done", "failed", "reboot_required", "idle"] {
            assert!(is_terminal_phase(p));
        }
        assert!(!is_terminal_phase("downloading"));
    }
}
