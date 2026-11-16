//! `aifw config …` — versioned configuration, export/import (incl.
//! OPNsense), restore and retention via the API.
//!
//! Import and restore are applied to pf by the API immediately (with
//! rollback on failure), so both ask first. Exporting secrets in the clear
//! is deliberately not offered by the API; `aifw local config-export
//! --secrets plain` does it as root on the box.

use std::path::PathBuf;
use std::time::Duration;

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Show the active configuration (secrets redacted)
    Show,
    /// Export the configuration
    Export {
        /// redact (default) or passphrase (secrets wrapped under a passphrase)
        #[arg(long, default_value = "redact", value_parser = ["redact", "passphrase", "plain"])]
        secrets: String,
        /// File whose first line is the passphrase (else $AIFW_BACKUP_PASSPHRASE)
        #[arg(long)]
        passphrase_file: Option<String>,
        /// Write to a file (mode 0600) instead of stdout
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    /// Import a configuration export (applies it immediately)
    Import {
        file: String,
        /// Passphrase for a passphrase-wrapped export (file, first line)
        #[arg(long)]
        passphrase_file: Option<String>,
        /// Only show what would change
        #[arg(long)]
        preview: bool,
        #[arg(short, long)]
        yes: bool,
    },
    /// Import an OPNsense config.xml (applies it; arms commit-confirm)
    ImportOpnsense {
        file: String,
        /// Only show the plan
        #[arg(long)]
        preview: bool,
        /// Interface mapping, e.g. --map lan=em1 (repeatable)
        #[arg(long = "map", value_name = "OPN=IFACE")]
        map: Vec<String>,
        /// Also take hostname/domain/DNS upstreams from the file
        #[arg(long)]
        system_settings: bool,
        /// Don't arm the commit-confirm auto-revert
        #[arg(long)]
        no_commit_confirm: bool,
        #[arg(short, long)]
        yes: bool,
    },
    /// Saved configuration versions
    History {
        #[arg(long, default_value = "20")]
        limit: i64,
    },
    /// Save the current configuration as a new version
    Save {
        #[arg(long)]
        comment: Option<String>,
    },
    /// Restore (and apply) a saved version
    #[command(visible_alias = "restore")]
    Rollback {
        version: i64,
        #[arg(short, long)]
        yes: bool,
    },
    /// Compare two versions
    Diff { v1: i64, v2: i64 },
    /// Validate the current configuration
    Check,
    /// Show or set how many versions are kept
    Retention { max_versions: Option<u32> },
}

/// First line of `--passphrase-file`, else $AIFW_BACKUP_PASSPHRASE.
pub fn backup_passphrase(passphrase_file: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(path) = passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CliError::Usage(format!("reading passphrase file {path}: {e}")))?;
        let line = content.lines().next().unwrap_or("").trim_end_matches('\r');
        if line.is_empty() {
            return Err(CliError::Usage(format!("passphrase file {path} is empty")).into());
        }
        return Ok(Some(line.to_string()));
    }
    Ok(std::env::var("AIFW_BACKUP_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty()))
}

/// Accept both an export envelope (`{config, …}`) and a bare config.
pub fn import_body(file_value: Value, passphrase: Option<String>) -> Value {
    let mut body = if file_value.get("config").is_some() {
        file_value
    } else {
        json!({ "config": file_value })
    };
    if let Some(p) = passphrase {
        body["passphrase"] = json!(p);
    }
    body
}

fn parse_map(pairs: &[String]) -> Result<serde_json::Map<String, Value>, CliError> {
    let mut m = serde_json::Map::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("--map expects OPN=IFACE, got '{p}'")))?;
        m.insert(k.trim().to_string(), json!(v.trim()));
    }
    Ok(m)
}

async fn active_version(client: &aifw_client::Client) -> anyhow::Result<i64> {
    let h = client.get("/config/history?limit=100").await?;
    crate::cli::output::rows(&h)
        .into_iter()
        .find(|v| v["applied"] == json!(true))
        .and_then(|v| v["version"].as_i64())
        .ok_or_else(|| anyhow::anyhow!("no active configuration version"))
}

pub async fn run(ctx: &mut Ctx, cmd: ConfigCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        ConfigCmd::Show => {
            let v = active_version(&client).await?;
            let cfg = client.get(&format!("/config/version?version={v}")).await?;
            ctx.raw(&cfg)
        }
        ConfigCmd::Export {
            secrets,
            passphrase_file,
            output_file,
        } => {
            let bytes = match secrets.as_str() {
                "plain" => {
                    return Err(CliError::Usage(
                        "plain-text secrets aren't exported through the API; as root on the appliance run `aifw local config-export --secrets plain`".into(),
                    )
                    .into());
                }
                "passphrase" => {
                    let pw = backup_passphrase(passphrase_file.as_deref())?.ok_or_else(|| {
                        CliError::Usage("--secrets passphrase needs --passphrase-file or $AIFW_BACKUP_PASSPHRASE".into())
                    })?;
                    client
                        .post_for_bytes("/config/export", &json!({ "passphrase": pw }))
                        .await?
                }
                _ => client.get_bytes("/config/export").await?,
            };
            // Re-indent for humans; keep the API's bytes if it isn't JSON.
            let text = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
            match output_file {
                Some(p) => {
                    crate::cli::config::write_atomic(&p, text.as_bytes(), 0o600)?;
                    ctx.io.eprintln(&format!("Wrote {} (0600)", p.display()));
                }
                None => ctx.io.println(&text),
            }
            Ok(())
        }
        ConfigCmd::Import {
            file,
            passphrase_file,
            preview,
            yes,
        } => {
            let v = crate::cli::body::read(&mut ctx.io, &file)?;
            let body = import_body(v, backup_passphrase(passphrase_file.as_deref())?);
            if preview {
                let p = client.post("/config/import-preview", &body).await?;
                return ctx.raw(&p);
            }
            ctx.confirm("Import this configuration and apply it to pf now?", yes)?;
            let timeout = ctx.slow_timeout(Duration::from_secs(300));
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/config/import",
                    Some(&body),
                    timeout,
                )
                .await?;
            ctx.message(&v, "Configuration imported and applied")
        }
        ConfigCmd::ImportOpnsense {
            file,
            preview,
            map,
            system_settings,
            no_commit_confirm,
            yes,
        } => {
            let xml = std::fs::read_to_string(&file)
                .map_err(|e| CliError::Usage(format!("cannot read {file}: {e}")))?;
            let mut body = json!({ "xml": xml, "interface_map": parse_map(&map)? });
            if preview {
                return ctx.raw(&client.post("/config/preview-opnsense", &body).await?);
            }
            body["commit_confirm"] = json!(!no_commit_confirm);
            body["import_system_settings"] = json!(system_settings);
            ctx.confirm("Import this OPNsense configuration and apply it now?", yes)?;
            let timeout = ctx.slow_timeout(Duration::from_secs(300));
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/config/import-opnsense",
                    Some(&body),
                    timeout,
                )
                .await?;
            ctx.message(&v, "OPNsense configuration imported")?;
            if !no_commit_confirm && !ctx.format().is_structured() {
                ctx.io.eprintln("Confirm it with `aifw confirm accept` before the window closes, or it reverts.");
            }
            Ok(())
        }
        ConfigCmd::History { limit } => {
            let v = client
                .get(&format!("/config/history?limit={limit}"))
                .await?;
            ctx.list_mapped(
                &v,
                &[
                    col("VERSION", "/version"),
                    col("STATE", "/_state"),
                    col("CREATED", "/created_at"),
                    col("BY", "/created_by"),
                    col("RESOURCES", "/resource_count"),
                    col("COMMENT", "/comment"),
                    wide("HASH", "/hash"),
                ],
                |r| {
                    let mut x = r.clone();
                    x["_state"] = json!(if r["applied"] == json!(true) {
                        "ACTIVE"
                    } else if r["rolled_back"] == json!(true) {
                        "ROLLED_BACK"
                    } else {
                        "saved"
                    });
                    x
                },
            )
        }
        ConfigCmd::Save { comment } => {
            let v = client
                .post("/config/save", &json!({ "comment": comment }))
                .await?;
            ctx.message(&v, "Configuration version saved")
        }
        ConfigCmd::Rollback { version, yes } => {
            ctx.confirm(
                &format!("Restore configuration version {version} and apply it now?"),
                yes,
            )?;
            let timeout = ctx.slow_timeout(Duration::from_secs(300));
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/config/restore",
                    Some(&json!({ "version": version })),
                    timeout,
                )
                .await?;
            ctx.message(&v, &format!("Restored version {version}"))
        }
        ConfigCmd::Diff { v1, v2 } => {
            let v = client.get(&format!("/config/diff?v1={v1}&v2={v2}")).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            // The summary fields are flattened into `data`.
            let s = crate::cli::output::item(&v);
            if s["identical"] == json!(true) {
                ctx.io
                    .println(&format!("Versions {v1} and {v2} are identical."));
                return Ok(());
            }
            let section = |name: &str, d: &Value| {
                format!(
                    "  {name}: {} → {} (+{} −{})",
                    d["v1_count"], d["v2_count"], d["added"], d["removed"]
                )
            };
            ctx.io.println(&format!("Version {v1} → {v2}"));
            ctx.io.println(&section("rules", &s["rules_diff"]));
            ctx.io.println(&section("nat", &s["nat_diff"]));
            ctx.io.println(&format!(
                "  total resources: {} → {}",
                s["total_v1"], s["total_v2"]
            ));
            Ok(())
        }
        ConfigCmd::Check => {
            let v = client.get("/config/check").await?;
            let c = crate::cli::output::item(&v).clone();
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                for (label, key) in [
                    ("error", "errors"),
                    ("warning", "warnings"),
                    ("info", "info"),
                ] {
                    for m in c[key].as_array().into_iter().flatten() {
                        ctx.io.println(&format!(
                            "{label}: {}",
                            m.as_str().map_or_else(|| m.to_string(), str::to_string)
                        ));
                    }
                }
                if c["valid"] == json!(true) {
                    ctx.io.println("Configuration is valid.");
                }
            }
            if c["valid"] == json!(false) {
                return Err(CliError::CheckFailed("configuration has errors".into()).into());
            }
            Ok(())
        }
        ConfigCmd::Retention { max_versions } => {
            let v = match max_versions {
                Some(n) => {
                    client
                        .put("/config/retention", &json!({ "max_versions": n }))
                        .await?
                }
                None => client.get("/config/retention").await?,
            };
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let d = crate::cli::output::item(&v);
            ctx.io.println(&format!(
                "Keeping {} versions ({} stored)",
                d["max_versions"],
                crate::cli::output::cell(d.get("current_count"))
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_file_first_line_wins_and_empty_is_error() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pw");
        std::fs::write(&f, "hunter2\r\nsecond line\n").unwrap();
        assert_eq!(
            backup_passphrase(Some(f.to_str().unwrap()))
                .unwrap()
                .as_deref(),
            Some("hunter2")
        );
        std::fs::write(&f, "\n").unwrap();
        assert!(
            backup_passphrase(Some(f.to_str().unwrap())).is_err(),
            "empty file is an error"
        );
        assert!(backup_passphrase(Some(dir.join("missing").to_str().unwrap())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_wraps_bare_configs() {
        let b = import_body(json!({"rules": []}), Some("pw".into()));
        assert_eq!(b, json!({"config": {"rules": []}, "passphrase": "pw"}));
        let env = json!({"version": 1, "config": {"rules": []}});
        assert_eq!(import_body(env.clone(), None), env);
    }

    #[test]
    fn interface_map() {
        let m = parse_map(&["lan=em1".into(), " wan = em0 ".into()]).unwrap();
        assert_eq!(m["lan"], "em1");
        assert_eq!(m["wan"], "em0");
        assert!(parse_map(&["nope".into()]).is_err());
    }
}
