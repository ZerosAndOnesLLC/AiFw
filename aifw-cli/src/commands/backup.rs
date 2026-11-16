//! `aifw backup s3 …` and `aifw notify smtp …` via the API. Secrets in the
//! config files: omit (or null) to keep the stored one, "" to clear it.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, col};

#[derive(Debug, Subcommand)]
pub enum BackupCmd {
    /// Off-box backups to S3-compatible storage
    #[command(subcommand)]
    S3(S3Cmd),
}

#[derive(Debug, Subcommand)]
pub enum S3Cmd {
    /// Show or replace the S3 settings (JSON/YAML)
    Config {
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Write, read and delete a test object
    Test,
    /// Backups stored in the bucket
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, default_value_t = 500)]
        max: u32,
    },
    /// Download a backup from S3 and save it as a config version
    /// (restore it afterwards with `aifw config rollback <version>`)
    Restore {
        key: String,
        #[arg(long)]
        comment: Option<String>,
        /// Passphrase for a passphrase-wrapped backup (file, first line)
        #[arg(long)]
        passphrase_file: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum NotifyCmd {
    /// Email notifications
    #[command(subcommand)]
    Smtp(SmtpCmd),
}

#[derive(Debug, Subcommand)]
pub enum SmtpCmd {
    /// Show or replace the SMTP settings (JSON/YAML)
    Config {
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Send a test email
    Test,
}

fn check_ok(ctx: &mut Ctx, v: &Value, what: &str) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        ctx.raw(v)?;
    } else {
        ctx.io.println(v["message"].as_str().unwrap_or(what));
    }
    if v["ok"] == json!(false) {
        return Err(CliError::CheckFailed(format!("{what} failed")).into());
    }
    Ok(())
}

async fn config(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    path: &str,
    file: Option<String>,
) -> anyhow::Result<()> {
    let v = match file {
        Some(f) => {
            let body = crate::cli::body::read(&mut ctx.io, &f)?;
            client.put(path, &body).await?
        }
        None => client.get(path).await?,
    };
    ctx.raw(&v)
}

pub async fn backup(ctx: &mut Ctx, cmd: BackupCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let BackupCmd::S3(c) = cmd;
    match c {
        S3Cmd::Config { file } => config(ctx, &client, "/backup/s3/config", file).await,
        S3Cmd::Test => {
            let v = client.post("/backup/s3/test", &Value::Null).await?;
            check_ok(ctx, &v, "S3 test")
        }
        S3Cmd::List { max } => {
            let v = client.get(&format!("/backup/s3/list?max={max}")).await?;
            ctx.list(
                &v,
                &[
                    col("KEY", "/key"),
                    col("SIZE", "/size"),
                    col("MODIFIED", "/last_modified"),
                ],
            )
        }
        S3Cmd::Restore {
            key,
            comment,
            passphrase_file,
        } => {
            let pw = super::config::backup_passphrase(passphrase_file.as_deref())?;
            let mut body = json!({ "key": key, "comment": comment });
            if let Some(p) = pw {
                body["passphrase"] = json!(p);
            }
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/backup/s3/import",
                    Some(&body),
                    ctx.slow_timeout(std::time::Duration::from_secs(300)),
                )
                .await?;
            ctx.message(&v, "Imported")
        }
    }
}

pub async fn notify(ctx: &mut Ctx, cmd: NotifyCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let NotifyCmd::Smtp(c) = cmd;
    match c {
        SmtpCmd::Config { file } => config(ctx, &client, "/notify/smtp/config", file).await,
        SmtpCmd::Test => {
            let v = client.post("/notify/smtp/test", &Value::Null).await?;
            check_ok(ctx, &v, "SMTP test")
        }
    }
}
