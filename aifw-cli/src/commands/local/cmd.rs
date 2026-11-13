//! `aifw local` subcommands.

use clap::Subcommand;
use serde_json::json;

use crate::cli::Ctx;
use crate::cli::exit::CliError;
use crate::cli::onbox;

#[derive(Debug, Subcommand)]
pub enum LocalCmd {
    /// pf / anchor / DNS-backend status read straight from the box
    Status,
    /// Load rules, NAT, queues and rate limits from the database into pf
    Reload,
    /// Repair missing pf anchor hooks and rc.conf DNS backend drift
    Reconcile,
    /// Create the database (first boot / recovery)
    Init {
        #[arg(long)]
        path: Option<std::path::PathBuf>,
    },
    /// Mint the root-only on-box CLI key (/usr/local/etc/aifw/cli.key)
    ///
    /// Happens automatically the first time `aifw` runs as root with no
    /// other credential; use --rotate to replace an existing key.
    CliKey {
        /// Replace the existing key
        #[arg(long)]
        rotate: bool,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: LocalCmd, db: &std::path::Path) -> anyhow::Result<()> {
    match cmd {
        LocalCmd::Status => super::status(db).await,
        LocalCmd::Reload => super::reload(db).await,
        LocalCmd::Reconcile => super::reconcile(db).await,
        LocalCmd::Init { path } => super::init(path.as_deref().unwrap_or(db)).await,
        LocalCmd::CliKey { rotate } => cli_key(ctx, rotate),
    }
}

fn cli_key(ctx: &mut Ctx, rotate: bool) -> anyhow::Result<()> {
    if !onbox::is_root() {
        return Err(CliError::Usage(
            "`aifw local cli-key` must run as root on the appliance".into(),
        )
        .into());
    }
    let path = ctx.onbox.cli_key.clone();
    if onbox::read_key(&path).is_some() && !rotate {
        ctx.io.eprintln(&format!(
            "{} already exists; pass --rotate to replace it",
            path.display()
        ));
        return Ok(());
    }
    let key = super::provision_cli_key(&ctx.onbox)?;
    let v = json!({ "path": path.display().to_string(), "prefix": &key[..12] });
    if ctx.format().is_structured() {
        return ctx.raw(&v);
    }
    ctx.io.println(&format!(
        "Wrote {} (key prefix {}…)",
        path.display(),
        &key[..12]
    ));
    Ok(())
}
