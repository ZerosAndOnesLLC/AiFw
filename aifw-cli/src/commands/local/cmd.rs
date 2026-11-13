//! `aifw local` subcommands.

use clap::Subcommand;
use serde_json::json;

use crate::cli::Ctx;
use crate::cli::exit::CliError;
use crate::cli::onbox;

#[derive(Debug, Subcommand)]
pub enum LocalCmd {
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

pub async fn run(ctx: &mut Ctx, cmd: LocalCmd) -> anyhow::Result<()> {
    match cmd {
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
