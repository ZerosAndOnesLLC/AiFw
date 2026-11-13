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
    /// Run the updater directly (when the API is down, e.g. to roll back)
    #[command(subcommand)]
    Update(LocalUpdateCmd),
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

#[derive(Debug, Subcommand)]
pub enum LocalUpdateCmd {
    /// Check GitHub for an AiFw update
    Check {
        #[arg(long)]
        pre: bool,
    },
    /// Download and install the latest AiFw release
    Install {
        #[arg(long)]
        restart: bool,
        #[arg(long)]
        pre: bool,
    },
    /// Restore the previous AiFw version
    Rollback {
        #[arg(long)]
        restart: bool,
    },
    /// Restart AiFw services
    Restart,
    /// Reboot (shutdown -r +1)
    Reboot,
    /// Check for OS and package updates
    OsCheck,
    /// Install OS and package updates
    OsInstall,
    /// Upgrade FreeBSD to a newer release
    OsUpgrade {
        target: String,
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: LocalCmd, db: &std::path::Path) -> anyhow::Result<()> {
    match cmd {
        LocalCmd::Update(u) => match u {
            LocalUpdateCmd::Check { pre } => super::update_check(pre).await,
            LocalUpdateCmd::Install { restart, pre } => {
                super::update_install(db, restart, pre).await
            }
            LocalUpdateCmd::Rollback { restart } => super::update_rollback(restart).await,
            LocalUpdateCmd::Restart => super::update_restart().await,
            LocalUpdateCmd::Reboot => super::update_reboot().await,
            LocalUpdateCmd::OsCheck => super::update_os_check().await,
            LocalUpdateCmd::OsInstall => super::update_os_install().await,
            LocalUpdateCmd::OsUpgrade { target, yes } => {
                super::update_os_upgrade(&target, yes).await
            }
        },
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
