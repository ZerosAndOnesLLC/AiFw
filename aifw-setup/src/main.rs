mod apply;
mod config;
mod console;
mod hwdetect;
#[cfg(test)]
mod totp;
mod tuning;
mod wizard;

#[cfg(test)]
mod tests;

use clap::Parser;

#[derive(Parser)]
#[command(name = "aifw-setup", about = "AiFw initial setup wizard")]
struct Args {
    /// Re-run setup without wiping (reconfigure mode)
    #[arg(long)]
    reconfigure: bool,

    /// Skip interactive wizard and apply a config file
    #[arg(long)]
    config: Option<String>,

    /// Just generate a pf.conf and exit (no DB init)
    #[arg(long)]
    pf_only: bool,

    /// Print the sudoers content that would be installed at
    /// /usr/local/etc/sudoers.d/aifw and exit. Used by CI to pipe into
    /// `visudo -cf -` for syntax validation (#204).
    #[arg(long)]
    print_sudoers: bool,

    /// Print an example seed file for unattended setup (--config) and exit.
    /// Edit the CHANGE-ME placeholders, then: aifw-setup --config seed.json
    #[arg(long)]
    print_seed_template: bool,

    /// Print the OS packages this build requires (one per line, from the
    /// embedded manifest) and exit. Used by aifw-restart.sh to install
    /// dependencies a transitional upgrade missed (#565).
    #[arg(long)]
    print_packages: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.print_sudoers {
        print!("{}", apply::sudoers_content());
        return Ok(());
    }

    if args.print_seed_template {
        print!("{}", config::SetupConfig::seed_template());
        return Ok(());
    }

    if args.print_packages {
        for pkg in aifw_core::updater::manifest_packages() {
            println!("{pkg}");
        }
        return Ok(());
    }

    // If --config provided, load from file instead of wizard (unattended
    // setup, #533 Phase 2). The seed may carry plaintext admin/root
    // passwords; they are hashed/applied here and never written back out.
    if let Some(ref config_path) = args.config {
        let content = std::fs::read_to_string(config_path)?;
        let mut config: config::SetupConfig = serde_json::from_str(&content)?;
        // Auto-detect RAM if not explicitly set in the config file
        if config.ram_mb == 0 || config.ram_mb == 1024 {
            config.ram_mb = hwdetect::SystemProfile::detect().memory.total_mb;
        }

        if args.pf_only {
            println!("{}", apply::generate_pf_conf(&config));
            return Ok(());
        }

        config
            .resolve_seed_secrets()
            .map_err(|e| anyhow::anyhow!("seed config: {e}"))?;
        config
            .validate_seed()
            .map_err(|e| anyhow::anyhow!("seed config: {e}"))?;
        if config.wan_interface.starts_with("CHANGE-ME") {
            anyhow::bail!("seed config: template placeholders not filled in");
        }

        if let Some(root_pw) = config.root_password.take() {
            match apply::set_root_password_noninteractive(&root_pw) {
                Ok(()) => println!("Root password set."),
                Err(e) => eprintln!("WARNING: root password not set: {e}"),
            }
        }

        apply::apply(&config, &[])
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        return Ok(());
    }

    // Run interactive wizard
    let Some(result) = wizard::run_wizard(args.reconfigure) else {
        std::process::exit(0);
    };

    if args.pf_only {
        println!("{}", apply::generate_pf_conf(&result.config));
        return Ok(());
    }

    apply::apply(&result.config, &result.tuning)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}
