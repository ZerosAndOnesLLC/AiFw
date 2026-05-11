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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.print_sudoers {
        print!("{}", apply::sudoers_content());
        return Ok(());
    }

    // If --config provided, load from file instead of wizard
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
