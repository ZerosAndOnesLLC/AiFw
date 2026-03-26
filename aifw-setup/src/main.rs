mod apply;
mod config;
mod console;
mod totp;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // If --config provided, load from file instead of wizard
    if let Some(ref config_path) = args.config {
        let content = std::fs::read_to_string(config_path)?;
        let config: config::SetupConfig = serde_json::from_str(&content)?;

        if args.pf_only {
            println!("{}", apply::generate_pf_conf(&config));
            return Ok(());
        }

        apply::apply(&config).await.map_err(|e| anyhow::anyhow!(e))?;
        return Ok(());
    }

    // Run interactive wizard
    let Some(config) = wizard::run_wizard(args.reconfigure) else {
        std::process::exit(0);
    };

    if args.pf_only {
        println!("{}", apply::generate_pf_conf(&config));
        return Ok(());
    }

    apply::apply(&config).await.map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}
