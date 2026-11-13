//! `aifw interfaces …` — network interfaces via the API. Bare
//! `aifw interfaces` lists them, as it always has.

use clap::Subcommand;
use serde_json::Value;

use crate::cli::body::Fields;
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum IfaceCmd {
    /// List interfaces
    #[command(visible_alias = "ls")]
    List,
    /// Detailed view (addresses, media, counters, roles)
    Detail,
    /// Traffic counters for one interface
    Stats { name: String },
    /// Assign a role (wan, lan, dmz, …) or clear it with --clear
    Role {
        name: String,
        role: Option<String>,
        #[arg(long, conflicts_with = "role")]
        clear: bool,
    },
    /// Change addressing (applied live)
    Configure {
        name: String,
        /// dhcp, static, none
        #[arg(long)]
        ipv4_mode: Option<String>,
        /// CIDR for static mode
        #[arg(long)]
        ipv4_address: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[arg(long)]
        ipv6_address: Option<String>,
        #[arg(long)]
        mtu: Option<u16>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        description: Option<String>,
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: Option<IfaceCmd>) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd.unwrap_or(IfaceCmd::List) {
        IfaceCmd::List => {
            let v = client.get("/interfaces").await?;
            ctx.list(
                &v,
                &[
                    col("INTERFACE", "/name"),
                    col("IPV4", "/ipv4"),
                    col("MAC", "/mac"),
                    col("STATUS", "/status"),
                    col("ROLE", "/role"),
                    wide("IPV6", "/ipv6"),
                ],
            )
        }
        IfaceCmd::Detail => {
            let v = client.get("/interfaces/detailed").await?;
            ctx.list(
                &v,
                &[
                    col("INTERFACE", "/name"),
                    col("STATUS", "/status"),
                    col("IPV4", "/ipv4"),
                    col("MODE", "/ipv4_mode"),
                    col("ROLE", "/role"),
                    col("MTU", "/mtu"),
                    col("RX BYTES", "/bytes_in"),
                    col("TX BYTES", "/bytes_out"),
                    wide("MAC", "/mac"),
                    wide("MEDIA", "/media"),
                    wide("GATEWAY", "/gateway"),
                    wide("ERRORS IN", "/errors_in"),
                    wide("ERRORS OUT", "/errors_out"),
                ],
            )
        }
        IfaceCmd::Stats { name } => {
            let v = client.get(&format!("/interfaces/{name}/stats")).await?;
            ctx.detail(
                &v,
                &[
                    ("Interface", "/name"),
                    ("Bytes in", "/bytes_in"),
                    ("Bytes out", "/bytes_out"),
                    ("Packets in", "/packets_in"),
                    ("Packets out", "/packets_out"),
                    ("Errors in", "/errors_in"),
                    ("Errors out", "/errors_out"),
                ],
            )
        }
        IfaceCmd::Role { name, role, clear } => {
            let v = match (role, clear) {
                (_, true) => client.delete(&format!("/interfaces/{name}/role")).await?,
                (Some(r), false) => {
                    client
                        .put(
                            &format!("/interfaces/{name}/role"),
                            &serde_json::json!({ "role": r }),
                        )
                        .await?
                }
                (None, false) => {
                    return Err(CliError::Usage("give a role, or --clear".into()).into());
                }
            };
            ctx.message(&v, "Role updated")
        }
        IfaceCmd::Configure {
            name,
            ipv4_mode,
            ipv4_address,
            gateway,
            ipv6_address,
            mtu,
            enabled,
            description,
            yes,
        } => {
            let body = Fields::new()
                .opt("ipv4_mode", ipv4_mode)
                .opt("ipv4_address", ipv4_address)
                .opt("gateway", gateway)
                .opt("ipv6_address", ipv6_address)
                .opt("mtu", mtu)
                .opt("enabled", enabled)
                .opt("description", description);
            if body.is_empty() {
                return Err(CliError::Usage("nothing to change: pass a field flag".into()).into());
            }
            ctx.confirm(
                &format!("Reconfigure {name} now? A mistake on the interface you're connected through can cut you off."),
                yes,
            )?;
            let v = client
                .put(&format!("/interfaces/config/{name}"), &body.into_value())
                .await?;
            ctx.message(&v, "Interface configured")?;
            // The API answers 200 with the validation message on bad input.
            let msg = v.get("message").and_then(Value::as_str).unwrap_or_default();
            if !msg.starts_with("Interface ") {
                return Err(CliError::Usage(msg.to_string()).into());
            }
            Ok(())
        }
    }
}
