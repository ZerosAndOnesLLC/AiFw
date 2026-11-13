//! `aifw dhcp …` — the rDHCP server via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::{Ctx, Format, col, wide};

#[derive(Debug, Subcommand)]
pub enum DhcpCmd {
    /// Server status
    Status,
    /// Start the server
    Start,
    /// Stop the server
    Stop,
    /// Restart the server
    Restart,
    /// Write the config and reload the server
    Apply,
    /// List subnets
    Subnets {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Add a subnet
    SubnetAdd {
        #[arg(long)]
        network: String,
        #[arg(long)]
        pool_start: String,
        #[arg(long)]
        pool_end: String,
        #[arg(long)]
        gateway: String,
        /// DNS servers, comma-separated
        #[arg(long)]
        dns: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        lease_time: Option<u32>,
        #[arg(long)]
        desc: Option<String>,
        /// Full subnet (JSON/YAML, API request shape) from a file, or -
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Change a subnet (only the flags you pass)
    SubnetEdit {
        id: String,
        #[arg(long)]
        pool_start: Option<String>,
        #[arg(long)]
        pool_end: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
        #[arg(long)]
        dns: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        lease_time: Option<u32>,
        #[arg(long)]
        desc: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a subnet
    SubnetRemove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// List static reservations
    Reservations {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Add a static reservation
    ReservationAdd {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        ip: String,
        #[arg(long)]
        hostname: Option<String>,
        /// Subnet id
        #[arg(long)]
        subnet: Option<String>,
        #[arg(long)]
        desc: Option<String>,
    },
    /// Delete a reservation
    ReservationRemove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Active leases
    Leases {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Release (delete) the lease for an IP
    Release {
        ip: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Recent server log lines
    Logs {
        #[arg(long, default_value_t = 100)]
        lines: u32,
        /// Keep printing new lines
        #[arg(short = 'F', long)]
        follow: bool,
    },
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

/// Subnet as returned → request shape (dns_servers is a comma string on
/// the way out, a list on the way in).
fn subnet_request(s: &Value) -> Value {
    let mut r = s.clone();
    if let Some(o) = r.as_object_mut() {
        for k in ["id", "created_at", "updated_at"] {
            o.remove(k);
        }
        if let Some(d) = o.get("dns_servers").and_then(Value::as_str).map(csv) {
            o.insert("dns_servers".into(), json!(d));
        }
        if o.get("dns_servers").is_some_and(Value::is_null) {
            o.insert("dns_servers".into(), json!([]));
        }
    }
    r
}

pub async fn run(ctx: &mut Ctx, cmd: DhcpCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        DhcpCmd::Status => {
            let v = client.get("/dhcp/status").await?;
            ctx.detail(
                &v,
                &[
                    ("Running", "/running"),
                    ("Version", "/version"),
                    ("Uptime", "/uptime"),
                    ("Subnets", "/total_subnets"),
                    ("Reservations", "/total_reservations"),
                    ("Active leases", "/active_leases"),
                ],
            )
        }
        DhcpCmd::Start => {
            let v = client.post_empty("/dhcp/start").await?;
            ctx.service_message(&v, "DHCP started")
        }
        DhcpCmd::Stop => {
            let v = client.post_empty("/dhcp/stop").await?;
            ctx.service_message(&v, "DHCP stopped")
        }
        DhcpCmd::Restart => {
            let v = client.post_empty("/dhcp/restart").await?;
            ctx.service_message(&v, "DHCP restarted")
        }
        DhcpCmd::Apply => {
            let v = client.post_empty("/dhcp/v4/apply").await?;
            ctx.service_message(&v, "DHCP config applied")
        }
        DhcpCmd::Subnets { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/dhcp/v4/subnets").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NETWORK", "/network"),
                    col("POOL START", "/pool_start"),
                    col("POOL END", "/pool_end"),
                    col("GATEWAY", "/gateway"),
                    col("DNS", "/dns_servers"),
                    col("ENABLED", "/enabled"),
                    wide("DOMAIN", "/domain_name"),
                    wide("LEASE", "/lease_time"),
                    wide("DESCRIPTION", "/description"),
                ],
            )
        }
        DhcpCmd::SubnetAdd {
            network,
            pool_start,
            pool_end,
            gateway,
            dns,
            domain,
            lease_time,
            desc,
            file,
        } => {
            let flags = Fields::new()
                .set("network", network)
                .set("pool_start", pool_start)
                .set("pool_end", pool_end)
                .set("gateway", gateway)
                .opt("dns_servers", dns.as_deref().map(csv))
                .opt("domain_name", domain)
                .opt("lease_time", lease_time)
                .opt("description", desc);
            let body = body::for_create(&mut ctx.io, file.as_deref(), flags)?;
            let v = client.post("/dhcp/v4/subnets", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added subnet {}",
                crate::cli::output::item(&v)["id"].as_str().unwrap_or("?")
            ));
            ctx.io
                .eprintln("Run `aifw dhcp apply` to load it into the server.");
            Ok(())
        }
        DhcpCmd::SubnetEdit {
            id,
            pool_start,
            pool_end,
            gateway,
            dns,
            domain,
            lease_time,
            desc,
            enabled,
        } => {
            let all = client.get("/dhcp/v4/subnets").await?;
            let cur = crate::cli::output::rows(&all)
                .into_iter()
                .find(|s| s["id"] == json!(id))
                .cloned()
                .ok_or_else(|| aifw_client::ClientError::NotFound(format!("subnet {id}")))?;
            let flags = Fields::new()
                .opt("pool_start", pool_start)
                .opt("pool_end", pool_end)
                .opt("gateway", gateway)
                .opt("dns_servers", dns.as_deref().map(csv))
                .opt("domain_name", domain)
                .opt("lease_time", lease_time)
                .opt("description", desc)
                .opt("enabled", enabled);
            let body = body::for_update(&mut ctx.io, subnet_request(&cur), None, flags)?;
            let v = client.put(&format!("/dhcp/v4/subnets/{id}"), &body).await?;
            ctx.message(&v, &format!("Updated subnet {id}"))
        }
        DhcpCmd::SubnetRemove { id, yes } => {
            ctx.confirm(&format!("Delete DHCP subnet {id}?"), yes)?;
            let v = client.delete(&format!("/dhcp/v4/subnets/{id}")).await?;
            ctx.message(&v, &format!("Removed subnet {id}"))
        }
        DhcpCmd::Reservations { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/dhcp/v4/reservations").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("MAC", "/mac_address"),
                    col("IP", "/ip_address"),
                    col("HOSTNAME", "/hostname"),
                    col("SUBNET", "/subnet_id"),
                    wide("DESCRIPTION", "/description"),
                ],
            )
        }
        DhcpCmd::ReservationAdd {
            mac,
            ip,
            hostname,
            subnet,
            desc,
        } => {
            let body = Fields::new()
                .set("mac_address", mac)
                .set("ip_address", ip)
                .opt("hostname", hostname)
                .opt("subnet_id", subnet)
                .opt("description", desc)
                .into_value();
            let v = client.post("/dhcp/v4/reservations", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added reservation {}",
                crate::cli::output::item(&v)["id"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        DhcpCmd::ReservationRemove { id, yes } => {
            ctx.confirm(&format!("Delete reservation {id}?"), yes)?;
            let v = client
                .delete(&format!("/dhcp/v4/reservations/{id}"))
                .await?;
            ctx.message(&v, &format!("Removed reservation {id}"))
        }
        DhcpCmd::Leases { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/dhcp/v4/leases").await?;
            ctx.list(
                &v,
                &[
                    col("IP", "/ip_address"),
                    col("MAC", "/mac_address"),
                    col("HOSTNAME", "/hostname"),
                    col("STATE", "/state"),
                    col("EXPIRES", "/expires"),
                    wide("SUBNET", "/subnet"),
                ],
            )
        }
        DhcpCmd::Release { ip, yes } => {
            ctx.confirm(&format!("Release the lease for {ip}?"), yes)?;
            let v = client.delete(&format!("/dhcp/v4/leases/{ip}")).await?;
            ctx.message(&v, &format!("Released {ip}"))
        }
        DhcpCmd::Logs { lines, follow } => {
            super::logs::tail(ctx, &client, &format!("/dhcp/logs?lines={lines}"), follow).await
        }
    }
}
