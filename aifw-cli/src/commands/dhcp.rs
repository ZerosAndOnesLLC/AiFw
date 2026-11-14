//! `aifw dhcp …` — the rDHCP server via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::{Ctx, col, wide};

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

/// Subnet as returned → request shape. List fields come back as comma
/// strings and go in as arrays; `null` stays `null` (a subnet without its
/// own DNS servers inherits the global ones — sending `[]` would turn
/// that into "no DNS at all").
fn subnet_request(s: &Value) -> Value {
    let mut r = s.clone();
    if let Some(o) = r.as_object_mut() {
        for k in ["id", "created_at", "updated_at"] {
            o.remove(k);
        }
        for k in ["dns_servers", "ntp_servers", "trusted_relays"] {
            if let Some(list) = o.get(k).and_then(Value::as_str).map(csv) {
                o.insert(k.into(), json!(list));
            }
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
            let v = client.get("/dhcp/v4/subnets").await?;
            if json {
                return ctx.legacy_json(&v, Some(&legacy_subnet));
            }
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
            let v = client.get("/dhcp/v4/reservations").await?;
            if json {
                return ctx.legacy_json(&v, Some(&legacy_reservation));
            }
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
            let v = client.get("/dhcp/v4/leases").await?;
            if json {
                return ctx.legacy_json(&v, Some(&legacy_lease));
            }
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
            ctx.service_message(&v, &format!("Released {ip}"))
        }
        DhcpCmd::Logs { lines, follow } => {
            super::logs::tail(ctx, &client, &format!("/dhcp/logs?lines={lines}"), follow).await
        }
    }
}

/// Row shapes the pre-API `dhcp … --json` printed.
fn legacy_subnet(s: &Value) -> Value {
    json!({
        "id": s["id"], "network": s["network"], "pool_start": s["pool_start"],
        "pool_end": s["pool_end"], "gateway": s["gateway"], "enabled": s["enabled"],
    })
}

fn legacy_reservation(r: &Value) -> Value {
    json!({ "id": r["id"], "mac": r["mac_address"], "ip": r["ip_address"], "hostname": r["hostname"] })
}

fn legacy_lease(l: &Value) -> Value {
    let mut out = l.clone();
    if let Some(o) = out.as_object_mut() {
        if let Some(ip) = o.remove("ip_address") {
            o.insert("ip".into(), ip);
        }
        if let Some(mac) = o.remove("mac_address") {
            o.insert("mac".into(), mac);
        }
    }
    out
}

#[cfg(test)]
mod legacy_tests {
    use super::*;

    #[test]
    fn subnet_edit_keeps_inherited_dns_and_lists_ntp() {
        let r = subnet_request(
            &json!({"id": "x", "network": "10.0.0.0/24", "dns_servers": null, "ntp_servers": "10.0.0.1, 10.0.0.2"}),
        );
        assert_eq!(r["dns_servers"], Value::Null, "inherit global DNS");
        assert_eq!(r["ntp_servers"], json!(["10.0.0.1", "10.0.0.2"]));
        assert!(r.get("id").is_none());
    }

    #[test]
    fn legacy_shapes() {
        let r = legacy_reservation(
            &json!({"id": "1", "mac_address": "aa", "ip_address": "10.0.0.2", "hostname": "h", "subnet_id": "s"}),
        );
        assert_eq!(
            r,
            json!({"id": "1", "mac": "aa", "ip": "10.0.0.2", "hostname": "h"})
        );
        let l = legacy_lease(
            &json!({"ip_address": "10.0.0.3", "mac_address": "bb", "state": "active"}),
        );
        assert_eq!(l, json!({"ip": "10.0.0.3", "mac": "bb", "state": "active"}));
    }
}
