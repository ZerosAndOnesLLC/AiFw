//! `aifw cluster …` — HA: CARP VIPs, pfsync, nodes, health checks,
//! promote/demote/maintenance, and `verify` (local kernel checks + the API
//! view; `--json` output is the contract `scripts/ha-verify.sh` parses).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::output::Col;
use crate::cli::{Ctx, Format, col, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum ClusterCmd {
    /// This node's cluster status
    Status {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// CARP virtual IPs
    #[command(subcommand)]
    Carp(CarpCmd),
    /// pfsync configuration
    #[command(subcommand)]
    Pfsync(PfsyncCmd),
    /// Cluster nodes
    #[command(subcommand)]
    Nodes(NodesCmd),
    /// Health checks
    #[command(subcommand)]
    Health(HealthCmd),
    /// Clear this node's operator demotion and maintenance mode; with
    /// preemption on, it retakes MASTER if its advskew beats the peer's
    Promote,
    /// Demote this node so the peer takes the VIPs (until promote or reboot)
    Demote {
        #[arg(short, long)]
        yes: bool,
    },
    /// Persistent CARP maintenance mode (survives reboot)
    Maintenance {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Force a snapshot pull from peer
    Sync,
    /// Peer and replication state as seen from this node
    PeerState,
    /// Recent CARP role changes
    FailoverHistory,
    /// Run local-side verification checks. Exits 0 on healthy, non-zero on failure.
    Verify {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CarpCmd {
    /// List CARP VIPs
    #[command(visible_alias = "ls")]
    List,
    /// Show a single CARP VIP
    Show { id: String },
    /// Create a CARP VIP
    Add {
        #[arg(long)]
        vhid: u8,
        #[arg(long)]
        interface: String,
        /// Virtual IP in addr/prefix form, e.g. 192.0.2.1/24
        #[arg(long)]
        vip: String,
        /// Shared CARP password (prefer --password-stdin)
        #[arg(
            long,
            required_unless_present = "password_stdin",
            conflicts_with = "password_stdin"
        )]
        password: Option<String>,
        /// Read the CARP password from stdin
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove a CARP VIP
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum PfsyncCmd {
    /// Get pfsync configuration
    Get,
    /// Set pfsync configuration
    Set {
        #[arg(long)]
        sync_interface: String,
        #[arg(long)]
        sync_peer: Option<String>,
        /// Defer packets until the peer acknowledges the state (true/false)
        #[arg(long, num_args = 0..=1, default_value = "true", default_missing_value = "true")]
        defer: bool,
        /// conservative, tight, aggressive
        #[arg(long, default_value = "conservative")]
        latency_profile: String,
        #[arg(long, num_args = 0..=1, default_value = "false", default_missing_value = "true")]
        dhcp_link: bool,
        /// Legacy (#486), ignored: since #712 WireGuard always follows the CARP role
        #[arg(long, hide = true, num_args = 0..=1, default_value = "false", default_missing_value = "true")]
        wg_deconfigure_on_backup: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodesCmd {
    /// List cluster nodes
    #[command(visible_alias = "ls")]
    List,
    /// Show a cluster node
    Show { id: String },
    /// Add a cluster node
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        address: String,
        /// Node role: primary, secondary, or standalone
        #[arg(long, default_value = "secondary")]
        role: String,
        /// Port the peer's API listens on (default 8080)
        #[arg(long)]
        api_port: Option<u16>,
    },
    /// Remove a cluster node
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Reset (or set) the pinned TLS certificate fingerprint of a peer.
    /// Without --fingerprint the pin is cleared and re-learned on next contact.
    Repin {
        id: String,
        /// SHA-256 fingerprint of the peer's certificate (64 hex chars, colons ok)
        #[arg(long)]
        fingerprint: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum HealthCmd {
    /// List health checks
    #[command(visible_alias = "ls")]
    List,
    /// Add a health check
    Add {
        #[arg(long)]
        name: String,
        /// Check type: ping, tcp_port, http_get, pf_status
        #[arg(long)]
        check_type: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value_t = 10)]
        interval_secs: u32,
    },
    /// Remove a health check
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Trigger an immediate probe of all enabled health checks
    Run,
}

const CARP_COLS: &[Col] = &[
    col("ID", "/id"),
    col("VHID", "/vhid"),
    col("VIP", "/_vip"),
    col("IFACE", "/interface"),
    col("STATUS", "/status"),
    wide("ADVSKEW", "/advskew"),
];
const NODE_COLS: &[Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("ADDRESS", "/address"),
    col("ROLE", "/role"),
    col("HEALTH", "/health"),
    col("LAST SEEN", "/last_seen"),
    wide("VERSION", "/software_version"),
    wide("API PORT", "/api_port"),
    wide("PIN", "/cert_fingerprint"),
];
const HEALTH_COLS: &[Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("TYPE", "/check_type"),
    col("TARGET", "/target"),
    col("INTERVAL", "/interval_secs"),
    col("ENABLED", "/enabled"),
];

fn carp_row(c: &Value) -> Value {
    let mut r = c.clone();
    r["_vip"] = json!(format!(
        "{}/{}",
        c["virtual_ip"].as_str().unwrap_or("?"),
        c["prefix"]
    ));
    r
}

pub async fn run(ctx: &mut Ctx, cmd: ClusterCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        ClusterCmd::Status { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let s = client.get("/cluster/status").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&s);
            }
            let mut v = s.clone();
            v["_reasons"] = s["demotion"]["reasons"].clone();
            ctx.detail(
                &v,
                &[
                    ("Role", "/role"),
                    ("Configured role", "/configured_role"),
                    ("Peer reachable", "/peer_reachable"),
                    ("Split brain", "/split_brain"),
                    ("pfsync state count", "/pfsync_state_count"),
                    ("Last snapshot hash", "/last_snapshot_hash"),
                    ("Maintenance", "/demotion/maintenance"),
                    ("Demotion level", "/demotion/level"),
                    ("Demotion reasons", "/_reasons"),
                ],
            )?;
            if let Some(w) = s["warnings"].as_array().filter(|w| !w.is_empty()) {
                for x in w {
                    ctx.io
                        .eprintln(&format!("warning: {}", x.as_str().unwrap_or_default()));
                }
            }
            Ok(())
        }
        ClusterCmd::Carp(c) => match c {
            CarpCmd::List => {
                let v = client.get("/cluster/carp").await?;
                ctx.list_mapped(&v, CARP_COLS, carp_row)
            }
            CarpCmd::Show { id } => ctx.raw(&client.get(&format!("/cluster/carp/{id}")).await?),
            CarpCmd::Add {
                vhid,
                interface,
                vip,
                password,
                password_stdin,
            } => {
                let (ip, prefix) = vip.split_once('/').ok_or_else(|| {
                    CliError::Usage("--vip must be in 'addr/prefix' form, e.g. 192.0.2.1/24".into())
                })?;
                let ip: std::net::IpAddr = ip
                    .parse()
                    .map_err(|e| CliError::Usage(format!("invalid IP {ip}: {e}")))?;
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|e| CliError::Usage(format!("invalid prefix {prefix}: {e}")))?;
                let password = match (password, password_stdin) {
                    (Some(p), _) => p,
                    (None, true) => prompt::read_line_raw(&mut ctx.io)?.trim().to_string(),
                    (None, false) => String::new(),
                };
                if password.is_empty() {
                    return Err(CliError::Usage("a CARP password is required".into()).into());
                }
                let v = client
                    .post(
                        "/cluster/carp",
                        &json!({ "vhid": vhid, "virtual_ip": ip, "prefix": prefix, "interface": interface, "password": password }),
                    )
                    .await?;
                if let Some(w) = v["warning"].as_str() {
                    ctx.io.eprintln(&format!("warning: {w}"));
                }
                if ctx.format().is_structured() {
                    return ctx.raw(&v);
                }
                ctx.io.println(&format!(
                    "Added CARP VIP {} (vhid {vhid})",
                    v["id"].as_str().unwrap_or("?")
                ));
                Ok(())
            }
            CarpCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Remove CARP VIP {id}?"), yes)?;
                client.delete(&format!("/cluster/carp/{id}")).await?;
                ctx.message(&Value::Null, &format!("Removed CARP VIP {id}"))
            }
        },
        ClusterCmd::Pfsync(p) => match p {
            PfsyncCmd::Get => {
                let v = client.get("/cluster/pfsync").await?;
                if v.is_null() && !ctx.format().is_structured() {
                    ctx.io.println("pfsync is not configured.");
                    return Ok(());
                }
                ctx.raw(&v)
            }
            PfsyncCmd::Set {
                sync_interface,
                sync_peer,
                defer,
                latency_profile,
                dhcp_link,
                wg_deconfigure_on_backup,
            } => {
                let v = client
                    .put(
                        "/cluster/pfsync",
                        &json!({
                            "sync_interface": sync_interface,
                            "sync_peer": sync_peer,
                            "defer": defer,
                            "enabled": true,
                            "latency_profile": latency_profile,
                            "heartbeat_iface": null,
                            "heartbeat_interval_ms": null,
                            "dhcp_link": dhcp_link,
                            "wg_deconfigure_on_backup": wg_deconfigure_on_backup,
                        }),
                    )
                    .await?;
                ctx.raw(&v)
            }
        },
        ClusterCmd::Nodes(n) => match n {
            NodesCmd::List => {
                let v = client.get("/cluster/nodes").await?;
                ctx.list(&v, NODE_COLS)
            }
            NodesCmd::Show { id } => ctx.raw(&client.get(&format!("/cluster/nodes/{id}")).await?),
            NodesCmd::Add {
                name,
                address,
                role,
                api_port,
            } => {
                let mut body = json!({ "name": name, "address": address, "role": role });
                if let Some(p) = api_port {
                    body["api_port"] = json!(p);
                }
                let v = client.post("/cluster/nodes", &body).await?;
                if ctx.format().is_structured() {
                    return ctx.raw(&v);
                }
                ctx.io.println(&format!(
                    "Added node {} ({})",
                    v["name"].as_str().unwrap_or("?"),
                    v["id"].as_str().unwrap_or("?")
                ));
                Ok(())
            }
            NodesCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Remove cluster node {id}?"), yes)?;
                client.delete(&format!("/cluster/nodes/{id}")).await?;
                ctx.message(&Value::Null, &format!("Removed node {id}"))
            }
            NodesCmd::Repin { id, fingerprint } => {
                let body = match fingerprint {
                    Some(fp) => json!({ "fingerprint": crate::cli::parse::fingerprint(&fp)? }),
                    None => json!({}),
                };
                let v = client
                    .post(&format!("/cluster/nodes/{id}/repin"), &body)
                    .await?;
                if ctx.format().is_structured() {
                    return ctx.raw(&v);
                }
                match v.get("cert_fingerprint").and_then(Value::as_str) {
                    Some(fp) => ctx.io.println(&format!("Node {id} pinned to {fp}")),
                    None => ctx.io.println(&format!(
                        "Node {id} pin cleared — it will be re-learned on the next contact."
                    )),
                }
                Ok(())
            }
        },
        ClusterCmd::Health(h) => match h {
            HealthCmd::List => {
                let v = client.get("/cluster/health").await?;
                ctx.list(&v, HEALTH_COLS)
            }
            HealthCmd::Add {
                name,
                check_type,
                target,
                interval_secs,
            } => {
                let v = client
                    .post(
                        "/cluster/health",
                        &json!({ "name": name, "check_type": check_type, "target": target, "interval_secs": interval_secs }),
                    )
                    .await?;
                if ctx.format().is_structured() {
                    return ctx.raw(&v);
                }
                ctx.io.println(&format!(
                    "Added health check {}",
                    v["id"].as_str().unwrap_or("?")
                ));
                Ok(())
            }
            HealthCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Remove health check {id}?"), yes)?;
                client.delete(&format!("/cluster/health/{id}")).await?;
                ctx.message(&Value::Null, &format!("Removed health check {id}"))
            }
            HealthCmd::Run => {
                let timeout = ctx.slow_timeout(std::time::Duration::from_secs(120));
                let results = client
                    .request_with_timeout(
                        reqwest::Method::POST,
                        "/cluster/health/run",
                        Some(&json!({})),
                        timeout,
                    )
                    .await?;
                let rows = crate::cli::output::rows(&results);
                let failed = rows
                    .iter()
                    .filter(|r| r["healthy"].as_bool() != Some(true))
                    .count();
                if ctx.format().is_structured() {
                    ctx.raw(&results)?;
                } else if rows.is_empty() {
                    ctx.io.println("No enabled health checks.");
                } else {
                    let mapped: Vec<Value> = rows
                        .iter()
                        .map(|r| {
                            let mut x = (*r).clone();
                            x["_ok"] = json!(if r["healthy"].as_bool() == Some(true) {
                                "OK"
                            } else {
                                "FAIL"
                            });
                            x
                        })
                        .collect();
                    let t = crate::cli::output::table(
                        &mapped.iter().collect::<Vec<_>>(),
                        &[
                            col("RESULT", "/_ok"),
                            col("NAME", "/name"),
                            col("TYPE", "/check_type"),
                            col("TARGET", "/target"),
                        ],
                        ctx.format(),
                    );
                    ctx.io.println(&t);
                }
                if failed > 0 {
                    return Err(
                        CliError::CheckFailed(format!("{failed} health check(s) failing")).into(),
                    );
                }
                Ok(())
            }
        },
        ClusterCmd::Promote => {
            client.post_empty("/cluster/promote").await?;
            ctx.message(
                &Value::Null,
                "Operator demotion and maintenance mode cleared",
            )
        }
        ClusterCmd::Demote { yes } => {
            ctx.confirm("Demote this node so the peer takes the VIPs?", yes)?;
            client.post_empty("/cluster/demote").await?;
            ctx.message(
                &Value::Null,
                "Demoted — the peer takes the VIPs; `aifw cluster promote` undoes it",
            )
        }
        ClusterCmd::Maintenance { state } => {
            let on = state == "on";
            client
                .put("/cluster/maintenance", &json!({ "enabled": on }))
                .await?;
            ctx.message(
                &Value::Null,
                if on {
                    "Maintenance mode on — this node stays BACKUP, across reboots, until turned off"
                } else {
                    "Maintenance mode off"
                },
            )
        }
        ClusterCmd::Sync => {
            let timeout = ctx.slow_timeout(std::time::Duration::from_secs(120));
            client
                .request_with_timeout(
                    reqwest::Method::POST,
                    "/cluster/snapshot/force",
                    Some(&json!({})),
                    timeout,
                )
                .await?;
            ctx.message(&Value::Null, "Snapshot pulled from peer")
        }
        ClusterCmd::PeerState => ctx.raw(&client.get("/cluster/peer-state").await?),
        ClusterCmd::FailoverHistory => {
            let v = client.get("/cluster/failover-history").await?;
            ctx.raw(&v)
        }
        ClusterCmd::Verify { json } => verify(ctx, &client, json).await,
    }
}

/// `cluster verify`: `--json` prints exactly `{ok, failures, status}` on
/// stdout (one document; scripts/ha-verify.sh parses it) and the command
/// exits non-zero on any failure.
async fn verify(ctx: &mut Ctx, client: &aifw_client::Client, as_json: bool) -> anyhow::Result<()> {
    // Kernel checks look at *this* machine: run them only when the target
    // is this appliance; a remote target (--context fw2, fan-out) gets the
    // API-side checks, and `scope` says which ran.
    let local = crate::cli::onbox::is_loopback(&ctx.target()?.url);
    let failures = verify_failures(client, local).await;
    let status = client.get("/cluster/status").await.unwrap_or(Value::Null);
    if as_json || ctx.format().is_structured() {
        ctx.raw(&json!({
            "ok": failures.is_empty(),
            "failures": failures,
            "status": status,
            "scope": if local { "local" } else { "api-only" },
        }))?;
    } else if failures.is_empty() {
        ctx.io.println("OK — cluster healthy");
    } else {
        for f in &failures {
            ctx.io.eprintln(&format!("FAIL: {f}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CliError::CheckFailed(format!("{} cluster check(s) failed", failures.len())).into())
    }
}

/// Every check `aifw cluster verify` runs (#712: the old checks grepped
/// `pfctl -sr` for a `set` option that never appears there, and required a
/// received-snapshot hash that only a standby ever has — a healthy primary
/// could not pass).
/// Kernel-side checks; they inspect the machine the CLI runs on, so they
/// only make sense when the target is this appliance.
async fn kernel_failures() -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    if std::env::consts::OS != "freebsd" {
        failures.push(format!(
            "kernel checks skipped: not running on FreeBSD (host OS is {})",
            std::env::consts::OS
        ));
    }

    // 1. floating state policy in the loaded pf.conf (needed for pfsync'd
    //    states to match on the surviving node)
    let pf_conf = std::fs::read_to_string("/usr/local/etc/aifw/pf.conf.aifw").unwrap_or_default();
    if !pf_conf
        .lines()
        .any(|l| l.trim() == "set state-policy floating")
    {
        failures.push("pf.conf.aifw does not set `state-policy floating`".into());
    }

    // 2. kernel CARP + pfsync
    let view = aifw_core::carp::kernel_view().await;
    if view.vhids.is_empty() {
        failures.push("no CARP vhids in the kernel".into());
    }
    match view.aggregate_state() {
        "split" => failures.push("vhids disagree (MASTER on some, BACKUP on others)".into()),
        "init" => failures.push("a vhid is still in INIT".into()),
        _ => {}
    }
    if aifw_core::carp::preempt_enabled().await != Some(true) {
        failures.push("net.inet.carp.preempt is not 1".into());
    }
    match &view.pfsync {
        None => failures.push("pfsync0 does not exist".into()),
        Some(p) if !p.up => failures.push("pfsync0 is down".into()),
        Some(p) if p.syncdev.is_none() => failures.push("pfsync0 has no syncdev".into()),
        Some(p) if p.syncok == Some(false) => {
            failures.push("pfsync bulk update not complete (syncok 0)".into())
        }
        _ => {}
    }
    let reasons = aifw_core::carp::held_reasons().await;
    if !reasons.is_empty() {
        let names: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
        failures.push(format!("demotion held: {}", names.join(", ")));
    }

    failures
}

async fn verify_failures(client: &aifw_client::Client, local: bool) -> Vec<String> {
    let mut failures = if local {
        kernel_failures().await
    } else {
        Vec::new()
    };
    // 3. API view: peer answering, no split brain, replication state
    match client.get("/cluster/status").await {
        Ok(st) => {
            if !st["peer_reachable"].as_bool().unwrap_or(false) {
                failures.push("peer is not answering on its API".into());
            }
            if st["split_brain"].as_bool().unwrap_or(false) {
                failures.push("split brain: both nodes report MASTER".into());
            }
            if st["configured_role"] == "secondary"
                && st["last_snapshot_hash"].as_str().unwrap_or("").is_empty()
            {
                failures.push("no config snapshot received from the primary yet".into());
            }
        }
        Err(e) => failures.push(format!("/cluster/status failed: {e}")),
    }
    failures
}
