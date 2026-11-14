//! `aifw vpn …` — WireGuard tunnels/peers and IPsec (IKEv2) tunnels via the
//! API. The flat legacy commands (`wg-add`, `ipsec-status`, …) still work.

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::exit::CliError;
use crate::cli::output::{self, Col};
use crate::cli::{Ctx, Format, col, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum VpnCmd {
    /// WireGuard tunnels and peers
    #[command(subcommand)]
    Wg(WgCmd),
    /// IPsec (IKEv2) tunnels
    #[command(subcommand)]
    Ipsec(IpsecCmd),
    /// Everything: WireGuard tunnels with peers, IPsec tunnels, legacy SAs
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Delete a WireGuard tunnel, IPsec tunnel, legacy SA or WireGuard peer by id
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    // ---- legacy flat spellings (kept for scripts) ----
    #[command(hide = true)]
    WgAdd {
        #[arg(long)]
        name: String,
        /// Ignored: the API assigns the next free wgN
        #[arg(long, default_value = "wg0")]
        interface: String,
        #[arg(long, default_value = "51820")]
        port: u16,
        #[arg(long)]
        address: String,
    },
    #[command(hide = true)]
    WgPeerAdd {
        #[arg(long)]
        tunnel: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long, default_value = "0.0.0.0/0")]
        allowed_ips: String,
        #[arg(long)]
        keepalive: Option<u16>,
    },
    #[command(hide = true)]
    IpsecAdd {
        #[arg(long)]
        name: String,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        psk: String,
        #[arg(long)]
        local_ts: String,
        #[arg(long)]
        remote_ts: String,
        #[arg(long)]
        local: Option<String>,
    },
    #[command(hide = true)]
    IpsecStart { id: String },
    #[command(hide = true)]
    IpsecStop { id: String },
    #[command(hide = true)]
    IpsecStatus {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum WgCmd {
    /// List tunnels
    #[command(visible_alias = "ls")]
    List,
    /// Add a tunnel (the interface wgN is assigned automatically)
    Add(WgTunnelArgs),
    /// Change a tunnel
    Edit {
        id: String,
        #[command(flatten)]
        a: WgTunnelEdit,
    },
    /// Delete a tunnel and its peers
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Bring a tunnel up
    Start { id: String },
    /// Take a tunnel down
    Stop { id: String },
    /// Live tunnel status (handshakes, transfer)
    Status { id: String },
    /// Peers of a tunnel
    #[command(subcommand)]
    Peers(PeerCmd),
}

#[derive(Debug, Args)]
pub struct WgTunnelArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long, default_value = "51820")]
    pub port: u16,
    /// Tunnel address, e.g. 10.8.0.1/24
    #[arg(long)]
    pub address: String,
    #[arg(long)]
    pub address6: Option<String>,
    /// DNS servers pushed to peers
    #[arg(long)]
    pub dns: Option<String>,
    #[arg(long)]
    pub mtu: Option<u16>,
    /// Bind the listener to one interface
    #[arg(long)]
    pub listen_interface: Option<String>,
    /// Read the private key from stdin (default: generated)
    #[arg(long)]
    pub private_key_stdin: bool,
}

#[derive(Debug, Args)]
pub struct WgTunnelEdit {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub address: Option<String>,
    #[arg(long)]
    pub address6: Option<String>,
    #[arg(long)]
    pub dns: Option<String>,
    #[arg(long)]
    pub mtu: Option<u16>,
    #[arg(long)]
    pub listen_interface: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum PeerCmd {
    /// List a tunnel's peers
    #[command(visible_alias = "ls")]
    List { tunnel: String },
    /// Add a peer
    Add {
        tunnel: String,
        #[arg(long)]
        name: String,
        /// The peer's public key (omit with --generate-key)
        #[arg(long, required_unless_present = "generate_key")]
        pubkey: Option<String>,
        /// Generate the peer's key pair on the firewall (then fetch its config)
        #[arg(long)]
        generate_key: bool,
        #[arg(long)]
        endpoint: Option<String>,
        /// Comma-separated allowed IPs ("auto" = next free tunnel address)
        #[arg(long, default_value = "auto")]
        allowed_ips: String,
        #[arg(long)]
        keepalive: Option<u16>,
    },
    /// Change a peer
    Edit {
        tunnel: String,
        peer: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        allowed_ips: Option<String>,
        #[arg(long)]
        keepalive: Option<u16>,
    },
    /// Delete a peer
    #[command(visible_alias = "rm")]
    Remove {
        tunnel: String,
        peer: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Print (or save) a peer's client config
    Config {
        tunnel: String,
        peer: String,
        /// Split tunnel: route only the tunnel networks (default: all traffic)
        #[arg(long)]
        split: bool,
        /// Write to a file (mode 0600) instead of stdout
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<std::path::PathBuf>,
    },
    /// Next free tunnel address for a new peer
    NextIp { tunnel: String },
}

#[derive(Debug, Subcommand)]
pub enum IpsecCmd {
    /// List tunnels
    #[command(visible_alias = "ls")]
    List,
    /// Show a tunnel (secrets redacted)
    Show { id: String },
    /// Add a tunnel
    Add(IpsecArgs),
    /// Change a tunnel (only the flags you pass; secrets kept unless given)
    Edit {
        id: String,
        #[command(flatten)]
        a: IpsecArgs,
    },
    /// Delete a tunnel
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Bring a tunnel up
    Start { id: String },
    /// Take a tunnel down
    Stop { id: String },
    /// Live status of one tunnel, or all
    Status { id: Option<String> },
    /// Legacy (read-only) security associations
    Sa,
}

#[derive(Debug, Args)]
pub struct IpsecArgs {
    #[arg(long)]
    pub name: Option<String>,
    /// Remote gateway address
    #[arg(long)]
    pub remote: Option<String>,
    /// Local address (default: any)
    #[arg(long)]
    pub local: Option<String>,
    /// Local traffic selectors, comma-separated CIDRs
    #[arg(long)]
    pub local_ts: Option<String>,
    /// Remote traffic selectors, comma-separated CIDRs
    #[arg(long)]
    pub remote_ts: Option<String>,
    /// psk or cert
    #[arg(long)]
    pub auth: Option<String>,
    /// Pre-shared key (prefer --psk-stdin)
    #[arg(long, conflicts_with = "psk_stdin")]
    pub psk: Option<String>,
    /// Read the pre-shared key from stdin
    #[arg(long)]
    pub psk_stdin: bool,
    #[arg(long)]
    pub local_id: Option<String>,
    #[arg(long)]
    pub remote_id: Option<String>,
    #[arg(long)]
    pub ike_proposal: Option<String>,
    #[arg(long)]
    pub esp_proposal: Option<String>,
    /// none, trap, start
    #[arg(long)]
    pub start_action: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub enabled: Option<bool>,
    /// Read the tunnel (JSON/YAML, API request shape) from a file, or -
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

impl IpsecArgs {
    fn fields(&self, io: &mut crate::cli::Io) -> anyhow::Result<Fields> {
        let psk = if self.psk_stdin {
            Some(prompt::read_line_raw(io)?.trim().to_string()).filter(|s| !s.is_empty())
        } else {
            self.psk.clone()
        };
        Ok(Fields::new()
            .opt("name", self.name.clone())
            .opt("remote_addr", self.remote.clone())
            .opt("local_addr", self.local.clone())
            .opt("local_ts", self.local_ts.as_deref().map(csv))
            .opt("remote_ts", self.remote_ts.as_deref().map(csv))
            .opt("auth_method", self.auth.clone())
            .opt("psk", psk)
            .opt("local_id", self.local_id.clone())
            .opt("remote_id", self.remote_id.clone())
            .opt("ike_proposal", self.ike_proposal.clone())
            .opt("esp_proposal", self.esp_proposal.clone())
            .opt("start_action", self.start_action.clone())
            .opt("enabled", self.enabled))
    }
}

const WG_COLS: &[Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("IFACE", "/interface"),
    col("PORT", "/listen_port"),
    col("ADDRESS", "/address"),
    col("STATUS", "/status"),
    wide("PUBLIC KEY", "/public_key"),
    wide("ADDRESS6", "/address6"),
];
const PEER_COLS: &[Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("ENDPOINT", "/endpoint"),
    col("ALLOWED IPS", "/allowed_ips"),
    col("KEEPALIVE", "/persistent_keepalive"),
    wide("PUBLIC KEY", "/public_key"),
];
const IPSEC_COLS: &[Col] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("REMOTE", "/remote_addr"),
    col("AUTH", "/auth_method"),
    col("LOCAL TS", "/local_ts"),
    col("REMOTE TS", "/remote_ts"),
    col("ENABLED", "/enabled"),
    wide("START", "/start_action"),
];
const IPSEC_STATUS_COLS: &[Col] = &[
    col("TUNNEL", "/tunnel_id"),
    col("CONN", "/conn_name"),
    col("IKE", "/ike_state"),
    col("UP (s)", "/established_secs"),
    col("REMOTE", "/remote_host"),
    col("CHILD SAS", "/_children"),
];

fn ipsec_status_row(s: &Value) -> Value {
    let mut r = s.clone();
    r["_children"] = json!(s["child_sas"].as_array().map_or(0, Vec::len));
    r
}

/// The API returns generated peer private keys and preshared keys in
/// listings; lists (incl. `-o json`) never print them — use
/// `vpn wg peers config` to hand a client its config.
fn redact_peer_secrets(v: &mut Value) {
    let rows = match v.get_mut("data") {
        Some(Value::Array(a)) => a,
        _ => match v {
            Value::Array(a) => a,
            _ => return,
        },
    };
    for p in rows {
        for k in ["client_private_key", "preshared_key"] {
            if p.get(k).is_some_and(|x| !x.is_null()) {
                p[k] = json!("REDACTED");
            }
        }
    }
}

/// Tunnel as returned → the PUT body (secrets stay "REDACTED" = keep).
fn wg_request(t: &Value) -> Value {
    json!({
        "name": t["name"], "listen_port": t["listen_port"], "address": t["address"],
        "address6": t["address6"], "dns": t["dns"], "mtu": t["mtu"],
        "listen_interface": t["listen_interface"], "split_routes": t["split_routes"],
    })
}

async fn find_in(
    client: &aifw_client::Client,
    path: &str,
    id: &str,
    what: &str,
) -> anyhow::Result<Value> {
    let all = client.get(path).await?;
    output::rows(&all)
        .into_iter()
        .find(|r| r["id"] == json!(id))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("{what} {id}")).into())
}

pub async fn run(ctx: &mut Ctx, cmd: VpnCmd) -> anyhow::Result<()> {
    match cmd {
        VpnCmd::Wg(c) => wg(ctx, c).await,
        VpnCmd::Ipsec(c) => ipsec(ctx, c).await,
        VpnCmd::List { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            list_all(ctx).await
        }
        VpnCmd::Remove { id, yes } => remove_any(ctx, &id, yes).await,
        VpnCmd::WgAdd {
            name,
            interface,
            port,
            address,
        } => {
            if interface != "wg0" {
                ctx.io
                    .eprintln("note: --interface is ignored; the API assigns the next free wgN");
            }
            wg(
                ctx,
                WgCmd::Add(WgTunnelArgs {
                    name,
                    port,
                    address,
                    address6: None,
                    dns: None,
                    mtu: None,
                    listen_interface: None,
                    private_key_stdin: false,
                }),
            )
            .await
        }
        VpnCmd::WgPeerAdd {
            tunnel,
            name,
            pubkey,
            endpoint,
            allowed_ips,
            keepalive,
        } => {
            wg(
                ctx,
                WgCmd::Peers(PeerCmd::Add {
                    tunnel,
                    name,
                    pubkey: Some(pubkey),
                    generate_key: false,
                    endpoint,
                    allowed_ips,
                    keepalive,
                }),
            )
            .await
        }
        VpnCmd::IpsecAdd {
            name,
            remote,
            psk,
            local_ts,
            remote_ts,
            local,
        } => {
            ipsec(
                ctx,
                IpsecCmd::Add(IpsecArgs {
                    name: Some(name),
                    remote: Some(remote),
                    local,
                    local_ts: Some(local_ts),
                    remote_ts: Some(remote_ts),
                    auth: Some("psk".into()),
                    psk: Some(psk),
                    psk_stdin: false,
                    local_id: None,
                    remote_id: None,
                    ike_proposal: None,
                    esp_proposal: None,
                    start_action: None,
                    enabled: None,
                    file: None,
                }),
            )
            .await
        }
        VpnCmd::IpsecStart { id } => ipsec(ctx, IpsecCmd::Start { id }).await,
        VpnCmd::IpsecStop { id } => ipsec(ctx, IpsecCmd::Stop { id }).await,
        VpnCmd::IpsecStatus { json } => {
            if json {
                // Pre-API output was the bare status array.
                let client = ctx.client()?;
                let v = client.get("/vpn/ipsec/status").await?;
                return ctx.legacy_json(&v, None);
            }
            ipsec(ctx, IpsecCmd::Status { id: None }).await
        }
    }
}

async fn list_all(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let wg = client.get("/vpn/wg").await?;
    let mut tunnels = Vec::new();
    for t in output::rows(&wg) {
        let id = t["id"].as_str().unwrap_or_default();
        let peers = client.get(&format!("/vpn/wg/{id}/peers")).await?;
        let mut t = t.clone();
        let mut peers = peers;
        redact_peer_secrets(&mut peers);
        t["peers"] = json!(output::rows(&peers));
        tunnels.push(t);
    }
    let ipsec = client.get("/vpn/ipsec/tunnels").await?;
    let sas = client.get("/vpn/ipsec").await?;
    if ctx.format().is_structured() {
        return ctx.raw(&json!({
            "wireguard": tunnels,
            "ipsec_tunnels": output::rows(&ipsec),
            "ipsec_legacy_sas": output::rows(&sas),
        }));
    }
    ctx.io.println("WireGuard tunnels:");
    if tunnels.is_empty() {
        ctx.io.println("  (none)");
    } else {
        let t = output::table(&tunnels.iter().collect::<Vec<_>>(), WG_COLS, ctx.format());
        ctx.io.println(&t);
        for t in &tunnels {
            let peers: Vec<&Value> = t["peers"]
                .as_array()
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            if !peers.is_empty() {
                ctx.io.println(&format!(
                    "\n  Peers of {}:",
                    t["name"].as_str().unwrap_or("?")
                ));
                let pt = output::table(&peers, PEER_COLS, ctx.format());
                ctx.io.println(&pt);
            }
        }
    }
    ctx.io.println("\nIPsec tunnels:");
    let ipsec_rows = output::rows(&ipsec);
    if ipsec_rows.is_empty() {
        ctx.io.println("  (none)");
    } else {
        let t = output::table(&ipsec_rows, IPSEC_COLS, ctx.format());
        ctx.io.println(&t);
    }
    let sa_rows = output::rows(&sas);
    if !sa_rows.is_empty() {
        ctx.io.println(&format!(
            "\nLegacy IPsec SAs: {} (see `aifw vpn ipsec sa`)",
            sa_rows.len()
        ));
    }
    Ok(())
}

/// The legacy generic remove: try each kind of VPN object in turn.
async fn remove_any(ctx: &mut Ctx, id: &str, yes: bool) -> anyhow::Result<()> {
    let client = ctx.client()?;
    ctx.confirm(&format!("Delete VPN object {id}?"), yes)?;
    let attempts = [
        (format!("/vpn/wg/{id}"), "WireGuard tunnel"),
        (format!("/vpn/ipsec/tunnels/{id}"), "IPsec tunnel"),
        (format!("/vpn/ipsec/{id}"), "IPsec SA"),
        // The handler ignores the tunnel id segment for peer deletes.
        (format!("/vpn/wg/-/peers/{id}"), "WireGuard peer"),
    ];
    for (path, what) in attempts {
        match client.delete(&path).await {
            Ok(_) => return ctx.message(&Value::Null, &format!("Removed {what} {id}")),
            Err(
                aifw_client::ClientError::NotFound(_) | aifw_client::ClientError::Validation(_),
            ) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(aifw_client::ClientError::NotFound(format!("VPN resource {id}")).into())
}

async fn wg(ctx: &mut Ctx, cmd: WgCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        WgCmd::List => {
            let v = client.get("/vpn/wg").await?;
            ctx.list(&v, WG_COLS)
        }
        WgCmd::Add(a) => {
            let private_key = if a.private_key_stdin {
                Some(prompt::read_line_raw(&mut ctx.io)?.trim().to_string())
                    .filter(|s| !s.is_empty())
            } else {
                None
            };
            let body = Fields::new()
                .set("name", a.name)
                .set("listen_port", a.port)
                .set("address", a.address)
                .opt("address6", a.address6)
                .opt("dns", a.dns)
                .opt("mtu", a.mtu)
                .opt("listen_interface", a.listen_interface)
                .opt("private_key", private_key)
                .into_value();
            let v = client.post("/vpn/wg", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let t = output::item(&v);
            ctx.io.println(&format!(
                "Added WireGuard tunnel {} on {} (public key {})",
                t["id"].as_str().unwrap_or("?"),
                t["interface"].as_str().unwrap_or("?"),
                t["public_key"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        WgCmd::Edit { id, a } => {
            let cur = wg_request(&find_in(&client, "/vpn/wg", &id, "WireGuard tunnel").await?);
            let flags = Fields::new()
                .opt("name", a.name)
                .opt("listen_port", a.port)
                .opt("address", a.address)
                .opt("address6", a.address6)
                .opt("dns", a.dns)
                .opt("mtu", a.mtu)
                .opt("listen_interface", a.listen_interface);
            let body = body::for_update(&mut ctx.io, cur, None, flags)?;
            let v = client.put(&format!("/vpn/wg/{id}"), &body).await?;
            ctx.message(&v, &format!("Updated WireGuard tunnel {id}"))
        }
        WgCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete WireGuard tunnel {id} and its peers?"), yes)?;
            let v = client.delete(&format!("/vpn/wg/{id}")).await?;
            ctx.message(&v, &format!("Removed WireGuard tunnel {id}"))
        }
        WgCmd::Start { id } => {
            let v = client.post_empty(&format!("/vpn/wg/{id}/start")).await?;
            ctx.message(&v, &format!("Started {id}"))
        }
        WgCmd::Stop { id } => {
            let v = client.post_empty(&format!("/vpn/wg/{id}/stop")).await?;
            ctx.message(&v, &format!("Stopped {id}"))
        }
        WgCmd::Status { id } => {
            let v = client.get(&format!("/vpn/wg/{id}/status")).await?;
            ctx.raw(&v)
        }
        WgCmd::Peers(p) => peers(ctx, &client, p).await,
    }
}

async fn peers(ctx: &mut Ctx, client: &aifw_client::Client, cmd: PeerCmd) -> anyhow::Result<()> {
    match cmd {
        PeerCmd::List { tunnel } => {
            let mut v = client.get(&format!("/vpn/wg/{tunnel}/peers")).await?;
            redact_peer_secrets(&mut v);
            ctx.list(&v, PEER_COLS)
        }
        PeerCmd::Add {
            tunnel,
            name,
            pubkey,
            generate_key,
            endpoint,
            allowed_ips,
            keepalive,
        } => {
            let allowed = if allowed_ips == "auto" {
                String::new()
            } else {
                allowed_ips
            };
            let body = Fields::new()
                .set("name", name)
                .opt("public_key", pubkey)
                .flag("auto_generate_key", generate_key, true)
                .opt("endpoint", endpoint)
                .set("allowed_ips", allowed)
                .opt("keepalive", keepalive)
                .into_value();
            let v = client
                .post(&format!("/vpn/wg/{tunnel}/peers"), &body)
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let p = output::item(&v);
            let pid = p["id"].as_str().unwrap_or("?");
            ctx.io.println(&format!(
                "Added peer {pid} ({})",
                output::cell(p.get("allowed_ips"))
            ));
            if generate_key {
                ctx.io.eprintln(&format!(
                    "Fetch its config with: aifw vpn wg peers config {tunnel} {pid}"
                ));
            }
            Ok(())
        }
        PeerCmd::Edit {
            tunnel,
            peer,
            name,
            endpoint,
            allowed_ips,
            keepalive,
        } => {
            let flags = Fields::new()
                .opt("name", name)
                .opt("endpoint", endpoint)
                .opt("allowed_ips", allowed_ips)
                .opt("keepalive", keepalive);
            if flags.is_empty() {
                return Err(CliError::Usage("nothing to change: pass a field flag".into()).into());
            }
            let v = client
                .put(
                    &format!("/vpn/wg/{tunnel}/peers/{peer}"),
                    &flags.into_value(),
                )
                .await?;
            ctx.message(&v, &format!("Updated peer {peer}"))
        }
        PeerCmd::Remove { tunnel, peer, yes } => {
            ctx.confirm(&format!("Delete peer {peer}?"), yes)?;
            let v = client
                .delete(&format!("/vpn/wg/{tunnel}/peers/{peer}"))
                .await?;
            ctx.message(&v, &format!("Removed peer {peer}"))
        }
        PeerCmd::Config {
            tunnel,
            peer,
            split,
            output_file,
        } => {
            let bytes = client
                .get_bytes(&format!("/vpn/wg/{tunnel}/peers/{peer}/config"))
                .await?;
            // The API returns both variants: {full_tunnel, split_tunnel}.
            let key = if split { "split_tunnel" } else { "full_tunnel" };
            let text = match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) => crate::cli::output::item(&v)[key]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("unexpected peer config response (no {key})"))?,
                Err(_) => String::from_utf8_lossy(&bytes).into_owned(),
            };
            match output_file {
                Some(path) => {
                    crate::cli::config::write_atomic(&path, text.as_bytes(), 0o600)?;
                    ctx.io.eprintln(&format!("Wrote {} (0600)", path.display()));
                }
                None => ctx.io.println(text.trim_end()),
            }
            Ok(())
        }
        PeerCmd::NextIp { tunnel } => {
            let v = client
                .get(&format!("/vpn/wg/{tunnel}/peers/next-ip"))
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let ip = v["data"]
                .as_str()
                .or(v["ip"].as_str())
                .or(v["next_ip"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string());
            ctx.io.println(&ip);
            Ok(())
        }
    }
}

async fn ipsec(ctx: &mut Ctx, cmd: IpsecCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        IpsecCmd::List => {
            let v = client.get("/vpn/ipsec/tunnels").await?;
            ctx.list(&v, IPSEC_COLS)
        }
        IpsecCmd::Show { id } => {
            let v = client.get(&format!("/vpn/ipsec/tunnels/{id}")).await?;
            ctx.raw(output::item(&v))
        }
        IpsecCmd::Add(a) => {
            let flags = a.fields(&mut ctx.io)?;
            let mut body = body::for_create(&mut ctx.io, a.file.as_deref(), flags)?;
            for k in ["name", "remote_addr", "local_ts", "remote_ts"] {
                if body.get(k).is_none_or(Value::is_null) {
                    return Err(CliError::Usage(format!(
                        "--{} is required",
                        match k {
                            "remote_addr" => "remote",
                            "local_ts" => "local-ts",
                            "remote_ts" => "remote-ts",
                            o => o,
                        }
                    ))
                    .into());
                }
            }
            if body.get("auth_method").is_none_or(Value::is_null) {
                body["auth_method"] = json!("psk");
            }
            let v = client.post("/vpn/ipsec/tunnels", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added IPsec tunnel {}",
                output::item(&v)["id"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        IpsecCmd::Edit { id, a } => {
            let cur = client.get(&format!("/vpn/ipsec/tunnels/{id}")).await?;
            let mut cur = output::item(&cur).clone();
            if let Some(o) = cur.as_object_mut() {
                for k in ["id", "created_at", "updated_at"] {
                    o.remove(k);
                }
            }
            let flags = a.fields(&mut ctx.io)?;
            let body = body::for_update(&mut ctx.io, cur, a.file.as_deref(), flags)?;
            let v = client
                .put(&format!("/vpn/ipsec/tunnels/{id}"), &body)
                .await?;
            ctx.message(&v, &format!("Updated IPsec tunnel {id}"))
        }
        IpsecCmd::Remove { id, yes } => {
            ctx.confirm(&format!("Delete IPsec tunnel {id}?"), yes)?;
            let v = client.delete(&format!("/vpn/ipsec/tunnels/{id}")).await?;
            ctx.message(&v, &format!("Removed IPsec tunnel {id}"))
        }
        IpsecCmd::Start { id } => {
            let v = client
                .post_empty(&format!("/vpn/ipsec/tunnels/{id}/start"))
                .await?;
            ctx.message(&v, &format!("Started IPsec tunnel {id}"))
        }
        IpsecCmd::Stop { id } => {
            let v = client
                .post_empty(&format!("/vpn/ipsec/tunnels/{id}/stop"))
                .await?;
            ctx.message(&v, &format!("Stopped IPsec tunnel {id}"))
        }
        IpsecCmd::Status { id } => {
            let path = match &id {
                Some(i) => format!("/vpn/ipsec/tunnels/{i}/status"),
                None => "/vpn/ipsec/status".into(),
            };
            let v = client.get(&path).await?;
            if id.is_some() {
                return ctx.raw(&v);
            }
            ctx.list_mapped(&v, IPSEC_STATUS_COLS, ipsec_status_row)
        }
        IpsecCmd::Sa => {
            let v = client.get("/vpn/ipsec").await?;
            ctx.raw(&v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_secrets_are_redacted() {
        let mut v =
            json!({"data": [{"name": "p", "client_private_key": "secret", "preshared_key": null}]});
        redact_peer_secrets(&mut v);
        assert_eq!(v["data"][0]["client_private_key"], "REDACTED");
        assert!(v["data"][0]["preshared_key"].is_null());
    }

    #[test]
    fn csv_split() {
        assert_eq!(
            csv("10.0.0.0/8, ,192.168.0.0/16"),
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
        assert!(csv("").is_empty());
    }

    #[test]
    fn wg_request_carries_settings() {
        let t = json!({"id": "x", "name": "a", "listen_port": 51820, "address": "10.8.0.1/24",
                       "mtu": 1420, "private_key": "REDACTED", "status": "up"});
        let r = wg_request(&t);
        assert_eq!(r["mtu"], 1420);
        assert!(r.get("private_key").is_none(), "never sends the key back");
        assert!(r.get("status").is_none());
    }
}
