mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "aifw", about = "AiFw — AI-Powered Firewall for FreeBSD", version)]
struct Cli {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db", global = true)]
    db: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize AiFw configuration and database
    Init {
        /// Path to create the database
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Manage firewall rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Manage NAT rules
    Nat {
        #[command(subcommand)]
        action: NatAction,
    },
    /// Manage traffic queues
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// Manage rate limiting rules
    Ratelimit {
        #[command(subcommand)]
        action: RateLimitAction,
    },
    /// Manage Geo-IP filtering
    Geoip {
        #[command(subcommand)]
        action: GeoIpCmd,
    },
    /// Manage VPN tunnels
    Vpn {
        #[command(subcommand)]
        action: VpnAction,
    },
    /// Show firewall status
    Status,
    /// Reload rules from database and apply to pf
    Reload,
}

#[derive(Subcommand)]
enum GeoIpCmd {
    /// Add a country block/allow rule
    Add {
        /// Country code (ISO 3166-1 alpha-2, e.g., CN, RU, US)
        #[arg(long)]
        country: String,
        /// Action: block or allow
        #[arg(long)]
        action: String,
        /// Rule label
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a geo-ip rule by ID
    Remove { id: String },
    /// List all geo-ip rules
    List {
        #[arg(long)]
        json: bool,
    },
    /// Lookup an IP address
    Lookup {
        /// IP address to look up
        ip: String,
    },
}

#[derive(Subcommand)]
enum VpnAction {
    /// Add a WireGuard tunnel
    WgAdd {
        /// Tunnel name
        #[arg(long)]
        name: String,
        /// WireGuard interface (e.g., wg0)
        #[arg(long, default_value = "wg0")]
        interface: String,
        /// Listen port
        #[arg(long, default_value = "51820")]
        port: u16,
        /// Tunnel address (e.g., 10.0.0.1/24)
        #[arg(long)]
        address: String,
    },
    /// Add a peer to a WireGuard tunnel
    WgPeerAdd {
        /// Tunnel ID
        #[arg(long)]
        tunnel: String,
        /// Peer name
        #[arg(long)]
        name: String,
        /// Peer public key
        #[arg(long)]
        pubkey: String,
        /// Peer endpoint (host:port)
        #[arg(long)]
        endpoint: Option<String>,
        /// Allowed IPs (comma-separated)
        #[arg(long, default_value = "0.0.0.0/0")]
        allowed_ips: String,
        /// Persistent keepalive interval
        #[arg(long)]
        keepalive: Option<u16>,
    },
    /// Add an IPsec SA
    IpsecAdd {
        /// SA name
        #[arg(long)]
        name: String,
        /// Source address
        #[arg(long)]
        src: String,
        /// Destination address
        #[arg(long)]
        dst: String,
        /// Protocol: esp, ah, esp+ah
        #[arg(long, default_value = "esp")]
        proto: String,
        /// Mode: tunnel, transport
        #[arg(long, default_value = "tunnel")]
        mode: String,
    },
    /// Remove a VPN tunnel or SA by ID
    Remove {
        /// Resource ID
        id: String,
    },
    /// List all VPN tunnels and SAs
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum QueueAction {
    /// Add a traffic queue
    Add {
        /// Queue name
        #[arg(long)]
        name: String,

        /// Network interface
        #[arg(long)]
        interface: String,

        /// Queue type: codel, hfsc, priq
        #[arg(long, name = "type", default_value = "codel")]
        queue_type: String,

        /// Bandwidth (e.g., 100Mb, 1Gb, 500Kb)
        #[arg(long)]
        bandwidth: String,

        /// Traffic class: voip, interactive, default, bulk
        #[arg(long, default_value = "default")]
        class: String,

        /// Bandwidth percentage of parent (1-100)
        #[arg(long)]
        pct: Option<u8>,

        /// Mark as default queue
        #[arg(long)]
        default: bool,
    },
    /// Remove a queue by ID
    Remove { id: String },
    /// List all queues
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RateLimitAction {
    /// Add a rate limit rule
    Add {
        /// Rule name
        #[arg(long)]
        name: String,

        /// Protocol: tcp, udp, any
        #[arg(long, default_value = "tcp")]
        proto: String,

        /// Max connections per source IP
        #[arg(long)]
        max_conn: u32,

        /// Time window in seconds
        #[arg(long, default_value = "60")]
        window: u32,

        /// Overload table name
        #[arg(long)]
        table: String,

        /// Destination port
        #[arg(long)]
        dst_port: Option<String>,

        /// Network interface
        #[arg(long)]
        interface: Option<String>,

        /// Don't flush states on overload
        #[arg(long)]
        no_flush: bool,
    },
    /// Remove a rate limit rule by ID
    Remove { id: String },
    /// List all rate limit rules
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum NatAction {
    /// Add a NAT rule
    Add {
        /// NAT type: snat, dnat, masquerade, binat, nat64, nat46
        #[arg(long, name = "type")]
        nat_type: String,

        /// Network interface (required)
        #[arg(long)]
        interface: String,

        /// Protocol: tcp, udp, any
        #[arg(long, default_value = "any")]
        proto: String,

        /// Source address
        #[arg(long, default_value = "any")]
        src: String,

        /// Source port
        #[arg(long)]
        src_port: Option<String>,

        /// Destination address
        #[arg(long, default_value = "any")]
        dst: String,

        /// Destination port
        #[arg(long)]
        dst_port: Option<String>,

        /// Redirect target address
        #[arg(long)]
        redirect: String,

        /// Redirect target port
        #[arg(long)]
        redirect_port: Option<String>,

        /// Rule label
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a NAT rule by ID
    Remove {
        /// Rule UUID
        id: String,
    },
    /// List all NAT rules
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// Add a new rule
    Add {
        /// Action: pass, block, block-drop, block-return
        #[arg(long)]
        action: String,

        /// Direction: in, out, any
        #[arg(long, default_value = "any")]
        direction: String,

        /// Protocol: tcp, udp, icmp, icmp6, any
        #[arg(long, default_value = "any")]
        proto: String,

        /// Source address (IP, CIDR, "any", or <table>)
        #[arg(long, default_value = "any")]
        src: String,

        /// Source port or port range (e.g., 80, 8000:9000)
        #[arg(long)]
        src_port: Option<String>,

        /// Destination address
        #[arg(long, default_value = "any")]
        dst: String,

        /// Destination port or port range
        #[arg(long)]
        dst_port: Option<String>,

        /// Network interface
        #[arg(long)]
        interface: Option<String>,

        /// Rule priority (0-10000, lower = first)
        #[arg(long, default_value = "100")]
        priority: i32,

        /// Enable logging
        #[arg(long)]
        log: bool,

        /// Rule label
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a rule by ID
    Remove {
        /// Rule UUID
        id: String,
    },
    /// List all rules
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            commands::init(path.as_deref().unwrap_or(&cli.db)).await?;
        }
        Commands::Rules { action } => match action {
            RulesAction::Add {
                action,
                direction,
                proto,
                src,
                src_port,
                dst,
                dst_port,
                interface,
                priority,
                log,
                label,
            } => {
                commands::rules_add(
                    &cli.db, &action, &direction, &proto, &src, src_port.as_deref(),
                    &dst, dst_port.as_deref(), interface.as_deref(), priority, log,
                    label.as_deref(),
                )
                .await?;
            }
            RulesAction::Remove { id } => {
                commands::rules_remove(&cli.db, &id).await?;
            }
            RulesAction::List { json } => {
                commands::rules_list(&cli.db, json).await?;
            }
        },
        Commands::Nat { action } => match action {
            NatAction::Add {
                nat_type,
                interface,
                proto,
                src,
                src_port,
                dst,
                dst_port,
                redirect,
                redirect_port,
                label,
            } => {
                commands::nat_add(
                    &cli.db,
                    &nat_type,
                    &interface,
                    &proto,
                    &src,
                    src_port.as_deref(),
                    &dst,
                    dst_port.as_deref(),
                    &redirect,
                    redirect_port.as_deref(),
                    label.as_deref(),
                )
                .await?;
            }
            NatAction::Remove { id } => {
                commands::nat_remove(&cli.db, &id).await?;
            }
            NatAction::List { json } => {
                commands::nat_list(&cli.db, json).await?;
            }
        },
        Commands::Queue { action } => match action {
            QueueAction::Add {
                name,
                interface,
                queue_type,
                bandwidth,
                class,
                pct,
                default,
            } => {
                commands::queue_add(
                    &cli.db, &name, &interface, &queue_type, &bandwidth, &class, pct, default,
                )
                .await?;
            }
            QueueAction::Remove { id } => {
                commands::queue_remove(&cli.db, &id).await?;
            }
            QueueAction::List { json } => {
                commands::queue_list(&cli.db, json).await?;
            }
        },
        Commands::Ratelimit { action } => match action {
            RateLimitAction::Add {
                name,
                proto,
                max_conn,
                window,
                table,
                dst_port,
                interface,
                no_flush,
            } => {
                commands::ratelimit_add(
                    &cli.db,
                    &name,
                    &proto,
                    max_conn,
                    window,
                    &table,
                    dst_port.as_deref(),
                    interface.as_deref(),
                    !no_flush,
                )
                .await?;
            }
            RateLimitAction::Remove { id } => {
                commands::ratelimit_remove(&cli.db, &id).await?;
            }
            RateLimitAction::List { json } => {
                commands::ratelimit_list(&cli.db, json).await?;
            }
        },
        Commands::Geoip { action } => match action {
            GeoIpCmd::Add { country, action, label } => {
                commands::geoip_add(&cli.db, &country, &action, label.as_deref()).await?;
            }
            GeoIpCmd::Remove { id } => {
                commands::geoip_remove(&cli.db, &id).await?;
            }
            GeoIpCmd::List { json } => {
                commands::geoip_list(&cli.db, json).await?;
            }
            GeoIpCmd::Lookup { ip } => {
                commands::geoip_lookup(&cli.db, &ip).await?;
            }
        },
        Commands::Vpn { action } => match action {
            VpnAction::WgAdd { name, interface, port, address } => {
                commands::vpn_wg_add(&cli.db, &name, &interface, port, &address).await?;
            }
            VpnAction::WgPeerAdd { tunnel, name, pubkey, endpoint, allowed_ips, keepalive } => {
                commands::vpn_wg_peer_add(
                    &cli.db, &tunnel, &name, &pubkey, endpoint.as_deref(),
                    &allowed_ips, keepalive,
                ).await?;
            }
            VpnAction::IpsecAdd { name, src, dst, proto, mode } => {
                commands::vpn_ipsec_add(&cli.db, &name, &src, &dst, &proto, &mode).await?;
            }
            VpnAction::Remove { id } => {
                commands::vpn_remove(&cli.db, &id).await?;
            }
            VpnAction::List { json } => {
                commands::vpn_list(&cli.db, json).await?;
            }
        },
        Commands::Status => {
            commands::status(&cli.db).await?;
        }
        Commands::Reload => {
            commands::reload(&cli.db).await?;
        }
    }

    Ok(())
}
