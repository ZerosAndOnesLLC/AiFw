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
    /// Manage versioned configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage static routes
    Routes {
        #[command(subcommand)]
        action: RoutesAction,
    },
    /// Manage DNS nameservers
    Dns {
        #[command(subcommand)]
        action: DnsAction,
    },
    /// Manage DHCP server
    Dhcp {
        #[command(subcommand)]
        action: DhcpAction,
    },
    /// Manage users
    Users {
        #[command(subcommand)]
        action: UsersAction,
    },
    /// Manage AiFw and OS updates
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
    /// Show network interfaces
    Interfaces,
    /// Show firewall status
    Status,
    /// Reload rules from database and apply to pf
    Reload,
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Check for AiFw firmware update from GitHub
    Check,
    /// Download and install AiFw firmware update
    Install,
    /// Rollback to previous AiFw firmware version
    Rollback,
    /// Check for OS and package updates
    OsCheck,
    /// Install OS and package updates
    OsInstall,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current active config
    Show,
    /// Export current config to stdout as JSON
    Export,
    /// Import config from a JSON file
    Import {
        /// Path to JSON config file
        file: String,
    },
    /// Show config version history
    History {
        /// Number of versions to show
        #[arg(long, default_value = "20")]
        limit: i64,
    },
    /// Rollback to a specific config version
    Rollback {
        /// Version number to rollback to
        version: i64,
    },
    /// Diff two config versions
    Diff {
        /// First version
        v1: i64,
        /// Second version
        v2: i64,
    },
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
enum RoutesAction {
    /// Add a static route
    Add {
        /// Destination network (CIDR, e.g., 10.0.0.0/8 or "default")
        #[arg(long)]
        dest: String,
        /// Gateway IP
        #[arg(long)]
        gateway: String,
        /// Network interface (optional)
        #[arg(long)]
        interface: Option<String>,
        /// Route metric
        #[arg(long, default_value = "0")]
        metric: i32,
        /// Description
        #[arg(long)]
        desc: Option<String>,
    },
    /// Remove a static route by ID
    Remove { id: String },
    /// List all static routes
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show system routing table (netstat -rn)
    System,
}

#[derive(Subcommand)]
enum DnsAction {
    /// Show current DNS servers
    List,
    /// Set DNS servers (replaces all)
    Set {
        /// DNS servers (comma-separated)
        servers: String,
    },
}

#[derive(Subcommand)]
enum UsersAction {
    /// List all users
    List {
        #[arg(long)]
        json: bool,
    },
    /// Add a new user
    Add {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "admin")]
        role: String,
    },
    /// Remove a user by ID
    Remove { id: String },
    /// Disable a user
    Disable { id: String },
    /// Enable a user
    Enable { id: String },
}

#[derive(Subcommand)]
enum DhcpAction {
    /// Show DHCP server status
    Status,
    /// Start DHCP server
    Start,
    /// Stop DHCP server
    Stop,
    /// Restart DHCP server
    Restart,
    /// List DHCP subnets
    Subnets {
        #[arg(long)]
        json: bool,
    },
    /// Add a DHCP subnet
    SubnetAdd {
        #[arg(long)]
        network: String,
        #[arg(long)]
        pool_start: String,
        #[arg(long)]
        pool_end: String,
        #[arg(long)]
        gateway: String,
        #[arg(long)]
        dns: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        lease_time: Option<u32>,
        #[arg(long)]
        desc: Option<String>,
    },
    /// Remove a DHCP subnet
    SubnetRemove { id: String },
    /// List DHCP reservations (static leases)
    Reservations {
        #[arg(long)]
        json: bool,
    },
    /// Add a DHCP reservation
    ReservationAdd {
        #[arg(long)]
        mac: String,
        #[arg(long)]
        ip: String,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        subnet: Option<String>,
        #[arg(long)]
        desc: Option<String>,
    },
    /// Remove a DHCP reservation
    ReservationRemove { id: String },
    /// Show active DHCP leases
    Leases {
        #[arg(long)]
        json: bool,
    },
    /// Apply DHCP config (write + restart Kea)
    Apply,
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
        Commands::Config { action } => match action {
            ConfigAction::Show => commands::config_show(&cli.db).await?,
            ConfigAction::Export => commands::config_export(&cli.db).await?,
            ConfigAction::Import { file } => commands::config_import(&cli.db, &file).await?,
            ConfigAction::History { limit } => commands::config_history(&cli.db, limit).await?,
            ConfigAction::Rollback { version } => commands::config_rollback(&cli.db, version).await?,
            ConfigAction::Diff { v1, v2 } => commands::config_diff(&cli.db, v1, v2).await?,
        },
        Commands::Routes { action } => match action {
            RoutesAction::Add { dest, gateway, interface, metric, desc } => {
                commands::routes_add(&cli.db, &dest, &gateway, interface.as_deref(), metric, desc.as_deref()).await?;
            }
            RoutesAction::Remove { id } => {
                commands::routes_remove(&cli.db, &id).await?;
            }
            RoutesAction::List { json } => {
                commands::routes_list(&cli.db, json).await?;
            }
            RoutesAction::System => {
                commands::routes_system().await?;
            }
        },
        Commands::Dhcp { action } => match action {
            DhcpAction::Status => commands::dhcp_status(&cli.db).await?,
            DhcpAction::Start => { let _ = std::process::Command::new("service").args(["kea", "start"]).output(); println!("DHCP started"); }
            DhcpAction::Stop => { let _ = std::process::Command::new("service").args(["kea", "stop"]).output(); println!("DHCP stopped"); }
            DhcpAction::Restart => { let _ = std::process::Command::new("service").args(["kea", "restart"]).output(); println!("DHCP restarted"); }
            DhcpAction::Subnets { json } => commands::dhcp_subnets(&cli.db, json).await?,
            DhcpAction::SubnetAdd { network, pool_start, pool_end, gateway, dns, domain, lease_time, desc } => {
                commands::dhcp_subnet_add(&cli.db, &network, &pool_start, &pool_end, &gateway, dns.as_deref(), domain.as_deref(), lease_time, desc.as_deref()).await?;
            }
            DhcpAction::SubnetRemove { id } => commands::dhcp_subnet_remove(&cli.db, &id).await?,
            DhcpAction::Reservations { json } => commands::dhcp_reservations(&cli.db, json).await?,
            DhcpAction::ReservationAdd { mac, ip, hostname, subnet, desc } => {
                commands::dhcp_reservation_add(&cli.db, &mac, &ip, hostname.as_deref(), subnet.as_deref(), desc.as_deref()).await?;
            }
            DhcpAction::ReservationRemove { id } => commands::dhcp_reservation_remove(&cli.db, &id).await?,
            DhcpAction::Leases { json } => commands::dhcp_leases(json).await?,
            DhcpAction::Apply => commands::dhcp_apply(&cli.db).await?,
        },
        Commands::Dns { action } => match action {
            DnsAction::List => {
                commands::dns_list().await?;
            }
            DnsAction::Set { servers } => {
                commands::dns_set(&servers).await?;
            }
        },
        Commands::Users { action } => match action {
            UsersAction::List { json } => {
                commands::users_list(&cli.db, json).await?;
            }
            UsersAction::Add { username, password, role } => {
                commands::users_add(&cli.db, &username, &password, &role).await?;
            }
            UsersAction::Remove { id } => {
                commands::users_remove(&cli.db, &id).await?;
            }
            UsersAction::Disable { id } => {
                commands::users_set_enabled(&cli.db, &id, false).await?;
            }
            UsersAction::Enable { id } => {
                commands::users_set_enabled(&cli.db, &id, true).await?;
            }
        },
        Commands::Update { action } => match action {
            UpdateAction::Check => commands::update_check().await?,
            UpdateAction::Install => commands::update_install().await?,
            UpdateAction::Rollback => commands::update_rollback().await?,
            UpdateAction::OsCheck => commands::update_os_check().await?,
            UpdateAction::OsInstall => commands::update_os_install().await?,
        },
        Commands::Interfaces => {
            commands::interfaces_list().await?;
        }
        Commands::Status => {
            commands::status(&cli.db).await?;
        }
        Commands::Reload => {
            commands::reload(&cli.db).await?;
        }
    }

    Ok(())
}
