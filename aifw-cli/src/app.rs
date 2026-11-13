//! `aifw` command tree and dispatch.

use crate::cli::{Ctx, Env, Io, exit};
use crate::commands;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aifw",
    about = "AiFw — AI-Powered Firewall for FreeBSD",
    long_about = "AiFw — AI-Powered Firewall for FreeBSD.\n\n\
        Talks to the AiFw API: on the appliance it works as root with no setup; \
        from anywhere else, `aifw login https://<firewall>:8080` first.\n\n\
        Exit codes: 0 ok, 1 error, 2 usage, 3 not authenticated, 4 forbidden, \
        5 not found, 6 rejected by validation, 7 API unreachable/TLS, \
        8 some contexts failed, 9 change rolled back.",
    version
)]
struct Cli {
    /// Path to the database file (only used by `aifw local` and commands
    /// not yet moved to the API)
    #[arg(long, default_value = "/var/db/aifw/aifw.db", global = true)]
    db: PathBuf,

    #[command(flatten)]
    global: crate::cli::global::GlobalArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Log in to an appliance and save it as a context
    Login(commands::session::LoginArgs),
    /// Log out of the current context (revokes the session)
    Logout,
    /// Show who you are on the current context
    Whoami,
    /// Manage saved appliances (contexts)
    Context {
        #[command(subcommand)]
        action: commands::context::ContextCmd,
    },
    /// Show staged changes not yet applied to pf
    Pending {
        /// Keep streaming changes as they happen
        #[arg(long)]
        watch: bool,
    },
    /// Apply staged changes to pf
    Apply,
    /// Commit-confirm: arm a rollback window before risky changes, then accept
    Confirm {
        #[command(subcommand)]
        action: Option<commands::staging::ConfirmCmd>,
    },
    /// Break-glass operations that work without the API (root, on the appliance)
    Local {
        #[command(subcommand)]
        action: commands::local::LocalCmd,
    },
    /// Initialize AiFw configuration and database
    Init {
        /// Path to create the database
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Manage firewall rules
    Rules {
        #[command(subcommand)]
        action: commands::rules::RulesCmd,
    },
    /// Manage NAT rules
    Nat {
        #[command(subcommand)]
        action: commands::nat::NatCmd,
    },
    /// Manage the IDS engine (alerts, retention)
    Ids {
        #[command(subcommand)]
        action: commands::ids::IdsCmd,
    },
    /// Manage remote syslog forwarding
    Syslog {
        #[command(subcommand)]
        action: commands::logging::SyslogCmd,
    },
    /// View and configure built-in plugins (threat feeds, notifier, …)
    Plugins {
        #[command(subcommand)]
        action: commands::plugins::PluginsCmd,
    },
    /// Manage rotation of AiFw service logs (newsyslog policy)
    Logrotate {
        #[command(subcommand)]
        action: commands::logging::LogrotateCmd,
    },
    /// Manage traffic queues
    Queue {
        #[command(subcommand)]
        action: commands::shaping::QueueCmd,
    },
    /// Manage rate limiting rules (local: root on the appliance; no API yet)
    Ratelimit {
        #[command(subcommand)]
        action: RateLimitAction,
    },
    /// Manage Geo-IP filtering
    Geoip {
        #[command(subcommand)]
        action: commands::geoip::GeoipCmd,
    },
    /// Manage VPN tunnels
    Vpn {
        #[command(subcommand)]
        action: commands::vpn::VpnCmd,
    },
    /// Manage versioned configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Manage static routes
    Routes {
        #[command(subcommand)]
        action: commands::routes::RoutesCmd,
    },
    /// Manage DNS nameservers
    Dns {
        #[command(subcommand)]
        action: commands::dns::DnsCmd,
    },
    /// Manage DHCP server
    Dhcp {
        #[command(subcommand)]
        action: DhcpAction,
    },
    /// Manage users
    Users {
        #[command(subcommand)]
        action: commands::users::UsersCmd,
    },
    /// Manage the reverse proxy (TrafficCop)
    ReverseProxy {
        #[command(subcommand)]
        action: ReverseProxyAction,
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
    /// Apply staged changes and re-apply queues (via the API)
    Reload {
        /// Load straight from the database into pf, without the API
        /// (break-glass; root on the appliance)
        #[arg(long)]
        local: bool,
    },
    /// (Local, root) Reconcile kernel pf state and rc.conf against db/pf.conf.aifw.
    /// Reloads pf.conf.aifw if anchor hooks are missing and fixes rc.conf
    /// DNS backend flags if they disagree with the db.
    Reconcile,
    /// Multi-WAN: routing instances, gateways, groups, policies, leaks
    Multiwan {
        #[command(subcommand)]
        action: MultiwanAction,
    },
    /// Cluster / HA operations
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
}

#[derive(Subcommand)]
enum MultiwanAction {
    /// List routing instances (FIBs)
    Instances,
    /// List gateways with live health state
    Gateways,
    /// List gateway groups
    Groups,
    /// List policy-routing rules
    Policies,
    /// List route leaks
    Leaks,
    /// Show live pf flows with iface/FIB
    Flows,
    /// Show current pf state table count
    FibInfo,
    /// Recompile and apply all multi-WAN pf anchors
    Apply,
    /// Seed management-escape leaks for non-default instances
    SeedMgmt,
    /// Force a manual probe outcome for a gateway (for testing)
    Probe {
        /// Gateway UUID
        id: String,
        /// "ok" or "fail"
        #[arg(default_value = "ok")]
        outcome: String,
    },
    /// Export full multi-WAN config as JSON
    Export,
    /// Import multi-WAN config from a JSON file
    Import { file: String },
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Show this node's cluster status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// CARP VIP operations
    Carp {
        #[command(subcommand)]
        action: CarpAction,
    },
    /// pfsync configuration
    Pfsync {
        #[command(subcommand)]
        action: PfsyncAction,
    },
    /// Cluster nodes
    Nodes {
        #[command(subcommand)]
        action: NodesAction,
    },
    /// Health checks
    Health {
        #[command(subcommand)]
        action: HealthAction,
    },
    /// Clear this node's operator demotion and maintenance mode; with
    /// preemption on, it retakes MASTER if its advskew beats the peer's
    Promote,
    /// Demote this node so the peer takes the VIPs (until promote or reboot)
    Demote,
    /// Persistent CARP maintenance mode (survives reboot)
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },
    /// Force a snapshot pull from peer
    Sync,
    /// Run local-side verification checks. Exits 0 on healthy, non-zero on failure.
    Verify {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum MaintenanceAction {
    /// Enter maintenance: stay BACKUP, across reboots, until turned off
    On,
    /// Leave maintenance mode
    Off,
}

#[derive(Subcommand)]
enum CarpAction {
    /// List CARP VIPs
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
        #[arg(long)]
        password: String,
    },
    /// Remove a CARP VIP
    Remove { id: String },
}

#[derive(Subcommand)]
enum PfsyncAction {
    /// Get pfsync configuration
    Get,
    /// Set pfsync configuration
    Set {
        #[arg(long)]
        sync_interface: String,
        #[arg(long)]
        sync_peer: Option<String>,
        #[arg(long, default_value_t = true)]
        defer: bool,
        #[arg(long, default_value = "conservative")]
        latency_profile: String,
        #[arg(long, default_value_t = false)]
        dhcp_link: bool,
        /// Legacy (#486), ignored: since #712 WireGuard always follows the CARP role
        #[arg(long, default_value_t = false)]
        wg_deconfigure_on_backup: bool,
    },
}

#[derive(Subcommand)]
enum NodesAction {
    /// List cluster nodes
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
    Remove { id: String },
    /// Reset (or set) the pinned TLS certificate fingerprint of a peer.
    /// Without --fingerprint the pin is cleared and re-learned on next contact.
    #[command(after_help = "\
Peer HTTPS calls are pinned to the certificate seen on first contact. If a
peer's API certificate changed by hand (self-signed regeneration, manual
import), replication logs 'TLS pin mismatch' until you re-pin it here.")]
    Repin {
        id: String,
        /// SHA-256 fingerprint of the peer's certificate (64 hex chars, colons ok)
        #[arg(long)]
        fingerprint: Option<String>,
    },
}

#[derive(Subcommand)]
enum HealthAction {
    /// List health checks
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
    Remove { id: String },
    /// Trigger an immediate probe of all enabled health checks
    Run,
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Check for AiFw firmware update from GitHub
    Check {
        /// Include pre-releases (test channel), not just stable releases.
        #[arg(long)]
        pre: bool,
    },
    /// Download and install AiFw firmware update.
    ///
    /// Does NOT restart services automatically. Run `aifw update restart`
    /// (or pass --restart) once you're ready for the brief outage.
    ///
    /// Pass `--from <path>` to install from a local .tar.xz tarball instead of
    /// fetching the latest GitHub release.  A sibling .sha256 sidecar is
    /// expected unless --skip-checksum is also passed.
    Install {
        /// Restart services immediately after install completes, skipping
        /// the confirmation prompt. Useful for scripts/cron.
        #[arg(long)]
        restart: bool,
        /// Assume "yes" to the restart prompt. Alias for --restart.
        #[arg(short = 'y', long)]
        yes: bool,
        /// Install from a local tarball instead of fetching the latest
        /// GitHub release.  Path must be a .tar.xz file; a sibling
        /// .sha256 file is expected unless --skip-checksum is passed.
        #[arg(long)]
        from: Option<std::path::PathBuf>,
        /// Skip checksum verification (use only when the .sha256 sidecar
        /// is unavailable).
        #[arg(long)]
        skip_checksum: bool,
        /// Include pre-releases (test channel) when fetching from GitHub.
        /// Ignored with --from.
        #[arg(long)]
        pre: bool,
    },
    /// Rollback to previous AiFw firmware version.
    ///
    /// Same restart semantics as `install`.
    Rollback {
        #[arg(long)]
        restart: bool,
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Restart all AiFw services to activate a previously installed update.
    Restart,
    /// Reboot the system (full reboot via shutdown -r +1). Recommended
    /// after updates that change service-supervision tooling.
    Reboot,
    /// Check for OS and package updates
    OsCheck,
    /// Install OS and package updates
    OsInstall,
    /// Upgrade FreeBSD to a newer release (e.g. 15.1). Downloads and
    /// stages the release, installs the new kernel, then asks for a
    /// reboot; the remaining install finishes automatically after boot.
    /// Required before installing an AiFw release built on a newer OS.
    OsUpgrade {
        /// Target release, e.g. "15.1"
        target: String,
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ReverseProxyAction {
    /// Show reverse proxy status
    Status,
    /// Start the reverse proxy
    Start,
    /// Stop the reverse proxy
    Stop,
    /// Restart the reverse proxy
    Restart,
    /// Validate the generated config
    Validate,
    /// Generate config, write YAML, and reload
    Apply,
    /// List HTTP routers
    Routers {
        #[arg(long)]
        json: bool,
    },
    /// List HTTP services
    Services {
        #[arg(long)]
        json: bool,
    },
    /// List HTTP middlewares
    Middlewares {
        #[arg(long)]
        json: bool,
    },
    /// List entrypoints
    Entrypoints {
        #[arg(long)]
        json: bool,
    },
    /// Print the generated YAML config
    ShowConfig,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current active config
    Show,
    /// Export current config to stdout as JSON
    Export {
        /// How to treat secret fields (WireGuard/IPsec keys, CARP passwords,
        /// TSIG): `redact` (default), `passphrase` (wrap under
        /// $AIFW_BACKUP_PASSPHRASE or --passphrase-file), or `plain`
        #[arg(long, default_value = "redact", value_parser = ["redact", "passphrase", "plain"])]
        secrets: String,
        /// File whose first line is the backup passphrase (--secrets passphrase)
        #[arg(long)]
        passphrase_file: Option<String>,
    },
    /// Import config from a JSON file
    Import {
        /// Path to JSON config file
        file: String,
        /// File whose first line is the passphrase for a passphrase-wrapped
        /// backup (also read from $AIFW_BACKUP_PASSPHRASE)
        #[arg(long)]
        passphrase_file: Option<String>,
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
    /// Apply DHCP config (write + restart rDHCP)
    Apply,
}

// One variant carries many large optional fields; boxing each variant would
// add allocator overhead for a CLI command type that lives briefly on the stack.

/// Parse `args` and run the command, writing to `io`. Returns the exit code.
pub async fn run<I, T>(args: I, io: Io, env: Env) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut io = io;
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            let text = e.render().to_string();
            return match e.kind() {
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayVersion
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                    io.println(text.trim_end());
                    if e.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
                        exit::USAGE
                    } else {
                        exit::OK
                    }
                }
                _ => {
                    io.eprintln(text.trim_end());
                    exit::USAGE
                }
            };
        }
    };
    let mut ctx = Ctx::new(cli.global.clone(), io, env);
    match dispatch(cli, &mut ctx).await {
        Ok(()) => exit::OK,
        Err(e) => {
            let code = exit::code_for(&e);
            if ctx.format().is_structured() {
                let v = serde_json::json!({
                    "error": format!("{e:#}"),
                    "kind": exit::kind_for(code),
                    "exit_code": code,
                });
                ctx.io.eprintln(&v.to_string());
            } else {
                ctx.io.eprintln(&format!("Error: {e:#}"));
            }
            code
        }
    }
}

async fn dispatch(cli: Cli, ctx: &mut Ctx) -> anyhow::Result<()> {
    // #298: secrets master key beside the database (shared with aifw-api).
    aifw_core::secrets::configure_from_db_path(&cli.db);

    match cli.command {
        Commands::Login(a) => commands::session::login(ctx, a).await?,
        Commands::Logout => commands::session::logout(ctx).await?,
        Commands::Whoami => commands::session::whoami(ctx).await?,
        Commands::Context { action } => commands::context::run(ctx, action).await?,
        Commands::Pending { watch } => commands::staging::pending(ctx, watch).await?,
        Commands::Apply => commands::staging::apply(ctx).await?,
        Commands::Confirm { action } => commands::staging::confirm(ctx, action).await?,
        Commands::Local { action } => commands::local::run(ctx, action, &cli.db).await?,
        Commands::Init { path } => {
            commands::local::init(path.as_deref().unwrap_or(&cli.db)).await?;
        }
        Commands::Rules { action } => commands::rules::run(ctx, action).await?,
        Commands::Ids { action } => commands::ids::run(ctx, action).await?,
        Commands::Plugins { action } => commands::plugins::run(ctx, action).await?,
        Commands::Logrotate { action } => commands::logging::logrotate(ctx, action).await?,
        Commands::Syslog { action } => commands::logging::syslog(ctx, action).await?,
        Commands::Nat { action } => commands::nat::run(ctx, action).await?,
        Commands::Queue { action } => commands::shaping::run(ctx, action).await?,
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
                commands::local::ratelimit_add(
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
                commands::local::ratelimit_remove(&cli.db, &id).await?;
            }
            RateLimitAction::List { json } => {
                commands::local::ratelimit_list(&cli.db, json).await?;
            }
        },
        Commands::Geoip { action } => commands::geoip::run(ctx, action).await?,
        Commands::Vpn { action } => commands::vpn::run(ctx, action).await?,
        Commands::Config { action } => match action {
            ConfigAction::Show => commands::config_show(&cli.db).await?,
            ConfigAction::Export {
                secrets,
                passphrase_file,
            } => commands::config_export(&cli.db, &secrets, passphrase_file.as_deref()).await?,
            ConfigAction::Import {
                file,
                passphrase_file,
            } => commands::config_import(&cli.db, &file, passphrase_file.as_deref()).await?,
            ConfigAction::History { limit } => commands::config_history(&cli.db, limit).await?,
            ConfigAction::Rollback { version } => {
                commands::config_rollback(&cli.db, version).await?
            }
            ConfigAction::Diff { v1, v2 } => commands::config_diff(&cli.db, v1, v2).await?,
        },
        Commands::Routes { action } => commands::routes::run(ctx, action).await?,
        Commands::Dhcp { action } => match action {
            DhcpAction::Status => commands::dhcp_status(&cli.db).await?,
            DhcpAction::Start => {
                commands::service_ctl("rdhcpd", "start")?;
                println!("DHCP started");
            }
            DhcpAction::Stop => {
                commands::service_ctl("rdhcpd", "stop")?;
                println!("DHCP stopped");
            }
            DhcpAction::Restart => {
                commands::service_ctl("rdhcpd", "restart")?;
                println!("DHCP restarted");
            }
            DhcpAction::Subnets { json } => commands::dhcp_subnets(&cli.db, json).await?,
            DhcpAction::SubnetAdd {
                network,
                pool_start,
                pool_end,
                gateway,
                dns,
                domain,
                lease_time,
                desc,
            } => {
                commands::dhcp_subnet_add(
                    &cli.db,
                    &network,
                    &pool_start,
                    &pool_end,
                    &gateway,
                    dns.as_deref(),
                    domain.as_deref(),
                    lease_time,
                    desc.as_deref(),
                )
                .await?;
            }
            DhcpAction::SubnetRemove { id } => commands::dhcp_subnet_remove(&cli.db, &id).await?,
            DhcpAction::Reservations { json } => commands::dhcp_reservations(&cli.db, json).await?,
            DhcpAction::ReservationAdd {
                mac,
                ip,
                hostname,
                subnet,
                desc,
            } => {
                commands::dhcp_reservation_add(
                    &cli.db,
                    &mac,
                    &ip,
                    hostname.as_deref(),
                    subnet.as_deref(),
                    desc.as_deref(),
                )
                .await?;
            }
            DhcpAction::ReservationRemove { id } => {
                commands::dhcp_reservation_remove(&cli.db, &id).await?
            }
            DhcpAction::Leases { json } => commands::dhcp_leases(json).await?,
            DhcpAction::Apply => commands::dhcp_apply(&cli.db).await?,
        },
        Commands::Dns { action } => commands::dns::run(ctx, action).await?,
        Commands::Users { action } => commands::users::run(ctx, action).await?,
        Commands::ReverseProxy { action } => match action {
            ReverseProxyAction::Status => commands::rp_status(&cli.db).await?,
            ReverseProxyAction::Start => commands::rp_start().await?,
            ReverseProxyAction::Stop => commands::rp_stop().await?,
            ReverseProxyAction::Restart => commands::rp_restart().await?,
            ReverseProxyAction::Validate => commands::rp_validate(&cli.db).await?,
            ReverseProxyAction::Apply => commands::rp_apply(&cli.db).await?,
            ReverseProxyAction::Routers { json } => commands::rp_routers(&cli.db, json).await?,
            ReverseProxyAction::Services { json } => commands::rp_services(&cli.db, json).await?,
            ReverseProxyAction::Middlewares { json } => {
                commands::rp_middlewares(&cli.db, json).await?
            }
            ReverseProxyAction::Entrypoints { json } => {
                commands::rp_entrypoints(&cli.db, json).await?
            }
            ReverseProxyAction::ShowConfig => commands::rp_show_config(&cli.db).await?,
        },
        Commands::Update { action } => match action {
            UpdateAction::Check { pre } => commands::update_check(pre).await?,
            UpdateAction::Install {
                restart,
                yes,
                from,
                skip_checksum,
                pre,
            } => {
                if let Some(path) = from {
                    commands::update_install_local(path, skip_checksum, restart || yes).await?
                } else {
                    commands::update_install(&cli.db, restart || yes, pre).await?
                }
            }
            UpdateAction::Rollback { restart, yes } => {
                commands::update_rollback(restart || yes).await?
            }
            UpdateAction::Restart => commands::update_restart().await?,
            UpdateAction::Reboot => commands::update_reboot().await?,
            UpdateAction::OsCheck => commands::update_os_check().await?,
            UpdateAction::OsInstall => commands::update_os_install().await?,
            UpdateAction::OsUpgrade { target, yes } => {
                commands::update_os_upgrade(&target, yes).await?
            }
        },
        Commands::Interfaces => {
            commands::interfaces::run(ctx).await?;
        }
        Commands::Status => {
            commands::system::status(ctx).await?;
        }
        Commands::Reload { local } => {
            if local {
                commands::local::reload(&cli.db).await?;
            } else {
                commands::system::reload(ctx).await?;
            }
        }
        Commands::Reconcile => {
            commands::local::reconcile(&cli.db).await?;
        }
        Commands::Multiwan { action } => match action {
            MultiwanAction::Instances => commands::multiwan_instances(&cli.db).await?,
            MultiwanAction::Gateways => commands::multiwan_gateways(&cli.db).await?,
            MultiwanAction::Groups => commands::multiwan_groups(&cli.db).await?,
            MultiwanAction::Policies => commands::multiwan_policies(&cli.db).await?,
            MultiwanAction::Leaks => commands::multiwan_leaks(&cli.db).await?,
            MultiwanAction::Flows => commands::multiwan_flows().await?,
            MultiwanAction::FibInfo => commands::multiwan_fib_info().await?,
            MultiwanAction::Apply => commands::multiwan_apply(&cli.db).await?,
            MultiwanAction::SeedMgmt => commands::multiwan_seed_mgmt(&cli.db).await?,
            MultiwanAction::Probe { id, outcome } => {
                commands::multiwan_probe(&cli.db, &id, &outcome).await?
            }
            MultiwanAction::Export => commands::multiwan_export(&cli.db).await?,
            MultiwanAction::Import { file } => commands::multiwan_import(&cli.db, &file).await?,
        },
        Commands::Cluster { action } => match action {
            ClusterAction::Status { json } => commands::cluster_status(json).await?,
            ClusterAction::Carp { action } => match action {
                CarpAction::List => commands::cluster_carp_list().await?,
                CarpAction::Show { id } => commands::cluster_carp_show(&id).await?,
                CarpAction::Add {
                    vhid,
                    interface,
                    vip,
                    password,
                } => commands::cluster_carp_add(vhid, &interface, &vip, &password).await?,
                CarpAction::Remove { id } => commands::cluster_carp_remove(&id).await?,
            },
            ClusterAction::Pfsync { action } => match action {
                PfsyncAction::Get => commands::cluster_pfsync_get().await?,
                PfsyncAction::Set {
                    sync_interface,
                    sync_peer,
                    defer,
                    latency_profile,
                    dhcp_link,
                    wg_deconfigure_on_backup,
                } => {
                    commands::cluster_pfsync_set(
                        &sync_interface,
                        sync_peer.as_deref(),
                        defer,
                        &latency_profile,
                        dhcp_link,
                        wg_deconfigure_on_backup,
                    )
                    .await?
                }
            },
            ClusterAction::Nodes { action } => match action {
                NodesAction::List => commands::cluster_nodes_list().await?,
                NodesAction::Show { id } => commands::cluster_nodes_show(&id).await?,
                NodesAction::Add {
                    name,
                    address,
                    role,
                    api_port,
                } => commands::cluster_nodes_add(&name, &address, &role, api_port).await?,
                NodesAction::Remove { id } => commands::cluster_nodes_remove(&id).await?,
                NodesAction::Repin { id, fingerprint } => {
                    commands::cluster_nodes_repin(&id, fingerprint.as_deref()).await?
                }
            },
            ClusterAction::Health { action } => match action {
                HealthAction::List => commands::cluster_health_list().await?,
                HealthAction::Add {
                    name,
                    check_type,
                    target,
                    interval_secs,
                } => {
                    commands::cluster_health_add(&name, &check_type, &target, interval_secs).await?
                }
                HealthAction::Remove { id } => commands::cluster_health_remove(&id).await?,
                HealthAction::Run => commands::cluster_health_run().await?,
            },
            ClusterAction::Promote => commands::cluster_promote().await?,
            ClusterAction::Demote => commands::cluster_demote().await?,
            ClusterAction::Maintenance { action } => {
                commands::cluster_maintenance(matches!(action, MaintenanceAction::On)).await?
            }
            ClusterAction::Sync => commands::cluster_sync().await?,
            ClusterAction::Verify { json } => return commands::cluster_verify(json).await,
        },
    }

    Ok(())
}
