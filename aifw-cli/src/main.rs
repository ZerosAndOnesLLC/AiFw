mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aifw",
    about = "AiFw — AI-Powered Firewall for FreeBSD",
    version
)]
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
    /// Manage the IDS engine (alerts, retention)
    Ids {
        #[command(subcommand)]
        action: IdsAction,
    },
    /// Manage remote syslog forwarding
    Syslog {
        #[command(subcommand)]
        action: SyslogAction,
    },
    /// Manage rotation of AiFw service logs (newsyslog policy)
    Logrotate {
        #[command(subcommand)]
        action: LogrotateAction,
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
    /// Reload rules from database and apply to pf
    Reload,
    /// Reconcile kernel pf state and rc.conf against db/pf.conf.aifw.
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
    /// Promote this node to master immediately (sysctl carp.demotion=0)
    Promote,
    /// Demote this node to backup immediately (sysctl carp.demotion=240)
    Demote,
    /// Force a snapshot pull from peer
    Sync,
    /// Run local-side verification checks. Exits 0 on healthy, non-zero on failure.
    Verify {
        #[arg(long)]
        json: bool,
    },
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
    },
    /// Remove a cluster node
    Remove { id: String },
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
    /// Add an IPsec IKEv2 site-to-site tunnel (PSK auth; use the web
    /// UI/API for certificate auth)
    IpsecAdd {
        /// Tunnel name
        #[arg(long)]
        name: String,
        /// Remote IKE endpoint (IP address or DNS name)
        #[arg(long)]
        remote: String,
        /// Pre-shared key (at least 16 printable characters)
        #[arg(long)]
        psk: String,
        /// Local subnets behind this firewall (comma-separated CIDRs)
        #[arg(long)]
        local_ts: String,
        /// Remote subnets behind the peer (comma-separated CIDRs)
        #[arg(long)]
        remote_ts: String,
        /// Local IKE endpoint address (default: any local address)
        #[arg(long)]
        local: Option<String>,
    },
    /// Initiate an IPsec tunnel's child SA
    IpsecStart {
        /// Tunnel ID
        id: String,
    },
    /// Terminate an IPsec tunnel's IKE SA
    IpsecStop {
        /// Tunnel ID
        id: String,
    },
    /// Show live IPsec tunnel status (negotiated state from charon)
    IpsecStatus {
        #[arg(long)]
        json: bool,
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
    /// Toggle the post-switch DNS probe (auto-rollback on :53 silence)
    Probe {
        #[command(subcommand)]
        action: ProbeAction,
    },
}

#[derive(Subcommand)]
enum ProbeAction {
    /// Enable probe + auto-rollback on backend switch
    On,
    /// Disable probe — trust exit code of `service <backend> restart`
    Off,
    /// Show current probe_enabled value
    Status,
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
    /// Apply DHCP config (write + restart rDHCP)
    Apply,
}

// One variant carries many large optional fields; boxing each variant would
// add allocator overhead for a CLI command type that lives briefly on the stack.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum IdsAction {
    /// Delete ALL stored IDS alerts and reclaim the disk space
    #[command(after_help = "\
EXAMPLES:
    aifw ids purge-alerts            # asks for confirmation first
    aifw ids purge-alerts --yes      # non-interactive (scripts/cron)")]
    PurgeAlerts {
        /// Skip the confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Show or set how long alerts are kept (pruned hourly by aifw-ids)
    #[command(after_help = "\
EXAMPLES:
    aifw ids retention               # show the current setting
    aifw ids retention 7             # keep one week (the default)
    aifw ids retention 30            # keep one month")]
    Retention {
        /// Days to keep alerts (1-365). Omit to show the current value.
        days: Option<u32>,
    },
}

#[derive(Subcommand)]
enum LogrotateAction {
    /// Show the rotation policy and the current size of every managed log
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Update the policy — only the flags you pass change
    #[command(after_help = "\
EXAMPLES:
    # Rotate at 20 MB, keep 5 compressed generations
    aifw logrotate set --max-size 20 --keep 5

    # Switch rotated logs to zstd (gzip, bzip2, xz, zstd, none)
    aifw logrotate set --compression zstd")]
    Set {
        /// Rotate a log once it exceeds this many MB (1-500)
        #[arg(long, value_name = "MB")]
        max_size: Option<u32>,
        /// Rotated generations to keep (0-50)
        #[arg(long)]
        keep: Option<u32>,
        /// Compression for rotated generations: gzip, bzip2, xz, zstd, none
        #[arg(long)]
        compression: Option<String>,
    },
    /// Rotate now: one log by path, or every managed log that is over its limit
    Rotate {
        /// Path of a managed log to force-rotate regardless of size
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyslogAction {
    /// Show the current remote syslog configuration
    Show {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Enable remote syslog forwarding (requires a host to be set)
    Enable,
    /// Disable remote syslog forwarding
    Disable,
    /// Update settings — only the flags you pass change
    #[command(after_help = "\
EXAMPLES:
    # Point at a syslog server and enable pf log forwarding
    aifw syslog set --host 192.168.1.10 --port 514 --pf true
    aifw syslog enable

    # Switch to TCP with RFC 5424 framing on facility local3
    aifw syslog set --transport tcp --format rfc5424 --facility local3

    # Forward everything, app logs at warn and above
    aifw syslog set --pf true --ids true --app true --app-min-level warn")]
    Set {
        /// Syslog server hostname or IP
        #[arg(long)]
        host: Option<String>,
        /// Syslog server port (default 514)
        #[arg(long)]
        port: Option<u16>,
        /// Transport: udp or tcp
        #[arg(long)]
        transport: Option<String>,
        /// Message format: rfc3164 (BSD) or rfc5424
        #[arg(long)]
        format: Option<String>,
        /// Facility name (kern, daemon, auth, local0-local7, ...) or number 0-23
        #[arg(long)]
        facility: Option<String>,
        /// HOSTNAME field override; pass an empty string for the system hostname
        #[arg(long)]
        hostname: Option<String>,
        /// Forward pf packet logs (true/false)
        #[arg(long)]
        pf: Option<bool>,
        /// Forward IDS alerts (true/false)
        #[arg(long)]
        ids: Option<bool>,
        /// Forward application logs (true/false)
        #[arg(long)]
        app: Option<bool>,
        /// Minimum app-log level to forward: error, warn, info, or debug
        #[arg(long)]
        app_min_level: Option<String>,
        /// Stop writing local log files while forwarding is active (true/false)
        #[arg(long)]
        disable_local: Option<bool>,
    },
    /// Send a test message using the saved config (or --host/--port overrides)
    #[command(after_help = "\
EXAMPLES:
    aifw syslog test                          # use the saved configuration
    aifw syslog test --host 10.0.0.9 --port 5514")]
    Test {
        /// Override the target host for this test only
        #[arg(long)]
        host: Option<String>,
        /// Override the target port for this test only
        #[arg(long)]
        port: Option<u16>,
    },
}

#[derive(Subcommand)]
enum NatAction {
    /// Add a NAT rule
    #[command(after_help = "\
EXAMPLES:
    # Source NAT a LAN behind a WAN address
    aifw nat add --nat-type snat --interface em0 --src 192.168.1.0/24 --redirect 203.0.113.1

    # Port-forward WAN :80 to an internal host
    aifw nat add --nat-type dnat --interface em0 --dst-port 80 --redirect 10.0.0.5 --redirect-port 8080

    # NAT64: IPv6-only clients reach IPv4 hosts (pf af-to, FreeBSD 15+).
    # --dst defaults to the well-known prefix 64:ff9b::/96; --redirect is
    # the IPv4 the firewall sources translated traffic from.
    aifw nat add --nat-type nat64 --interface em1 --redirect 203.0.113.1

    # NAT46: IPv4-only clients reach an IPv6 service. The v6 server must
    # hold the RFC 6052 embedding of --dst in --redirect's /96 subnet
    # (print it with: aifw nat embed <redirect> <dst>).
    aifw nat add --nat-type nat46 --interface em1 --dst 10.99.1.1 --redirect 2001:db8:2::1

    # Masquerade keeping the source port (SIP/VPN friendly)
    aifw nat add --nat-type masquerade --interface em0 --src 192.168.1.0/24 --static-port

    # NAT bypass: don't NAT LAN → site-to-site VPN subnet (order before the masquerade rule)
    aifw nat add --nat-type nonat --interface em0 --src 192.168.1.0/24 --dst 10.50.0.0/16")]
    Add {
        /// NAT type: snat, dnat, masquerade, binat, nat64 (IPv6→IPv4 af-to),
        /// nat46 (IPv4→IPv6 af-to), nonat (bypass — exempt matching traffic
        /// from later NAT rules; no --redirect)
        #[arg(long, name = "type")]
        nat_type: String,

        /// Network interface (required)
        #[arg(long)]
        interface: String,

        /// Protocol: tcp, udp, icmp, any (icmp auto-normalizes to icmp6 on nat64)
        #[arg(long, default_value = "any")]
        proto: String,

        /// Source address
        #[arg(long, default_value = "any")]
        src: String,

        /// Source port
        #[arg(long)]
        src_port: Option<String>,

        /// Destination address. nat64: the /96 translation prefix
        /// (defaults to 64:ff9b::/96). nat46: the IPv4 destination (required).
        #[arg(long)]
        dst: Option<String>,

        /// Destination port
        #[arg(long)]
        dst_port: Option<String>,

        /// Redirect target. nat64/nat46: the translation source address the
        /// firewall owns in the translated family (IPv4 for nat64, IPv6 for
        /// nat46). Not used for masquerade / nonat (defaults to any).
        #[arg(long)]
        redirect: Option<String>,

        /// Redirect target port (not valid for nat64/nat46)
        #[arg(long)]
        redirect_port: Option<String>,

        /// Rule label
        #[arg(long)]
        label: Option<String>,

        /// Keep the original source port (pf static-port). snat/masquerade
        /// only — needed by SIP, some VPNs and games that break when the
        /// source port is rewritten.
        #[arg(long)]
        static_port: bool,
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
    /// Print the RFC 6052 NAT64 address embedding an IPv4 host in a /96 prefix
    #[command(after_help = "\
EXAMPLES:
    aifw nat embed 64:ff9b::/96 8.8.8.8        # -> 64:ff9b::808:808
    aifw nat embed 2001:db8:2::1 10.99.1.1     # -> 2001:db8:2::a63:101")]
    Embed {
        /// IPv6 /96 prefix (or an address whose /96 subnet is used)
        prefix: String,

        /// IPv4 address to embed
        ipv4: String,
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

        /// Source address (IP, CIDR, "any", or `<table>`)
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
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
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
                    &cli.db,
                    &action,
                    &direction,
                    &proto,
                    &src,
                    src_port.as_deref(),
                    &dst,
                    dst_port.as_deref(),
                    interface.as_deref(),
                    priority,
                    log,
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
        Commands::Ids { action } => match action {
            IdsAction::PurgeAlerts { yes } => {
                commands::ids_purge_alerts(&cli.db, yes).await?;
            }
            IdsAction::Retention { days } => {
                commands::ids_retention(&cli.db, days).await?;
            }
        },
        Commands::Logrotate { action } => match action {
            LogrotateAction::Show { json } => commands::logrotate_show(&cli.db, json).await?,
            LogrotateAction::Set {
                max_size,
                keep,
                compression,
            } => commands::logrotate_set(&cli.db, max_size, keep, compression.as_deref()).await?,
            LogrotateAction::Rotate { path } => {
                commands::logrotate_rotate(&cli.db, path.as_deref()).await?
            }
        },
        Commands::Syslog { action } => match action {
            SyslogAction::Show { json } => {
                commands::syslog_show(&cli.db, json).await?;
            }
            SyslogAction::Enable => {
                commands::syslog_enable(&cli.db, true).await?;
            }
            SyslogAction::Disable => {
                commands::syslog_enable(&cli.db, false).await?;
            }
            SyslogAction::Set {
                host,
                port,
                transport,
                format,
                facility,
                hostname,
                pf,
                ids,
                app,
                app_min_level,
                disable_local,
            } => {
                commands::syslog_set(
                    &cli.db,
                    commands::SyslogSetOpts {
                        host,
                        port,
                        transport,
                        format,
                        facility,
                        hostname,
                        pf,
                        ids,
                        app,
                        app_min_level,
                        disable_local,
                    },
                )
                .await?;
            }
            SyslogAction::Test { host, port } => {
                commands::syslog_test(&cli.db, host, port).await?;
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
                static_port,
            } => {
                // Smart default: nat64 practically always matches the
                // well-known prefix; every other type keeps "any".
                let dst = dst.unwrap_or_else(|| {
                    if nat_type == "nat64" {
                        "64:ff9b::/96".to_string()
                    } else {
                        "any".to_string()
                    }
                });
                // masquerade / nonat have no translation target; everything
                // else needs one.
                let redirect = match redirect {
                    Some(r) => r,
                    None if matches!(
                        nat_type.as_str(),
                        "masquerade" | "masq" | "nonat" | "no-nat"
                    ) =>
                    {
                        "any".to_string()
                    }
                    None => anyhow::bail!("--redirect is required for --type {nat_type}"),
                };
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
                    static_port,
                )
                .await?;
            }
            NatAction::Remove { id } => {
                commands::nat_remove(&cli.db, &id).await?;
            }
            NatAction::List { json } => {
                commands::nat_list(&cli.db, json).await?;
            }
            NatAction::Embed { prefix, ipv4 } => {
                commands::nat_embed(&prefix, &ipv4)?;
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
                    &cli.db,
                    &name,
                    &interface,
                    &queue_type,
                    &bandwidth,
                    &class,
                    pct,
                    default,
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
            GeoIpCmd::Add {
                country,
                action,
                label,
            } => {
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
            VpnAction::WgAdd {
                name,
                interface,
                port,
                address,
            } => {
                commands::vpn_wg_add(&cli.db, &name, &interface, port, &address).await?;
            }
            VpnAction::WgPeerAdd {
                tunnel,
                name,
                pubkey,
                endpoint,
                allowed_ips,
                keepalive,
            } => {
                commands::vpn_wg_peer_add(
                    &cli.db,
                    &tunnel,
                    &name,
                    &pubkey,
                    endpoint.as_deref(),
                    &allowed_ips,
                    keepalive,
                )
                .await?;
            }
            VpnAction::IpsecAdd {
                name,
                remote,
                psk,
                local_ts,
                remote_ts,
                local,
            } => {
                commands::vpn_ipsec_add(
                    &cli.db,
                    &name,
                    &remote,
                    &psk,
                    &local_ts,
                    &remote_ts,
                    local.as_deref(),
                )
                .await?;
            }
            VpnAction::IpsecStart { id } => {
                commands::vpn_ipsec_start(&cli.db, &id).await?;
            }
            VpnAction::IpsecStop { id } => {
                commands::vpn_ipsec_stop(&cli.db, &id).await?;
            }
            VpnAction::IpsecStatus { json } => {
                commands::vpn_ipsec_status(&cli.db, json).await?;
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
            ConfigAction::Rollback { version } => {
                commands::config_rollback(&cli.db, version).await?
            }
            ConfigAction::Diff { v1, v2 } => commands::config_diff(&cli.db, v1, v2).await?,
        },
        Commands::Routes { action } => match action {
            RoutesAction::Add {
                dest,
                gateway,
                interface,
                metric,
                desc,
            } => {
                commands::routes_add(
                    &cli.db,
                    &dest,
                    &gateway,
                    interface.as_deref(),
                    metric,
                    desc.as_deref(),
                )
                .await?;
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
            DhcpAction::Start => {
                let _ = std::process::Command::new("service")
                    .args(["rdhcpd", "start"])
                    .output();
                println!("DHCP started");
            }
            DhcpAction::Stop => {
                let _ = std::process::Command::new("service")
                    .args(["rdhcpd", "stop"])
                    .output();
                println!("DHCP stopped");
            }
            DhcpAction::Restart => {
                let _ = std::process::Command::new("service")
                    .args(["rdhcpd", "restart"])
                    .output();
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
        Commands::Dns { action } => match action {
            DnsAction::List => {
                commands::dns_list().await?;
            }
            DnsAction::Set { servers } => {
                commands::dns_set(&servers).await?;
            }
            DnsAction::Probe { action } => match action {
                ProbeAction::On => commands::dns_probe_set(&cli.db, true).await?,
                ProbeAction::Off => commands::dns_probe_set(&cli.db, false).await?,
                ProbeAction::Status => commands::dns_probe_status(&cli.db).await?,
            },
        },
        Commands::Users { action } => match action {
            UsersAction::List { json } => {
                commands::users_list(&cli.db, json).await?;
            }
            UsersAction::Add {
                username,
                password,
                role,
            } => {
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
            commands::interfaces_list().await?;
        }
        Commands::Status => {
            commands::status(&cli.db).await?;
        }
        Commands::Reload => {
            commands::reload(&cli.db).await?;
        }
        Commands::Reconcile => {
            commands::reconcile(&cli.db).await?;
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
                } => {
                    commands::cluster_pfsync_set(
                        &sync_interface,
                        sync_peer.as_deref(),
                        defer,
                        &latency_profile,
                        dhcp_link,
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
                } => commands::cluster_nodes_add(&name, &address, &role).await?,
                NodesAction::Remove { id } => commands::cluster_nodes_remove(&id).await?,
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
            ClusterAction::Sync => commands::cluster_sync().await?,
            ClusterAction::Verify { json } => return commands::cluster_verify(json).await,
        },
    }

    Ok(())
}
