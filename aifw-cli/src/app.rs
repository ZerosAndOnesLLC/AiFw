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
    /// Your API keys for scripts and other machines
    ApiKeys {
        #[command(subcommand)]
        action: commands::api_keys::ApiKeysCmd,
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
    /// Intrusion detection: config, alerts, rules, suppressions
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
        action: commands::config::ConfigCmd,
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
        action: commands::dhcp::DhcpCmd,
    },
    /// Manage users
    Users {
        #[command(subcommand)]
        action: commands::users::UsersCmd,
    },
    /// Manage the reverse proxy (TrafficCop)
    ReverseProxy {
        #[command(subcommand)]
        action: commands::reverse_proxy::ReverseProxyCmd,
    },
    /// Manage AiFw and OS updates
    Update {
        #[command(subcommand)]
        action: commands::updates::UpdateCmd,
    },
    /// Network interfaces (bare: list)
    Interfaces {
        #[command(subcommand)]
        action: Option<commands::interfaces::IfaceCmd>,
    },
    /// Address/port aliases usable in rules as <name>
    Aliases {
        #[command(subcommand)]
        action: commands::objects::AliasCmd,
    },
    /// Time-of-day schedules for rules
    Schedules {
        #[command(subcommand)]
        action: commands::objects::ScheduleCmd,
    },
    /// VLAN interfaces
    Vlans {
        #[command(subcommand)]
        action: commands::objects::VlanCmd,
    },
    /// Let's Encrypt (ACME) certificates
    Acme {
        #[command(subcommand)]
        action: commands::certs::AcmeCmd,
    },
    /// Dynamic DNS
    Ddns {
        #[command(subcommand)]
        action: commands::certs::DdnsCmd,
    },
    /// The internal certificate authority
    Ca {
        #[command(subcommand)]
        action: commands::certs::CaCmd,
    },
    /// NTP/PTP time service
    Time {
        #[command(subcommand)]
        action: commands::time::TimeCmd,
    },
    /// Off-box backups
    Backup {
        #[command(subcommand)]
        action: commands::backup::BackupCmd,
    },
    /// Email notifications
    Notify {
        #[command(subcommand)]
        action: commands::backup::NotifyCmd,
    },
    /// Appliance settings sections, login policy, OAuth, AI providers
    Settings {
        #[command(subcommand)]
        action: commands::settings::SettingsCmd,
    },
    /// Hostname, banner, SSH, console, system info
    System {
        #[command(subcommand)]
        action: commands::system_cfg::SystemCmd,
    },
    /// Reboot the firewall
    Reboot {
        #[arg(short, long)]
        yes: bool,
    },
    /// Shut the firewall down
    Shutdown {
        #[arg(short, long)]
        yes: bool,
    },
    /// Roles and permissions
    Roles {
        #[command(subcommand)]
        action: commands::identity::RolesCmd,
    },
    /// Your two-factor authentication (needs a login session, not an API key)
    Totp {
        #[command(subcommand)]
        action: commands::identity::TotpCmd,
    },
    /// Account audit trail (logins, user and key changes)
    Audit,
    /// pf state table
    Connections {
        #[arg(long, default_value_t = 200)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
    /// Recently blocked traffic
    Blocked,
    /// Firewall change log
    Logs,
    /// Counters and recorded time series
    Metrics {
        #[command(subcommand)]
        action: Option<commands::ops::MetricsCmd>,
    },
    /// Version and memory use
    About,
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell)
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff) — used by packaging
    #[command(hide = true)]
    Man,
    /// Live status and counters, refreshed until Ctrl-C
    Top {
        /// Seconds between refreshes
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Print one frame and exit
        #[arg(long)]
        once: bool,
    },
    /// AI classification of IDS alerts
    Ai {
        #[command(subcommand)]
        action: commands::ai::AiCmd,
    },
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
        action: commands::multiwan::MultiwanCmd,
    },
    /// Cluster / HA operations
    Cluster {
        #[command(subcommand)]
        action: commands::cluster::ClusterCmd,
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

// One variant carries many large optional fields; boxing each variant would
// add allocator overhead for a CLI command type that lives briefly on the stack.

/// Parse `args` and run the command, writing to `io`. Returns the exit code.
pub async fn run<I, T>(args: I, io: Io, env: Env) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut io = io;
    let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let cli = match Cli::try_parse_from(&args) {
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
    // Fan-out: --context a,b or --all-contexts on a read-only command.
    let names = cli.global.context_names();
    if cli.global.all_contexts || names.len() > 1 {
        return fan_out(&args, cli.global.clone(), io, env).await;
    }
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

/// The subcommand chain the user typed (`["rules", "list"]`).
fn command_path(args: &[std::ffi::OsString]) -> Vec<String> {
    use clap::CommandFactory;
    let mut path = Vec::new();
    if let Ok(m) = Cli::command().try_get_matches_from(args) {
        let mut cur = m.subcommand();
        while let Some((name, sub)) = cur {
            path.push(name.to_string());
            cur = sub.subcommand();
        }
    }
    path
}

async fn fan_out(
    args: &[std::ffi::OsString],
    g: crate::cli::global::GlobalArgs,
    mut io: Io,
    env: Env,
) -> i32 {
    let fail = |io: &mut Io, e: anyhow::Error| {
        io.eprintln(&format!("Error: {e:#}"));
        exit::code_for(&e)
    };
    let path = command_path(args);
    if let Err(e) = crate::cli::fanout::require_read_only(&path) {
        return fail(&mut io, e.into());
    }
    let store = crate::cli::config::Store::new(&env.config_dir);
    let contexts = if g.all_contexts {
        match store.load_config() {
            Ok(c) => c.contexts.keys().cloned().collect::<Vec<_>>(),
            Err(e) => return fail(&mut io, e),
        }
    } else {
        g.context_names()
    };
    if contexts.is_empty() {
        return fail(
            &mut io,
            exit::CliError::Usage("no saved contexts to fan out to".into()).into(),
        );
    }
    let outcomes = crate::cli::fanout::run_all(args.to_vec(), contexts, g.parallel, env).await;
    match crate::cli::fanout::report(&mut io, &outcomes, g.output.unwrap_or_default()) {
        Ok(code) => code,
        Err(e) => fail(&mut io, e),
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
        Commands::ApiKeys { action } => commands::api_keys::run(ctx, action).await?,
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
        Commands::Config { action } => commands::config::run(ctx, action).await?,
        Commands::Routes { action } => commands::routes::run(ctx, action).await?,
        Commands::Dhcp { action } => commands::dhcp::run(ctx, action).await?,
        Commands::Dns { action } => commands::dns::run(ctx, action).await?,
        Commands::Users { action } => commands::users::run(ctx, action).await?,
        Commands::ReverseProxy { action } => commands::reverse_proxy::run(ctx, action).await?,
        Commands::Update { action } => commands::updates::run(ctx, action).await?,
        Commands::Interfaces { action } => commands::interfaces::run(ctx, action).await?,
        Commands::Aliases { action } => commands::objects::aliases(ctx, action).await?,
        Commands::Schedules { action } => commands::objects::schedules(ctx, action).await?,
        Commands::Vlans { action } => commands::objects::vlans(ctx, action).await?,
        Commands::Acme { action } => commands::certs::acme(ctx, action).await?,
        Commands::Ddns { action } => commands::certs::ddns(ctx, action).await?,
        Commands::Ca { action } => commands::certs::ca(ctx, action).await?,
        Commands::Time { action } => commands::time::run(ctx, action).await?,
        Commands::Backup { action } => commands::backup::backup(ctx, action).await?,
        Commands::Notify { action } => commands::backup::notify(ctx, action).await?,
        Commands::Settings { action } => commands::settings::run(ctx, action).await?,
        Commands::System { action } => commands::system_cfg::run(ctx, action).await?,
        Commands::Reboot { yes } => commands::system_cfg::power(ctx, false, yes).await?,
        Commands::Shutdown { yes } => commands::system_cfg::power(ctx, true, yes).await?,
        Commands::Roles { action } => commands::identity::roles(ctx, action).await?,
        Commands::Totp { action } => commands::identity::totp(ctx, action).await?,
        Commands::Audit => commands::identity::audit(ctx).await?,
        Commands::Connections { limit, offset } => {
            commands::ops::connections(ctx, limit, offset).await?
        }
        Commands::Blocked => commands::ops::blocked(ctx).await?,
        Commands::Logs => commands::ops::logs(ctx).await?,
        Commands::Metrics { action } => commands::ops::metrics(ctx, action).await?,
        Commands::About => commands::ops::about(ctx).await?,
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "aifw", &mut buf);
            ctx.io.println(String::from_utf8_lossy(&buf).trim_end());
        }
        Commands::Man => {
            use clap::CommandFactory;
            let mut buf = Vec::new();
            clap_mangen::Man::new(Cli::command()).render(&mut buf)?;
            ctx.io.println(String::from_utf8_lossy(&buf).trim_end());
        }
        Commands::Top { interval, once } => commands::ops::top(ctx, interval, once).await?,
        Commands::Ai { action } => commands::ai::run(ctx, action).await?,
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
        Commands::Multiwan { action } => commands::multiwan::run(ctx, action).await?,
        Commands::Cluster { action } => commands::cluster::run(ctx, action).await?,
    }

    Ok(())
}

#[cfg(test)]
mod compat_tests {
    use super::Cli;
    use clap::Parser;

    /// Every invocation something outside this crate relies on must keep
    /// parsing: the maintenance cron (aifw-api/src/updates.rs), the console
    /// menu (freebsd/overlay/usr/local/sbin/aifw-console), scripts/ha-verify.sh,
    /// build-update.sh / RELEASE-SIGNING.md, daemon/setup hint strings, the
    /// installer's closing hints and the documented legacy spellings.
    #[test]
    fn external_callers_still_parse() {
        let calls: &[&[&str]] = &[
            // maintenance cron + aifw-console
            &["update", "check"],
            &["update", "install"],
            &["update", "os-check"],
            &["update", "os-install"],
            // build-update.sh / RELEASE-SIGNING.md
            &["update", "install", "--from", "/tmp/aifw-update.tar.xz"],
            &[
                "update",
                "install",
                "--from",
                "/tmp/x.tar.xz",
                "--skip-checksum",
                "--restart",
            ],
            &["update", "rollback", "--yes"],
            &["update", "os-upgrade", "15.1", "--yes"],
            // scripts/ha-verify.sh
            &["cluster", "verify", "--json"],
            // daemon / setup hints, installer hints
            &["reconcile"],
            &["reload"],
            &["rules", "list"],
            &["status"],
            // legacy spellings kept for scripts
            &["rules", "list", "--json"],
            &["rules", "remove", "x"],
            &["rules", "add", "--action", "pass", "--log"],
            &[
                "nat",
                "add",
                "--type",
                "dnat",
                "--interface",
                "em0",
                "--redirect",
                "10.0.0.1",
            ],
            &[
                "nat",
                "add",
                "--nat-type",
                "snat",
                "--interface",
                "em0",
                "--redirect",
                "10.0.0.1",
            ],
            &["nat", "list", "--json"],
            &["nat", "embed", "64:ff9b::", "10.1.2.3"],
            &["vpn", "wg-add", "--name", "a", "--address", "10.8.0.1/24"],
            &[
                "vpn",
                "wg-peer-add",
                "--tunnel",
                "t",
                "--name",
                "p",
                "--pubkey",
                "k",
            ],
            &[
                "vpn",
                "ipsec-add",
                "--name",
                "a",
                "--remote",
                "1.2.3.4",
                "--psk",
                "x",
                "--local-ts",
                "10.0.0.0/8",
                "--remote-ts",
                "10.1.0.0/16",
            ],
            &["vpn", "ipsec-status", "--json"],
            &["vpn", "list", "--json"],
            &["geoip", "list", "--json"],
            &["geoip", "database", "--json"],
            &["queue", "list", "--json"],
            &["ratelimit", "list", "--json"],
            &["routes", "list", "--json"],
            &["dns", "probe", "status"],
            &["dhcp", "subnets", "--json"],
            &["users", "list", "--json"],
            &["users", "add", "--username", "u", "--password", "p"],
            &["ids", "purge-alerts", "--yes"],
            &["ids", "retention", "30"],
            &["syslog", "show", "--json"],
            &["syslog", "set", "--pf", "true"],
            &["logrotate", "show", "--json"],
            &["plugins", "list", "--json"],
            &["plugins", "status", "--json"],
            &["reverse-proxy", "routers", "--json"],
            &["reverse-proxy", "entrypoints", "--json"],
            &["reverse-proxy", "show-config"],
            &["cluster", "status", "--json"],
            &[
                "cluster",
                "pfsync",
                "set",
                "--sync-interface",
                "em2",
                "--defer",
            ],
            &["cluster", "maintenance", "on"],
            &["multiwan", "probe", "gw", "fail"],
            &[
                "config",
                "export",
                "--secrets",
                "passphrase",
                "--passphrase-file",
                "/tmp/pw",
            ],
            &["config", "history", "--limit", "5"],
            &["config", "rollback", "3"],
            &["init", "--path", "/tmp/x.db"],
            &["interfaces"],
        ];
        for args in calls {
            let mut argv = vec!["aifw"];
            argv.extend_from_slice(args);
            if let Err(e) = Cli::try_parse_from(&argv) {
                panic!("`aifw {}` no longer parses:\n{e}", args.join(" "));
            }
        }
    }

    #[tokio::test]
    async fn completions_and_man_page_render() {
        for shell in ["bash", "zsh", "fish"] {
            let io = crate::cli::Io::buffered("");
            let (out, _) = io.captures().unwrap();
            assert_eq!(
                super::run(
                    ["aifw", "completions", shell],
                    io,
                    crate::cli::Env::default()
                )
                .await,
                0
            );
            assert!(out.contents().contains("aifw"), "{shell}");
        }
        let io = crate::cli::Io::buffered("");
        let (out, _) = io.captures().unwrap();
        assert_eq!(
            super::run(["aifw", "man"], io, crate::cli::Env::default()).await,
            0
        );
        assert!(out.contents().contains(".TH"));
    }

    #[test]
    fn version_flag() {
        let e = Cli::try_parse_from(["aifw", "--version"]).err().unwrap();
        assert_eq!(e.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn command_tree_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
