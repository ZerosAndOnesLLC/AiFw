//! Fan a read-only command out across several contexts (`--context a,b`,
//! `--all-contexts`): the same command runs once per context, in-process
//! and concurrently, and the results are merged.

use std::ffi::OsString;

use futures_util::StreamExt;
use serde_json::{Value, json};

use super::exit::{self, CliError};
use super::io::Io;
use super::{Env, Format};

/// Full command paths that only read. Matched exactly (not by leaf name:
/// `acme account --email` and `totp verify` share leaf names with read-only
/// commands but write). Commands whose flags can turn a read into a write
/// (`geoip database`, `dns config`, `ids retention`, `system general`, …)
/// are deliberately absent. `compat_tests` checks every entry exists.
pub const READ_ONLY_PATHS: &[&str] = &[
    "status",
    "about",
    "whoami",
    "pending",
    "connections",
    "blocked",
    "logs",
    "audit",
    "metrics",
    "metrics show",
    "metrics list",
    "metrics series",
    "interfaces",
    "interfaces list",
    "interfaces detail",
    "interfaces stats",
    "rules list",
    "rules show",
    "rules system",
    "nat list",
    "nat show",
    "nat pf-output",
    "aliases list",
    "aliases show",
    "schedules list",
    "vlans list",
    "queue list",
    "queue status",
    "geoip list",
    "geoip lookup",
    "routes list",
    "routes system",
    "dns list",
    "dns status",
    "dns logs",
    "dns stats",
    "dns hosts",
    "dns hosts list",
    "dns hosts show",
    "dns domains",
    "dns domains list",
    "dns domains show",
    "dns acls",
    "dns acls list",
    "dns acls show",
    "dns whitelist",
    "dns whitelist list",
    "dns customblocks",
    "dns customblocks list",
    "dns blocklists list",
    "dhcp status",
    "dhcp subnets",
    "dhcp reservations",
    "dhcp leases",
    "dhcp logs",
    "time status",
    "time logs",
    "time sources",
    "time sources list",
    "time sources show",
    "vpn list",
    "vpn ipsec-status",
    "vpn wg list",
    "vpn wg status",
    "vpn wg peers list",
    "vpn wg peers next-ip",
    "vpn ipsec list",
    "vpn ipsec show",
    "vpn ipsec status",
    "vpn ipsec sa",
    "ids alerts list",
    "ids alerts show",
    "ids stats",
    "ids rulesets list",
    "ids rules search",
    "ids rules show",
    "ids suppressions list",
    "ai audit",
    "plugins list",
    "plugins show",
    "plugins status",
    "plugins logs",
    "syslog show",
    "syslog status",
    "logrotate show",
    "reverse-proxy status",
    "reverse-proxy logs",
    "reverse-proxy routers",
    "reverse-proxy services",
    "reverse-proxy middlewares",
    "reverse-proxy entrypoints",
    "reverse-proxy entrypoints list",
    "reverse-proxy http-routers",
    "reverse-proxy http-routers list",
    "reverse-proxy http-services",
    "reverse-proxy http-services list",
    "reverse-proxy http-middlewares",
    "reverse-proxy http-middlewares list",
    "reverse-proxy tcp-routers",
    "reverse-proxy tcp-services",
    "reverse-proxy udp-routers",
    "reverse-proxy udp-services",
    "reverse-proxy tls-certs",
    "reverse-proxy tls-options",
    "reverse-proxy cert-resolvers",
    "multiwan instances",
    "multiwan gateways",
    "multiwan groups",
    "multiwan policies",
    "multiwan leaks",
    "multiwan flows",
    "multiwan fib-info",
    "multiwan export",
    "cluster status",
    "cluster carp list",
    "cluster carp show",
    "cluster pfsync get",
    "cluster nodes list",
    "cluster nodes show",
    "cluster health list",
    "cluster peer-state",
    "cluster failover-history",
    "cluster verify",
    "update status",
    "update history",
    "config show",
    "config history",
    "config diff",
    "config check",
    "backup s3 list",
    "settings get",
    "settings ai-models",
    "system info",
    "system timezones",
    "acme certs list",
    "acme certs show",
    "acme dns-providers",
    "acme dns-providers list",
    "acme targets list",
    "ddns records",
    "ddns records list",
    "ca show",
    "ca crl",
    "ca certs list",
    "ca certs show",
    "users list",
    "users show",
    "roles list",
    "roles show",
    "roles permissions",
    "api-keys list",
];

/// Is the parsed command read-only? `path` is the subcommand chain, e.g.
/// `["rules", "list"]`.
pub fn is_read_only(path: &[String]) -> bool {
    !path.is_empty() && READ_ONLY_PATHS.contains(&path.join(" ").as_str())
}

/// Strip the fan-out flags from argv so each per-context run gets exactly
/// one `--context`.
pub fn strip_fanout_args(args: &[OsString]) -> Vec<OsString> {
    let mut out = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = a.to_string_lossy();
        match s.as_ref() {
            "--context" | "--parallel" => skip_next = true,
            "--all-contexts" => {}
            _ if s.starts_with("--context=") || s.starts_with("--parallel=") => {}
            _ => out.push(a.clone()),
        }
    }
    out
}

/// One context's outcome.
pub struct Outcome {
    pub context: String,
    pub code: i32,
    pub out: String,
    pub err: String,
}

/// Run `args` once per context (concurrently, at most `parallel` at a time).
pub async fn run_all(
    args: Vec<OsString>,
    contexts: Vec<String>,
    parallel: usize,
    env: Env,
) -> Vec<Outcome> {
    let base = strip_fanout_args(&args);
    let runs = contexts.into_iter().map(|ctx| {
        let mut argv = base.clone();
        argv.push("--context".into());
        argv.push(ctx.clone().into());
        let env = env.clone();
        async move {
            let io = Io::buffered("");
            let (out, err) = io.captures().expect("buffered io has captures");
            let code = Box::pin(crate::app::run(argv, io, env)).await;
            Outcome {
                context: ctx,
                code,
                out: out.contents(),
                err: err.contents(),
            }
        }
    });
    futures_util::stream::iter(runs)
        .buffered(parallel.max(1))
        .collect()
        .await
}

/// Print merged results; returns the exit code.
pub fn report(io: &mut Io, outcomes: &[Outcome], format: Format) -> anyhow::Result<i32> {
    if format.is_structured() {
        let arr: Vec<Value> = outcomes
            .iter()
            .map(|o| {
                let result = serde_json::from_str::<Value>(o.out.trim())
                    .unwrap_or_else(|_| if o.out.trim().is_empty() { Value::Null } else { json!(o.out.trim()) });
                let error = (o.code != 0).then(|| {
                    serde_json::from_str::<Value>(o.err.trim())
                        .ok()
                        .and_then(|e| e["error"].as_str().map(str::to_string))
                        .unwrap_or_else(|| o.err.trim().to_string())
                });
                json!({ "context": o.context, "exit_code": o.code, "result": result, "error": error })
            })
            .collect();
        io.println(&super::output::structured(&Value::Array(arr), format)?);
    } else {
        for (i, o) in outcomes.iter().enumerate() {
            if i > 0 {
                io.println("");
            }
            io.println(&format!("== {} ==", o.context));
            if !o.out.trim().is_empty() {
                io.println(o.out.trim_end());
            }
            if o.code != 0 {
                io.println(&format!(
                    "error (exit {}): {}",
                    o.code,
                    o.err.trim().trim_start_matches("Error: ")
                ));
            }
        }
    }
    Ok(exit_code(outcomes))
}

/// 0 when all succeeded; 8 when some failed; the shared code when all
/// failed the same way (else 8).
pub fn exit_code(outcomes: &[Outcome]) -> i32 {
    let failed: Vec<i32> = outcomes
        .iter()
        .map(|o| o.code)
        .filter(|c| *c != 0)
        .collect();
    if failed.is_empty() {
        exit::OK
    } else if failed.len() == outcomes.len() && failed.iter().all(|c| *c == failed[0]) {
        failed[0]
    } else {
        exit::PARTIAL
    }
}

/// With fan-out, each context's own credential, URL and pin are used; a
/// single ad-hoc one (e.g. an exported AIFW_TOKEN) must not be sent to
/// every appliance.
pub fn require_per_context_credentials(g: &super::global::GlobalArgs) -> Result<(), CliError> {
    if g.api_key.is_some() || g.url.is_some() || g.pin.is_some() {
        return Err(CliError::Usage(
            "fan-out uses each context's own credentials: drop --api-key/--url/--pin and unset AIFW_TOKEN/AIFW_API_URL".into(),
        ));
    }
    Ok(())
}

/// Refuse to fan out a command that changes things.
pub fn require_read_only(path: &[String]) -> Result<(), CliError> {
    if is_read_only(path) {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "`aifw {}` changes things, so it runs against one appliance at a time; pick a single --context",
            path.join(" ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn read_only_classification() {
        assert!(is_read_only(&p(&["rules", "list"])));
        assert!(is_read_only(&p(&["status"])));
        assert!(is_read_only(&p(&["cluster", "verify"])));
        assert!(is_read_only(&p(&["reverse-proxy", "entrypoints"])));
        // Leaf names shared with writes don't make a write read-only.
        assert!(!is_read_only(&p(&["acme", "account"])));
        assert!(!is_read_only(&p(&["totp", "verify"])));
        assert!(!is_read_only(&p(&["reverse-proxy", "entrypoints", "add"])));
        assert!(!is_read_only(&p(&["rules", "add"])));
        assert!(!is_read_only(&p(&["apply"])));
        assert!(!is_read_only(&p(&["update", "install"])));
        assert!(!is_read_only(&p(&[])));
        assert!(require_read_only(&p(&["rules", "rm"])).is_err());
    }

    #[test]
    fn strips_fanout_flags() {
        let a: Vec<OsString> = [
            "aifw",
            "--context",
            "a,b",
            "rules",
            "list",
            "--parallel",
            "3",
            "--all-contexts",
            "--context=x",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let s: Vec<String> = strip_fanout_args(&a)
            .iter()
            .map(|x| x.to_string_lossy().into_owned())
            .collect();
        assert_eq!(s, vec!["aifw", "rules", "list"]);
    }

    #[test]
    fn exit_codes() {
        let o = |code| Outcome {
            context: "c".into(),
            code,
            out: String::new(),
            err: String::new(),
        };
        assert_eq!(exit_code(&[o(0), o(0)]), 0);
        assert_eq!(exit_code(&[o(0), o(7)]), 8);
        assert_eq!(exit_code(&[o(7), o(7)]), 7);
        assert_eq!(exit_code(&[o(7), o(3)]), 8);
    }
}
