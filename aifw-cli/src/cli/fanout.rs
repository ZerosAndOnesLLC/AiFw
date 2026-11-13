//! Fan a read-only command out across several contexts (`--context a,b`,
//! `--all-contexts`): the same command runs once per context, in-process
//! and concurrently, and the results are merged.

use std::ffi::OsString;

use futures_util::StreamExt;
use serde_json::{Value, json};

use super::exit::{self, CliError};
use super::io::Io;
use super::{Env, Format};

/// Leaf subcommand names that never change anything.
const READ_ONLY_LEAVES: &[&str] = &[
    "list",
    "ls",
    "show",
    "status",
    "get",
    "history",
    "diff",
    "check",
    "logs",
    "stats",
    "lookup",
    "whoami",
    "pending",
    "interfaces",
    "instances",
    "gateways",
    "groups",
    "policies",
    "leaks",
    "flows",
    "fib-info",
    "system",
    "subnets",
    "reservations",
    "leases",
    "sa",
    "verify",
    "peer-state",
    "failover-history",
    "next-ip",
    "search",
    "about",
    "metrics",
    "connections",
    "blocked",
    "info",
    "timezones",
    "account",
    "routers",
    "services",
    "middlewares",
    "version",
    "export",
    "search-rules",
];

/// Collections whose verb defaults to `list` when omitted.
const LIST_BY_DEFAULT: &[&str] = &[
    "entrypoints",
    "http-routers",
    "http-services",
    "http-middlewares",
    "tcp-routers",
    "tcp-services",
    "udp-routers",
    "udp-services",
    "tls-certs",
    "tls-options",
    "cert-resolvers",
];

/// Is the parsed command read-only? `path` is the subcommand chain, e.g.
/// `["rules", "list"]`.
pub fn is_read_only(path: &[String]) -> bool {
    let Some(leaf) = path.last() else {
        return false;
    };
    READ_ONLY_LEAVES.contains(&leaf.as_str())
        || (path.len() >= 2 && LIST_BY_DEFAULT.contains(&leaf.as_str()))
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
