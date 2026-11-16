//! Service log tails (DHCP, resolver, time, reverse proxy). The API serves
//! the last N lines, so `--follow` polls and prints only lines it hasn't
//! shown yet.

use std::time::Duration;

use serde_json::Value;

use crate::cli::Ctx;
use crate::cli::output;

/// How often `--follow` polls.
pub const FOLLOW_INTERVAL: Duration = Duration::from_secs(2);

/// Lines from a tail response (`{data:[..]}` or a bare array).
pub fn lines(v: &Value) -> Vec<String> {
    output::rows(v)
        .into_iter()
        .map(|l| {
            l.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| l.to_string())
        })
        .collect()
}

pub fn print_log_lines(ctx: &mut Ctx, v: &Value) -> anyhow::Result<()> {
    if ctx.format().is_structured() {
        return ctx.raw(v);
    }
    let ls = lines(v);
    if ls.is_empty() {
        ctx.io.eprintln("No log lines.");
    }
    for l in ls {
        ctx.io.println(&l);
    }
    Ok(())
}

/// Lines in `next` that come after what `prev` already showed. The tail
/// window slides, so find where `prev`'s last lines reappear in `next`;
/// if they don't (log rotated, or more than a window of new lines), all of
/// `next` is new.
pub fn new_lines<'a>(prev: &[String], next: &'a [String]) -> &'a [String] {
    if prev.is_empty() {
        return next;
    }
    // Longest suffix of prev that is a prefix of next.
    let max = prev.len().min(next.len());
    for k in (1..=max).rev() {
        if prev[prev.len() - k..] == next[..k] {
            return &next[k..];
        }
    }
    next
}

/// Print a tail once, or keep following it.
pub async fn tail(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    path: &str,
    follow: bool,
) -> anyhow::Result<()> {
    let v = client.get(path).await?;
    print_log_lines(ctx, &v)?;
    if !follow {
        return Ok(());
    }
    let mut prev = lines(&v);
    loop {
        tokio::time::sleep(FOLLOW_INTERVAL).await;
        let next = lines(&client.get(path).await?);
        for l in new_lines(&prev, &next) {
            ctx.io.println(l);
        }
        prev = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sliding_window() {
        let a = v(&["1", "2", "3"]);
        assert_eq!(
            new_lines(&a, &v(&["2", "3", "4", "5"])),
            v(&["4", "5"]).as_slice()
        );
        assert_eq!(new_lines(&a, &v(&["1", "2", "3"])), &[] as &[String]);
        assert_eq!(new_lines(&a, &v(&["9"])), v(&["9"]).as_slice(), "rotated");
        assert_eq!(new_lines(&[], &v(&["x"])), v(&["x"]).as_slice());
        // A repeated line doesn't confuse the overlap search.
        let b = v(&["a", "b", "a"]);
        assert_eq!(new_lines(&b, &v(&["b", "a", "c"])), v(&["c"]).as_slice());
    }

    #[test]
    fn parses_shapes() {
        assert_eq!(
            lines(&serde_json::json!({"data": ["x", "y"]})),
            v(&["x", "y"])
        );
        assert_eq!(lines(&serde_json::json!(["z"])), v(&["z"]));
    }
}
