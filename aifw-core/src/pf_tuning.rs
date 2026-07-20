//! pf runtime limit tuning.
//!
//! `pf` defaults to 100_000 entries in its state table. On a busy
//! appliance with high connection churn that fills up and pf starts
//! dropping new states (visible as `match-state` errors and stalled
//! connections). The operator should be able to lift the cap from the
//! UI without editing pf.conf by hand.
//!
//! How we apply it without disturbing rules:
//!  1. Persist the desired value in `auth_config` (key `pf_max_states`).
//!  2. Patch a `set limit states N` line into
//!     `/usr/local/etc/aifw/pf.conf.aifw` (replace the existing line or
//!     insert into the options section), validate the staged copy with
//!     `pfctl -nf`, commit via the narrow `aifw-sudo-write` helper, and
//!     reload the FULL file with `pfctl -f` — the same
//!     patch/validate/commit/reload flow the anchor patcher uses, covered
//!     by the same sudoers grants.
//!  3. Boot picks the value up naturally because pf_start loads
//!     pf.conf.aifw; `apply_on_boot` just re-patches idempotently.
//!
//! HISTORY (#533 harness finding): the previous implementation loaded an
//! options-only tuning file with `pfctl -m -f`. `-m` merges the *options*,
//! but `-f` still replaces the *ruleset* with the file's — zero — rules,
//! so every boot and every save wiped the main pf ruleset. On appliances
//! the daemon's `reconcile_pf_main` auto-heal immediately reloaded
//! pf.conf.aifw, masking it (and explaining the long-mysterious
//! "main ruleset empty at boot" LAN outages it was built to heal); on any
//! host without pf.conf.aifw the firewall silently stayed rule-less.

use sqlx::SqlitePool;
use tokio::process::Command;

const PF_CONF_AIFW: &str = "/usr/local/etc/aifw/pf.conf.aifw";
/// Staging path for the patched copy — matches the existing sudoers grant
/// `pfctl -nf /tmp/aifw-pf.conf.aifw.patched` (see aifw-setup sudoers).
const PATCH_STAGE: &str = "/tmp/aifw-pf.conf.aifw.patched";
const SUDO: &str = "/usr/local/bin/sudo";

/// Default pf state-table cap (matches FreeBSD's stock default).
pub const DEFAULT_MAX_STATES: u64 = 100_000;
/// Sanity bounds. Below 1 k the resolver/HA will flap; above 4 M is past
/// any reasonable hardware envelope and almost always indicates a typo.
pub const MIN_STATES: u64 = 1_000;
/// Upper sanity bound for `pf_max_states` (4 million state entries)
pub const MAX_STATES: u64 = 4_000_000;

/// Read the configured max-states value (the operator's wish), falling
/// back to [`DEFAULT_MAX_STATES`].
pub async fn configured_max_states(pool: &SqlitePool) -> u64 {
    sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'pf_max_states'")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|(v,)| v.parse::<u64>().ok())
        .filter(|n| (MIN_STATES..=MAX_STATES).contains(n))
        .unwrap_or(DEFAULT_MAX_STATES)
}

/// Persist + apply a new max-states value. Returns the (possibly clamped)
/// value that's now in effect.
pub async fn set_max_states(pool: &SqlitePool, requested: u64) -> Result<u64, String> {
    if !(MIN_STATES..=MAX_STATES).contains(&requested) {
        return Err(format!(
            "max_states must be between {MIN_STATES} and {MAX_STATES} (got {requested})"
        ));
    }
    sqlx::query(
        r#"INSERT INTO auth_config (key, value) VALUES ('pf_max_states', ?1)
           ON CONFLICT(key) DO UPDATE SET value = excluded.value"#,
    )
    .bind(requested.to_string())
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    apply_to_pf(requested).await?;
    Ok(requested)
}

/// Read the live limit out of `pfctl -sm`. Useful for the UI to show
/// "configured value vs actual running value" (they differ if the apply
/// failed, e.g. pf isn't running).
pub async fn live_max_states() -> Option<u64> {
    let out = Command::new("pfctl").args(["-sm"]).output().await.ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if line.starts_with("states") {
            return line.split_whitespace().nth(3)?.parse::<u64>().ok();
        }
    }
    None
}

/// Patch the limit into pf.conf.aifw and reload the full ruleset.
/// Called from both the API save path and the daemon boot path.
pub async fn apply_to_pf(value: u64) -> Result<(), String> {
    let current = match tokio::fs::read_to_string(PF_CONF_AIFW).await {
        Ok(c) => c,
        Err(e) => {
            // Dev hosts / test harnesses have no appliance pf.conf. The DB
            // keeps the operator's value; it applies once the file exists.
            return Err(format!(
                "{PF_CONF_AIFW} not readable ({e}); limit stored in DB only"
            ));
        }
    };

    let patched = patch_limit_line(&current, value);
    if patched == current {
        // Already at the requested value — nothing to reload.
        return Ok(());
    }

    tokio::fs::write(PATCH_STAGE, &patched)
        .await
        .map_err(|e| format!("stage patched pf.conf: {e}"))?;

    // Dry-run validate the staged copy before touching the real file.
    let validate = Command::new(SUDO)
        .args(["/sbin/pfctl", "-nf", PATCH_STAGE])
        .output()
        .await
        .map_err(|e| format!("spawn pfctl -nf: {e}"))?;
    if !validate.status.success() {
        let _ = tokio::fs::remove_file(PATCH_STAGE).await;
        return Err(format!(
            "patched pf.conf did not validate: {}",
            String::from_utf8_lossy(&validate.stderr).trim()
        ));
    }

    // Commit through the narrow aifw-sudo-write helper, then reload the
    // complete file — anchors are unaffected (pf.conf.aifw carries no
    // `load anchor` lines since v5.57.3).
    crate::sudo::write_file(std::path::Path::new(PF_CONF_AIFW), patched.as_bytes())
        .await
        .map_err(|e| format!("commit patched pf.conf: {e}"))?;
    let reload = Command::new(SUDO)
        .args(["/sbin/pfctl", "-f", PF_CONF_AIFW])
        .output()
        .await
        .map_err(|e| format!("spawn pfctl -f: {e}"))?;
    let _ = tokio::fs::remove_file(PATCH_STAGE).await;
    if !reload.status.success() {
        return Err(format!(
            "pfctl -f {PF_CONF_AIFW}: {}",
            String::from_utf8_lossy(&reload.stderr).trim()
        ));
    }
    Ok(())
}

/// Pure patcher: replace an existing `set limit states …` line, or insert
/// one after the last `set …` option line (options must precede rules in
/// pf.conf grammar), or after the leading comment block when no options
/// exist. Kept pure so unit tests pin the syntax — `set limit states { N }`
/// (braced single value) is a pf parse error.
fn patch_limit_line(conf: &str, value: u64) -> String {
    let limit_line = format!("set limit states {value}");
    let lines: Vec<&str> = conf.lines().collect();

    if lines
        .iter()
        .any(|l| l.trim_start().starts_with("set limit states"))
    {
        let out: Vec<String> = lines
            .iter()
            .map(|l| {
                if l.trim_start().starts_with("set limit states") {
                    limit_line.clone()
                } else {
                    (*l).to_string()
                }
            })
            .collect();
        return out.join("\n") + "\n";
    }

    // Insert after the last `set ` option line, else after leading comments.
    let insert_at = lines
        .iter()
        .rposition(|l| l.trim_start().starts_with("set "))
        .map(|i| i + 1)
        .unwrap_or_else(|| {
            lines
                .iter()
                .position(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .unwrap_or(lines.len())
        });

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 1);
    for (i, l) in lines.iter().enumerate() {
        if i == insert_at {
            out.push(limit_line.clone());
        }
        out.push((*l).to_string());
    }
    if insert_at >= lines.len() {
        out.push(limit_line);
    }
    out.join("\n") + "\n"
}

/// Re-apply the saved value at daemon startup. Idempotent: when
/// pf.conf.aifw already carries the value (the normal case — boot loaded
/// it), this is a no-op with no pf reload.
pub async fn apply_on_boot(pool: &SqlitePool) {
    let v = configured_max_states(pool).await;
    if let Err(e) = apply_to_pf(v).await {
        tracing::warn!("pf-tuning apply at boot failed: {e}");
    } else {
        tracing::info!(max_states = v, "pf state-table limit ensured");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `set limit states { N }` is a pf.conf parser error — the braces
    /// wrap the limit-list, not the value. This test pins the correct form.
    #[test]
    fn patch_uses_unbraced_single_limit() {
        let out = patch_limit_line("set skip on lo0\n\nanchor \"aifw\"\n", 100_000);
        assert!(
            out.contains("set limit states 100000\n"),
            "expected unbraced `set limit states <N>`, got: {out:?}"
        );
        assert!(!out.contains("states {"));
    }

    #[test]
    fn patch_replaces_existing_limit_line() {
        let conf = "# header\nset skip on lo0\nset limit states 50000\n\nanchor \"aifw\"\n";
        let out = patch_limit_line(conf, 250_000);
        assert!(out.contains("set limit states 250000"));
        assert!(!out.lines().any(|l| l == "set limit states 50000"));
        assert_eq!(
            out.matches("set limit states").count(),
            1,
            "must not duplicate the limit line"
        );
    }

    #[test]
    fn patch_inserts_after_last_option() {
        let conf =
            "# header\nset skip on lo0\nset block-policy drop\n\nscrub in all\n\nanchor \"aifw\"\n";
        let out = patch_limit_line(conf, 200_000);
        let lines: Vec<&str> = out.lines().collect();
        let opt_idx = lines
            .iter()
            .position(|l| *l == "set block-policy drop")
            .unwrap();
        assert_eq!(lines[opt_idx + 1], "set limit states 200000");
        // Options must precede rules — the anchor line must come after.
        let anchor_idx = lines.iter().position(|l| *l == "anchor \"aifw\"").unwrap();
        assert!(anchor_idx > opt_idx + 1);
    }

    #[test]
    fn patch_handles_conf_without_options() {
        let conf = "# only comments\n# more\nanchor \"aifw\"\n";
        let out = patch_limit_line(conf, 150_000);
        let lines: Vec<&str> = out.lines().collect();
        let limit_idx = lines
            .iter()
            .position(|l| *l == "set limit states 150000")
            .unwrap();
        let anchor_idx = lines.iter().position(|l| *l == "anchor \"aifw\"").unwrap();
        assert!(limit_idx < anchor_idx, "limit must precede rules");
    }

    #[test]
    fn patch_is_idempotent() {
        let conf = "set skip on lo0\nanchor \"aifw\"\n";
        let once = patch_limit_line(conf, 100_000);
        let twice = patch_limit_line(&once, 100_000);
        assert_eq!(once, twice);
    }
}
