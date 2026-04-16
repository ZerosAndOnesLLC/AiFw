//! pf runtime limit tuning.
//!
//! `pf` defaults to 100_000 entries in its state table. On a busy
//! appliance with high connection churn that fills up and pf starts
//! dropping new states (visible as `match-state` errors and stalled
//! connections). The operator should be able to lift the cap from the
//! UI without editing /etc/pf.conf by hand.
//!
//! How we apply it without disturbing rules:
//!  1. Persist the desired value in `auth_config` (key
//!     `pf_max_states`).
//!  2. Write `/usr/local/etc/aifw/pf-tuning.conf` containing just
//!     `set limit states { N }`.
//!  3. Run `pfctl -m -f <file>` — `-m` merges the options into the
//!     running pf without flushing rules or NAT.
//!
//! aifw-daemon re-applies the file at boot so the limit survives
//! restarts; the API re-applies on every save.

use sqlx::SqlitePool;
use tokio::process::Command;

const TUNING_FILE: &str = "/usr/local/etc/aifw/pf-tuning.conf";
const SUDO: &str = "/usr/local/bin/sudo";

/// Default pf state-table cap (matches FreeBSD's stock default).
pub const DEFAULT_MAX_STATES: u64 = 100_000;
/// Sanity bounds. Below 1 k the resolver/HA will flap; above 4 M is past
/// any reasonable hardware envelope and almost always indicates a typo.
pub const MIN_STATES: u64 = 1_000;
pub const MAX_STATES: u64 = 4_000_000;

/// Read the configured max-states value (the operator's wish), falling
/// back to [`DEFAULT_MAX_STATES`].
pub async fn configured_max_states(pool: &SqlitePool) -> u64 {
    sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'pf_max_states'",
    )
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

/// Write the tuning file + merge it into the running pf via `pfctl -m`.
/// Called from both the API save path and the daemon boot path.
pub async fn apply_to_pf(value: u64) -> Result<(), String> {
    // Write tuning file via sudo install (same pattern as dns_blocklists
    // — the aifw user can't write under /usr/local/etc directly).
    let body = render_tuning(value);
    let tmp = "/tmp/aifw-pf-tuning.tmp";
    tokio::fs::write(tmp, body)
        .await
        .map_err(|e| format!("write tmp: {e}"))?;
    // Make sure the parent dir exists; sudo /bin/mkdir is in the sudoers.
    let _ = Command::new(SUDO)
        .args(["/bin/mkdir", "-p", "/usr/local/etc/aifw"])
        .output()
        .await;
    let install = Command::new(SUDO)
        .args(["/usr/bin/install", "-m", "0644", tmp, TUNING_FILE])
        .output()
        .await
        .map_err(|e| format!("spawn install: {e}"))?;
    let _ = tokio::fs::remove_file(tmp).await;
    if !install.status.success() {
        return Err(format!(
            "install pf tuning file: {}",
            String::from_utf8_lossy(&install.stderr).trim()
        ));
    }

    // Merge — does NOT flush filter rules or NAT.
    let merge = Command::new(SUDO)
        .args(["/sbin/pfctl", "-m", "-f", TUNING_FILE])
        .output()
        .await
        .map_err(|e| format!("spawn pfctl: {e}"))?;
    if !merge.status.success() {
        return Err(format!(
            "pfctl -mf {TUNING_FILE}: {}",
            String::from_utf8_lossy(&merge.stderr).trim()
        ));
    }
    Ok(())
}

/// Render the pf.conf tuning fragment. Kept pure so unit tests can assert
/// the syntax — a regression here puts the whole apply path into a silent-
/// failure loop (see `set limit states { … }` incident).
fn render_tuning(value: u64) -> String {
    format!(
        "# Managed by AiFw. Do not edit by hand — change in Settings → System.\n\
         set limit states {value}\n",
    )
}

/// Re-apply the saved value at daemon startup.
pub async fn apply_on_boot(pool: &SqlitePool) {
    let v = configured_max_states(pool).await;
    if let Err(e) = apply_to_pf(v).await {
        tracing::warn!("pf-tuning apply at boot failed: {e}");
    } else {
        tracing::info!(max_states = v, "pf state-table limit applied");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `set limit states { N }` is a pf.conf parser error — the braces
    /// wrap the limit-list, not the value. This test pins the correct form.
    #[test]
    fn render_tuning_uses_unbraced_single_limit() {
        let out = render_tuning(100_000);
        assert!(
            out.contains("set limit states 100000\n"),
            "expected unbraced `set limit states <N>`, got: {out:?}"
        );
        assert!(
            !out.contains("states {"),
            "braces must not wrap a single value; got: {out:?}"
        );
    }

    #[test]
    fn render_tuning_embeds_requested_value() {
        assert!(render_tuning(250_000).contains("set limit states 250000\n"));
        assert!(render_tuning(MIN_STATES).contains(&format!("states {MIN_STATES}")));
        assert!(render_tuning(MAX_STATES).contains(&format!("states {MAX_STATES}")));
    }
}
