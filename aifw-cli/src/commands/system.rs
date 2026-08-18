//! `aifw status`, `aifw reload`, `aifw reconcile` — pf/service state checks.

use std::path::Path;

use super::common::*;
use super::shaping::create_shaping_engine;

pub async fn status(db_path: &Path) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;

    let pf = engine.pf();
    let stats = pf.get_stats().await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let rules = engine.list().await?;
    let active_rules = rules
        .iter()
        .filter(|r| r.status == aifw_common::RuleStatus::Active)
        .count();

    println!("AiFw Status");
    println!("===========");
    println!(
        "pf running:     {}",
        if stats.running { "yes" } else { "no" }
    );
    println!("pf states:      {}", stats.states_count);
    println!("pf rules (pf):  {}", stats.rules_count);
    println!("aifw rules:     {} ({} active)", rules.len(), active_rules);
    match check_pf_anchors_present().await {
        Some(true) => println!("pf anchor hooks: present"),
        Some(false) => println!("pf anchor hooks: MISSING (run `aifw reconcile`)"),
        None => println!("pf anchor hooks: unknown (pfctl probe failed)"),
    }
    if let Ok(pool) =
        sqlx::sqlite::SqlitePool::connect(&format!("sqlite://{}", db_path.display())).await
    {
        match check_dns_backend_drift(&pool).await {
            Some(msg) => println!("dns backend:    DRIFT — {msg}"),
            None => println!("dns backend:    ok"),
        }
        pool.close().await;
    }
    println!("packets in:     {}", stats.packets_in);
    println!("packets out:    {}", stats.packets_out);
    println!("bytes in:       {}", stats.bytes_in);
    println!("bytes out:      {}", stats.bytes_out);

    Ok(())
}

/// True if the running kernel pf main ruleset references the aifw anchors.
/// When this is false the whole aifw firewall config is effectively
/// bypassed — see #153.
///
/// Returns `Some(bool)` only if the probe actually succeeded. Returns
/// `None` if we couldn't tell (e.g. pfctl permission denied) — callers
/// must NOT interpret that as "drift detected" or we recreate the v5.55.1
/// regression.
async fn check_pf_anchors_present() -> Option<bool> {
    let out = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/sbin/pfctl", "-sn"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Some(s.contains("aifw-nat") || s.contains("anchor \"aifw\""))
}

/// Returns `Some(message)` if the DB's configured DNS backend doesn't
/// match what rc.conf says is enabled. See #154.
async fn check_dns_backend_drift(pool: &sqlx::SqlitePool) -> Option<String> {
    let backend = sqlx::query_scalar::<_, String>(
        "SELECT value FROM dns_resolver_config WHERE key = 'backend'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;

    let (want_key, other_key) = match backend.as_str() {
        "rdns" => ("rdns_enable", "local_unbound_enable"),
        "unbound" => ("local_unbound_enable", "rdns_enable"),
        _ => return None,
    };

    let want_val = sysrc_read_local(want_key).await;
    let other_val = sysrc_read_local(other_key).await;

    if want_val.as_deref() != Some("YES") {
        return Some(format!("db={backend} but {want_key} is not YES"));
    }
    if other_val.as_deref() == Some("YES") {
        return Some(format!("db={backend} but {other_key} is also YES"));
    }
    None
}

async fn sysrc_read_local(key: &str) -> Option<String> {
    let out = tokio::process::Command::new("/usr/sbin/sysrc")
        .args(["-n", key])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

pub async fn reload(db_path: &Path) -> anyhow::Result<()> {
    let engine = create_engine(db_path).await?;
    engine.apply_rules().await?;
    let rules = engine.list().await?;

    let nat = create_nat_engine(db_path).await?;
    nat.apply_rules().await?;
    let nat_rules = nat.list().await?;

    let shaping = create_shaping_engine(db_path).await?;
    shaping.apply_queues().await?;
    shaping.apply_rate_limits().await?;
    let queues = shaping.list_queues().await?;
    let rate_limits = shaping.list_rate_limits().await?;

    println!(
        "Reloaded {} filter rules, {} NAT rules, {} queues, {} rate limits into pf",
        rules.len(),
        nat_rules.len(),
        queues.len(),
        rate_limits.len(),
    );
    Ok(())
}

/// Heal drift between running kernel state and the source of truth
/// (pf.conf.aifw + DB). Run this on demand when `aifw status` reports
/// "pf anchor hooks: MISSING" or "dns backend: DRIFT".
///
/// Must run as root (or a user with sudo for pfctl/sysrc) — the aifw
/// user can't probe pf directly. Order matters: populate anchors BEFORE
/// reloading main pf.conf so there's no window where main hooks point
/// at empty anchors.
pub async fn reconcile(db_path: &Path) -> anyhow::Result<()> {
    // 1. Repopulate anchors from DB first — same work `aifw reload` does.
    let engine = create_engine(db_path).await?;
    engine.apply_rules().await?;
    let nat = create_nat_engine(db_path).await?;
    nat.apply_rules().await?;
    println!("  anchors repopulated from db");

    // 2. Reload main pf ruleset if anchor hooks are missing.
    const PF_CONF: &str = "/usr/local/etc/aifw/pf.conf.aifw";
    if std::path::Path::new(PF_CONF).exists() {
        match check_pf_anchors_present().await {
            Some(true) => println!("  pf main ruleset ok (anchor hooks present)"),
            Some(false) => {
                let out = tokio::process::Command::new("/usr/local/bin/sudo")
                    .args(["/sbin/pfctl", "-f", PF_CONF])
                    .output()
                    .await?;
                if out.status.success() {
                    println!("  pf main ruleset reloaded from {PF_CONF}");
                } else {
                    eprintln!(
                        "  WARNING: pfctl -f {PF_CONF} failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    );
                }
            }
            None => eprintln!("  WARNING: could not probe pf (try running as root with sudo)"),
        }
    } else {
        println!("  {PF_CONF} not present; skipped");
    }

    // 3. Fix rc.conf DNS backend flags to match DB.
    if let Ok(pool) =
        sqlx::sqlite::SqlitePool::connect(&format!("sqlite://{}", db_path.display())).await
    {
        let backend = sqlx::query_scalar::<_, String>(
            "SELECT value FROM dns_resolver_config WHERE key = 'backend'",
        )
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
        let (want_key, other_key) = match backend.as_str() {
            "rdns" => (Some("rdns_enable"), Some("local_unbound_enable")),
            "unbound" => (Some("local_unbound_enable"), Some("rdns_enable")),
            _ => (None, None),
        };
        if let (Some(want), Some(other)) = (want_key, other_key) {
            let want_val = sysrc_read_local(want).await;
            let other_val = sysrc_read_local(other).await;
            if want_val.as_deref() != Some("YES") {
                sudo_sysrc_set(want, "YES").await?;
                println!("  set {want}=YES");
            }
            if other_val.as_deref() == Some("YES") {
                sudo_sysrc_set(other, "NO").await?;
                println!("  set {other}=NO");
            }
            if want_val.as_deref() == Some("YES") && other_val.as_deref() != Some("YES") {
                println!("  dns backend rc.conf already matches db (backend={backend})");
            }
        } else {
            println!("  db backend is unset or unknown; skipping dns reconciliation");
        }
        pool.close().await;
    }

    println!("reconcile complete");
    Ok(())
}

async fn sudo_sysrc_set(key: &str, value: &str) -> anyhow::Result<()> {
    let kv = format!("{key}={value}");
    let out = aifw_core::sudo::sysrc(&[&kv]).await?;
    if !out.status.success() {
        anyhow::bail!(
            "sysrc {key}={value} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
