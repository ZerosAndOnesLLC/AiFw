//! `aifw cluster …` — talks to the local API (needs a token) rather than the DB.

// ============================================================
// Cluster / HA commands — loopback HTTP client helpers
// ============================================================

/// Base URL for the local AiFw API.
/// Uses HTTP on loopback (TLS termination is handled by the appliance's
/// reverse proxy on the public interface; loopback is trusted).
pub(super) const AIFW_API_BASE: &str = "http://127.0.0.1:8080";
// Note: DEFAULT_LOOPBACK_API_BASE is HTTPS (for daemon-to-daemon use with
// self-signed cert acceptance). CLI uses plain HTTP on loopback since it
// runs interactively on the appliance itself.

/// Returns the bearer token for authenticating to the local API.
///
/// Resolution order:
///   1. `AIFW_TOKEN` env var (preferred for interactive shells / scripts)
///   2. `/var/db/aifw/cli.token` (reserved for future per-host token provisioning;
///      nothing currently writes this file — see #225 / #217 for follow-up)
///
/// Returns empty string if neither source is available; protected endpoints
/// will respond 401 in that case.
pub(super) fn read_api_token() -> String {
    if let Ok(t) = std::env::var("AIFW_TOKEN")
        && !t.is_empty()
    {
        return t;
    }
    std::fs::read_to_string("/var/db/aifw/cli.token")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Base URL of the local API: `AIFW_API_URL`, else the appliance loopback
/// (`https://127.0.0.1:8080`). The API serves HTTPS; the old plain-HTTP
/// default never connected (#712).
fn api_base() -> String {
    std::env::var("AIFW_API_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| aifw_common::DEFAULT_LOOPBACK_API_BASE.to_string())
}

/// Path of the daemon loopback key (root:aifw 0640) — a `system` identity
/// with `ha:manage`, so `aifw cluster …` works as root out of the box.
const LOOPBACK_KEY_PATH: &str = "/usr/local/etc/aifw/daemon.key";

/// `Authorization` header value for the local API.
///
/// Resolution order:
///   1. `AIFW_TOKEN` env var → `Bearer <token>` (a user's JWT)
///   2. the daemon loopback key → `ApiKey <key>` (readable by root)
pub(super) fn auth_header() -> Option<String> {
    if let Ok(t) = std::env::var("AIFW_TOKEN")
        && !t.is_empty()
    {
        return Some(format!("Bearer {t}"));
    }
    std::fs::read_to_string(LOOPBACK_KEY_PATH)
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .map(|k| format!("ApiKey {k}"))
}

fn api_client() -> anyhow::Result<reqwest::Client> {
    let timeout = std::time::Duration::from_secs(10);
    if api_base().starts_with("https://") {
        // Pinned to the certificate the local API serves (#317).
        return Ok(aifw_core::peer_tls::LocalApiClient::new(timeout).get()?);
    }
    Ok(reqwest::Client::builder().timeout(timeout).build()?)
}

fn authed(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match auth_header() {
        Some(h) => req.header("Authorization", h),
        None => req,
    }
}

async fn api_get(path: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}{path}", api_base());
    let resp = authed(api_client()?.get(&url)).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET {path} returned {status}: {body}");
    }
    Ok(resp.json().await?)
}

async fn api_post(path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}{path}", api_base());
    let resp = authed(api_client()?.post(&url).json(body)).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST {path} returned {status}: {body_text}");
    }
    // Some POST endpoints return 204 No Content
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::Value::Null);
    }
    Ok(resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn api_put(path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = format!("{}{path}", api_base());
    let resp = authed(api_client()?.put(&url).json(body)).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("PUT {path} returned {status}: {body_text}");
    }
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::Value::Null);
    }
    Ok(resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn api_delete(path: &str) -> anyhow::Result<()> {
    let url = format!("{}{path}", api_base());
    let resp = authed(api_client()?.delete(&url)).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("DELETE {path} returned {status}: {body}");
    }
    Ok(())
}

// ---- cluster status ----

pub async fn cluster_status(json: bool) -> anyhow::Result<()> {
    let s: serde_json::Value = api_get("/api/v1/cluster/status").await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
    } else {
        println!(
            "Role:                 {}",
            s["role"].as_str().unwrap_or("?")
        );
        println!("Peer reachable:       {}", s["peer_reachable"]);
        println!("pfsync state count:   {}", s["pfsync_state_count"]);
        if let Some(h) = s["last_snapshot_hash"].as_str() {
            println!("Last snapshot hash:   {h}");
        }
    }
    Ok(())
}

// ---- CARP ----

pub async fn cluster_carp_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/carp").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_show(id: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = api_get(&format!("/api/v1/cluster/carp/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_add(
    vhid: u8,
    interface: &str,
    vip: &str,
    password: &str,
) -> anyhow::Result<()> {
    let (ip_str, prefix_str) = vip
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("--vip must be in 'addr/prefix' form, e.g. 192.0.2.1/24"))?;
    let virtual_ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid IP {ip_str}: {e}"))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix {prefix_str}: {e}"))?;
    let body = serde_json::json!({
        "vhid": vhid,
        "virtual_ip": virtual_ip,
        "prefix": prefix,
        "interface": interface,
        "password": password,
    });
    let v: serde_json::Value = api_post("/api/v1/cluster/carp", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_carp_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/carp/{id}")).await?;
    println!("Removed CARP VIP {id}");
    Ok(())
}

// ---- pfsync ----

pub async fn cluster_pfsync_get() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/pfsync").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_pfsync_set(
    sync_interface: &str,
    sync_peer: Option<&str>,
    defer: bool,
    latency_profile: &str,
    dhcp_link: bool,
    wg_deconfigure_on_backup: bool,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "sync_interface": sync_interface,
        "sync_peer": sync_peer,
        "defer": defer,
        "enabled": true,
        "latency_profile": latency_profile,
        "heartbeat_iface": null,
        "heartbeat_interval_ms": null,
        "dhcp_link": dhcp_link,
        "wg_deconfigure_on_backup": wg_deconfigure_on_backup,
    });
    let v: serde_json::Value = api_put("/api/v1/cluster/pfsync", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

// ---- nodes ----

pub async fn cluster_nodes_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/nodes").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_show(id: &str) -> anyhow::Result<()> {
    let v: serde_json::Value = api_get(&format!("/api/v1/cluster/nodes/{id}")).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_add(
    name: &str,
    address: &str,
    role: &str,
    api_port: Option<u16>,
) -> anyhow::Result<()> {
    let mut body = serde_json::json!({ "name": name, "address": address, "role": role });
    if let Some(p) = api_port {
        body["api_port"] = serde_json::json!(p);
    }
    let v: serde_json::Value = api_post("/api/v1/cluster/nodes", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_nodes_repin(id: &str, fingerprint: Option<&str>) -> anyhow::Result<()> {
    let body = match fingerprint {
        Some(fp) => serde_json::json!({ "fingerprint": fp }),
        None => serde_json::json!({}),
    };
    let v: serde_json::Value =
        api_post(&format!("/api/v1/cluster/nodes/{id}/repin"), &body).await?;
    match v.get("cert_fingerprint").and_then(|f| f.as_str()) {
        Some(fp) => println!("Node {id} pinned to {fp}"),
        None => println!("Node {id} pin cleared — it will be re-learned on the next contact."),
    }
    Ok(())
}

pub async fn cluster_nodes_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/nodes/{id}")).await?;
    println!("Removed node {id}");
    Ok(())
}

// ---- health checks ----

pub async fn cluster_health_list() -> anyhow::Result<()> {
    let v: serde_json::Value = api_get("/api/v1/cluster/health").await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_health_add(
    name: &str,
    check_type: &str,
    target: &str,
    interval_secs: u32,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "name": name,
        "check_type": check_type,
        "target": target,
        "interval_secs": interval_secs,
    });
    let v: serde_json::Value = api_post("/api/v1/cluster/health", &body).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub async fn cluster_health_remove(id: &str) -> anyhow::Result<()> {
    api_delete(&format!("/api/v1/cluster/health/{id}")).await?;
    println!("Removed health check {id}");
    Ok(())
}

pub async fn cluster_health_run() -> anyhow::Result<()> {
    let results = api_post("/api/v1/cluster/health/run", &serde_json::json!({})).await?;
    let rows = results.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        println!("No enabled health checks.");
    }
    let mut failed = 0;
    for r in &rows {
        let ok = r["healthy"].as_bool().unwrap_or(false);
        if !ok {
            failed += 1;
        }
        println!(
            "{:4}  {:<24} {:<16} {}",
            if ok { "OK" } else { "FAIL" },
            r["name"].as_str().unwrap_or(""),
            r["check_type"].as_str().unwrap_or(""),
            r["target"].as_str().unwrap_or("")
        );
    }
    if failed > 0 {
        anyhow::bail!("{failed} health check(s) failing");
    }
    Ok(())
}

// ---- promote / demote / sync ----

pub async fn cluster_promote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/promote", &serde_json::json!({})).await?;
    println!("Operator demotion and maintenance mode cleared");
    Ok(())
}

pub async fn cluster_demote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/demote", &serde_json::json!({})).await?;
    println!("Demoted — the peer takes the VIPs; `aifw cluster promote` undoes it");
    Ok(())
}

pub async fn cluster_maintenance(on: bool) -> anyhow::Result<()> {
    api_put(
        "/api/v1/cluster/maintenance",
        &serde_json::json!({ "enabled": on }),
    )
    .await?;
    if on {
        println!("Maintenance mode on — this node stays BACKUP, across reboots, until turned off");
    } else {
        println!("Maintenance mode off");
    }
    Ok(())
}

pub async fn cluster_sync() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/snapshot/force", &serde_json::json!({})).await?;
    println!("Snapshot pulled from peer");
    Ok(())
}

// ---- verify ----

/// Run local-side cluster verification checks.
/// Exits 0 when healthy, 1 on any failure.
/// Designed to be called by scripts/ha-verify.sh (Commit 11 / #223).
pub async fn cluster_verify(as_json: bool) -> anyhow::Result<()> {
    let failures = verify_failures().await;
    let status: serde_json::Value = api_get("/api/v1/cluster/status")
        .await
        .unwrap_or(serde_json::Value::Null);
    if as_json {
        let body = serde_json::json!({
            "ok": failures.is_empty(),
            "failures": failures,
            "status": status,
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else if failures.is_empty() {
        println!("OK — cluster healthy");
    } else {
        for f in &failures {
            eprintln!("FAIL: {f}");
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// Every check `aifw cluster verify` runs (#712: the old checks grepped
/// `pfctl -sr` for a `set` option that never appears there, and required a
/// received-snapshot hash that only a standby ever has — a healthy primary
/// could not pass).
async fn verify_failures() -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    if std::env::consts::OS != "freebsd" {
        failures.push(format!(
            "kernel checks skipped: not running on FreeBSD (host OS is {})",
            std::env::consts::OS
        ));
    }

    // 1. floating state policy in the loaded pf.conf (needed for pfsync'd
    //    states to match on the surviving node)
    let pf_conf = std::fs::read_to_string("/usr/local/etc/aifw/pf.conf.aifw").unwrap_or_default();
    if !pf_conf
        .lines()
        .any(|l| l.trim() == "set state-policy floating")
    {
        failures.push("pf.conf.aifw does not set `state-policy floating`".into());
    }

    // 2. kernel CARP + pfsync
    let view = aifw_core::carp::kernel_view().await;
    if view.vhids.is_empty() {
        failures.push("no CARP vhids in the kernel".into());
    }
    match view.aggregate_state() {
        "split" => failures.push("vhids disagree (MASTER on some, BACKUP on others)".into()),
        "init" => failures.push("a vhid is still in INIT".into()),
        _ => {}
    }
    if aifw_core::carp::preempt_enabled().await != Some(true) {
        failures.push("net.inet.carp.preempt is not 1".into());
    }
    match &view.pfsync {
        None => failures.push("pfsync0 does not exist".into()),
        Some(p) if !p.up => failures.push("pfsync0 is down".into()),
        Some(p) if p.syncdev.is_none() => failures.push("pfsync0 has no syncdev".into()),
        Some(p) if p.syncok == Some(false) => {
            failures.push("pfsync bulk update not complete (syncok 0)".into())
        }
        _ => {}
    }
    let reasons = aifw_core::carp::held_reasons().await;
    if !reasons.is_empty() {
        let names: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
        failures.push(format!("demotion held: {}", names.join(", ")));
    }

    // 3. API view: peer answering, no split brain, replication state
    match api_get("/api/v1/cluster/status").await {
        Ok(st) => {
            if !st["peer_reachable"].as_bool().unwrap_or(false) {
                failures.push("peer is not answering on its API".into());
            }
            if st["split_brain"].as_bool().unwrap_or(false) {
                failures.push("split brain: both nodes report MASTER".into());
            }
            if st["configured_role"] == "secondary"
                && st["last_snapshot_hash"].as_str().unwrap_or("").is_empty()
            {
                failures.push("no config snapshot received from the primary yet".into());
            }
        }
        Err(e) => failures.push(format!("/cluster/status failed: {e}")),
    }
    failures
}
