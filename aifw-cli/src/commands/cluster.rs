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

fn api_client() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    Ok(client)
}

async fn api_get(path: &str) -> anyhow::Result<serde_json::Value> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET {path} returned {status}: {body}");
    }
    Ok(resp.json().await?)
}

async fn api_post(path: &str, body: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.post(&url).json(body);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
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
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.put(&url).json(body);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
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
    let url = format!("{AIFW_API_BASE}{path}");
    let token = read_api_token();
    let client = api_client()?;
    let mut req = client.delete(&url);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
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
    // POST to the trigger endpoint; the daemon still probes on its own 1-second
    // tick. This returns 202 Accepted — the actual out-of-band probe mechanism
    // is a future enhancement. See aifw-api/src/cluster.rs::run_health_checks.
    let r = api_post("/api/v1/cluster/health/run", &serde_json::json!({})).await;
    match r {
        Ok(_) => println!("Health-check run requested (daemon probes on its own 1s tick)."),
        Err(e) => eprintln!("Failed: {e}"),
    }
    Ok(())
}

// ---- promote / demote / sync ----

pub async fn cluster_promote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/promote", &serde_json::json!({})).await?;
    println!("Promoted (sysctl carp.demotion=0)");
    Ok(())
}

pub async fn cluster_demote() -> anyhow::Result<()> {
    api_post("/api/v1/cluster/demote", &serde_json::json!({})).await?;
    println!("Demoted (sysctl carp.demotion=240)");
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
    let mut failures: Vec<String> = Vec::new();

    // 1. pf state-policy floating
    match tokio::process::Command::new("pfctl")
        .args(["-sr"])
        .output()
        .await
    {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("set state-policy floating") {
                failures.push("pf state-policy is not floating".into());
            }
        }
        Err(_) => failures.push("pfctl -sr failed (not on FreeBSD or pf disabled?)".into()),
    }

    // 2. pfsync0 UP
    match tokio::process::Command::new("ifconfig")
        .arg("pfsync0")
        .output()
        .await
    {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("UP") {
                failures.push("pfsync0 not UP".into());
            }
        }
        Err(_) => failures.push("pfsync0 not present (kernel module loaded?)".into()),
    }

    // 3. Some CARP VIPs configured (any interface) — only meaningful on FreeBSD
    match tokio::process::Command::new("ifconfig").output().await {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if !stdout.contains("carp:") {
                if std::env::consts::OS == "freebsd" {
                    failures.push("no CARP VIPs configured (no 'carp:' lines in ifconfig)".into());
                } else {
                    failures.push(format!(
                        "CARP check skipped: not running on FreeBSD (host OS is {})",
                        std::env::consts::OS
                    ));
                }
            }
        }
        Err(_) => failures.push("ifconfig failed".into()),
    }

    // 4+5. Status from API: peer_reachable and snapshot hash present
    let status: serde_json::Value = match api_get("/api/v1/cluster/status").await {
        Ok(s) => s,
        Err(e) => {
            failures.push(format!("/cluster/status failed: {e}"));
            serde_json::json!({})
        }
    };
    if !status
        .get("peer_reachable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        failures.push("peer unreachable".into());
    }
    if status
        .get("last_snapshot_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .is_empty()
    {
        failures.push("no config snapshot on record (replication may be stalled)".into());
    }

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
