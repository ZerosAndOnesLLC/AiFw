//! `aifw reverse-proxy …` (TrafficCop control plane).

use aifw_core::Database;
use std::path::Path;

// ============================================================
// Reverse Proxy (TrafficCop) commands
// ============================================================

pub async fn rp_status(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    // Check service status
    let output = aifw_core::sudo::service("trafficcop", "status").await;
    let running = output.map(|o| o.status.success()).unwrap_or(false);

    println!("Reverse Proxy (TrafficCop)");
    println!("  Status: {}", if running { "running" } else { "stopped" });

    // Count entities
    let eps: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_entrypoints WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_services WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let hm: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_http_middlewares WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let tr: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_tcp_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));
    let ur: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tc_udp_routers WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    println!("  Entrypoints:     {}", eps.0);
    println!("  HTTP Routers:    {}", hr.0);
    println!("  HTTP Services:   {}", hs.0);
    println!("  HTTP Middlewares: {}", hm.0);
    println!("  TCP Routers:     {}", tr.0);
    println!("  UDP Routers:     {}", ur.0);
    Ok(())
}

pub async fn rp_start() -> anyhow::Result<()> {
    let output = aifw_core::sudo::service("trafficcop", "start").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    if !output.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

pub async fn rp_stop() -> anyhow::Result<()> {
    let output = aifw_core::sudo::service("trafficcop", "stop").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_restart() -> anyhow::Result<()> {
    let output = aifw_core::sudo::service("trafficcop", "restart").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_validate(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    println!("Generating config...");
    let yaml = rp_generate_config(pool).await?;

    let tmp = "/tmp/trafficcop-validate.yaml";
    tokio::fs::write(tmp, &yaml).await?;

    let output = tokio::process::Command::new("trafficcop")
        .args(["-c", tmp, "--validate"])
        .output()
        .await?;

    let _ = tokio::fs::remove_file(tmp).await;

    if output.status.success() {
        println!("Config is valid.");
    } else {
        println!("Config validation failed:");
        println!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

pub async fn rp_apply(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();

    println!("Generating config...");
    let yaml = rp_generate_config(pool).await?;

    // Write config through the narrow `aifw-sudo-write` helper rather
    // than the broad `sudo tee` grant (#204).
    aifw_core::sudo::write_file(
        std::path::Path::new("/usr/local/etc/trafficcop/config.yaml"),
        yaml.as_bytes(),
    )
    .await?;

    println!("Config written. Restarting service...");
    let output = aifw_core::sudo::service("trafficcop", "restart").await?;
    println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    Ok(())
}

pub async fn rp_routers(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, String, String, i32, i64)>(
        "SELECT name, rule, service, entry_points, priority, enabled FROM tc_http_routers ORDER BY name"
    ).fetch_all(pool).await?;

    if json {
        let items: Vec<serde_json::Value> = rows.iter().map(|(n, r, s, ep, p, e)| {
            serde_json::json!({"name": n, "rule": r, "service": s, "entry_points": ep, "priority": p, "enabled": *e == 1})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!(
            "{:<20} {:<40} {:<20} {:<5} ENABLED",
            "NAME", "RULE", "SERVICE", "PRI"
        );
        println!("{}", "-".repeat(95));
        for (n, r, s, _, p, e) in &rows {
            let rule_display = if r.len() > 38 {
                format!("{}...", &r[..35])
            } else {
                r.clone()
            };
            println!(
                "{:<20} {:<40} {:<20} {:<5} {}",
                n,
                rule_display,
                s,
                p,
                if *e == 1 { "yes" } else { "no" }
            );
        }
    }
    Ok(())
}

pub async fn rp_services(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, service_type, enabled FROM tc_http_services ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, t, e)| serde_json::json!({"name": n, "type": t, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<20} ENABLED", "NAME", "TYPE");
        println!("{}", "-".repeat(55));
        for (n, t, e) in &rows {
            println!("{:<30} {:<20} {}", n, t, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_middlewares(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, middleware_type, enabled FROM tc_http_middlewares ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, t, e)| serde_json::json!({"name": n, "type": t, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<30} {:<25} ENABLED", "NAME", "TYPE");
        println!("{}", "-".repeat(60));
        for (n, t, e) in &rows {
            println!("{:<30} {:<25} {}", n, t, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_entrypoints(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let rows = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT name, address, enabled FROM tc_entrypoints ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, a, e)| serde_json::json!({"name": n, "address": a, "enabled": *e == 1}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else {
        println!("{:<20} {:<20} ENABLED", "NAME", "ADDRESS");
        println!("{}", "-".repeat(45));
        for (n, a, e) in &rows {
            println!("{:<20} {:<20} {}", n, a, if *e == 1 { "yes" } else { "no" });
        }
    }
    Ok(())
}

pub async fn rp_show_config(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool();
    let yaml = rp_generate_config(pool).await?;
    println!("{}", yaml);
    Ok(())
}

/// Generate TrafficCop YAML config from DB (CLI version, mirrors the API logic).
async fn rp_generate_config(pool: &sqlx::SqlitePool) -> anyhow::Result<String> {
    use serde_json::json;

    let mut root = serde_json::Map::new();

    // Entry points
    let eps = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, address, config_json FROM tc_entrypoints WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !eps.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, addr, cfg) in &eps {
            let mut val: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            val["address"] = json!(addr);
            map.insert(name.clone(), val);
        }
        root.insert("entryPoints".to_string(), json!(map));
    }

    // HTTP
    let mut http = serde_json::Map::new();

    let routers = sqlx::query_as::<_, (String, String, String, String, String, i32, Option<String>)>(
        "SELECT name, rule, service, entry_points, middlewares, priority, tls_json FROM tc_http_routers WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, mw_json, pri, tls) in &routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mws: Vec<String> = serde_json::from_str(mw_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if !mws.is_empty() {
                rv["middlewares"] = json!(mws);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            if let Some(t) = tls
                && let Ok(tv) = serde_json::from_str::<serde_json::Value>(t)
            {
                rv["tls"] = tv;
            }
            map.insert(name.clone(), rv);
        }
        http.insert("routers".to_string(), json!(map));
    }

    let services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_http_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        http.insert("services".to_string(), json!(map));
    }

    let middlewares = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, middleware_type, config_json FROM tc_http_middlewares WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !middlewares.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, mtype, cfg) in &middlewares {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut mv = serde_json::Map::new();
            mv.insert(mtype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(mv));
        }
        http.insert("middlewares".to_string(), json!(map));
    }

    if !http.is_empty() {
        root.insert("http".to_string(), json!(http));
    }

    // TCP
    let mut tcp = serde_json::Map::new();
    let tcp_routers = sqlx::query_as::<_, (String, String, String, String, i32, Option<String>)>(
        "SELECT name, rule, service, entry_points, priority, tls_json FROM tc_tcp_routers WHERE enabled = 1"
    ).fetch_all(pool).await?;
    if !tcp_routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, pri, tls) in &tcp_routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            if let Some(t) = tls
                && let Ok(tv) = serde_json::from_str::<serde_json::Value>(t)
            {
                rv["tls"] = tv;
            }
            map.insert(name.clone(), rv);
        }
        tcp.insert("routers".to_string(), json!(map));
    }
    let tcp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_tcp_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !tcp_services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &tcp_services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        tcp.insert("services".to_string(), json!(map));
    }
    if !tcp.is_empty() {
        root.insert("tcp".to_string(), json!(tcp));
    }

    // UDP
    let mut udp = serde_json::Map::new();
    let udp_routers = sqlx::query_as::<_, (String, String, String, String, i32)>(
        "SELECT name, rule, service, entry_points, priority FROM tc_udp_routers WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !udp_routers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, rule, svc, ep_json, pri) in &udp_routers {
            let eps: Vec<String> = serde_json::from_str(ep_json).unwrap_or_default();
            let mut rv = json!({"rule": rule, "service": svc});
            if !eps.is_empty() {
                rv["entryPoints"] = json!(eps);
            }
            if *pri != 0 {
                rv["priority"] = json!(pri);
            }
            map.insert(name.clone(), rv);
        }
        udp.insert("routers".to_string(), json!(map));
    }
    let udp_services = sqlx::query_as::<_, (String, String, String)>(
        "SELECT name, service_type, config_json FROM tc_udp_services WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;
    if !udp_services.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, stype, cfg) in &udp_services {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            let mut sv = serde_json::Map::new();
            sv.insert(stype.clone(), config);
            map.insert(name.clone(), serde_json::Value::Object(sv));
        }
        udp.insert("services".to_string(), json!(map));
    }
    if !udp.is_empty() {
        root.insert("udp".to_string(), json!(udp));
    }

    // TLS
    let tls_certs =
        sqlx::query_as::<_, (String, String)>("SELECT cert_file, key_file FROM tc_tls_certs")
            .fetch_all(pool)
            .await?;
    let tls_opts =
        sqlx::query_as::<_, (String, String)>("SELECT name, config_json FROM tc_tls_options")
            .fetch_all(pool)
            .await?;
    if !tls_certs.is_empty() || !tls_opts.is_empty() {
        let mut tls = serde_json::Map::new();
        if !tls_certs.is_empty() {
            let certs: Vec<serde_json::Value> = tls_certs
                .iter()
                .map(|(c, k)| json!({"certFile": c, "keyFile": k}))
                .collect();
            tls.insert("certificates".to_string(), json!(certs));
        }
        if !tls_opts.is_empty() {
            let mut opts = serde_json::Map::new();
            for (name, cfg) in &tls_opts {
                let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
                opts.insert(name.clone(), config);
            }
            tls.insert("options".to_string(), json!(opts));
        }
        root.insert("tls".to_string(), json!(tls));
    }

    // Certificate resolvers
    let resolvers =
        sqlx::query_as::<_, (String, String)>("SELECT name, config_json FROM tc_cert_resolvers")
            .fetch_all(pool)
            .await?;
    if !resolvers.is_empty() {
        let mut map = serde_json::Map::new();
        for (name, cfg) in &resolvers {
            let config: serde_json::Value = serde_json::from_str(cfg).unwrap_or(json!({}));
            map.insert(name.clone(), config);
        }
        root.insert("certificatesResolvers".to_string(), json!(map));
    }

    // Global config (log, accessLog, api, metrics)
    let kv = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM tc_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    let get =
        |key: &str| -> Option<String> { kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()) };

    let log_level = get("log_level").unwrap_or_else(|| "info".to_string());
    root.insert(
        "log".to_string(),
        json!({
            "level": log_level,
            "filePath": "/var/log/trafficcop/trafficcop.log"
        }),
    );

    if get("access_log_enabled").as_deref() != Some("false") {
        let path =
            get("access_log_path").unwrap_or_else(|| "/var/log/trafficcop/access.log".to_string());
        let fmt = get("access_log_format").unwrap_or_else(|| "json".to_string());
        root.insert(
            "accessLog".to_string(),
            json!({"filePath": path, "format": fmt}),
        );
    }

    if get("api_dashboard").as_deref() != Some("false") {
        root.insert(
            "api".to_string(),
            json!({"dashboard": true, "insecure": true}),
        );
    }

    if get("metrics_enabled").as_deref() == Some("true") {
        let addr = get("metrics_address").unwrap_or_else(|| ":9090".to_string());
        root.insert(
            "metrics".to_string(),
            json!({"prometheus": {"address": addr}}),
        );
    }

    let yaml = serde_yaml_ng::to_string(&root)?;
    Ok(yaml)
}
