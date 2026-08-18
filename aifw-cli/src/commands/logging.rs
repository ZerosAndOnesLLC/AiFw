//! `aifw syslog …` and `aifw logrotate …`.

use aifw_core::Database;
use std::path::Path;

// ============================================================================
// Remote syslog forwarding (aifw syslog ...)
// ============================================================================

/// Optional field updates for `aifw syslog set`; `None` = keep current value.
pub struct SyslogSetOpts {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub transport: Option<String>,
    pub format: Option<String>,
    pub facility: Option<String>,
    pub hostname: Option<String>,
    pub pf: Option<bool>,
    pub ids: Option<bool>,
    pub app: Option<bool>,
    pub app_min_level: Option<String>,
    pub disable_local: Option<bool>,
}

// ============================================================
// Log rotation (#205)
// ============================================================

fn human_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    let b = b as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.0} KB", b / KB)
    } else {
        format!("{b} B")
    }
}

pub async fn logrotate_show(db_path: &Path, json: bool) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    let db = Database::new(db_path).await?;
    let cfg = lr::load(db.pool()).await;
    let logs = lr::status().await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "config": cfg,
                "logs": logs,
                "conf_path": lr::CONF_PATH,
            }))?
        );
        return Ok(());
    }
    println!("Log rotation policy (all AiFw-managed service logs)");
    println!("  Rotate above:   {} MB", cfg.max_size_mb);
    println!("  Keep:           {} rotated generation(s)", cfg.keep);
    println!("  Compression:    {}", cfg.compression.as_str());
    println!("  newsyslog conf: {}", lr::CONF_PATH);
    println!();
    println!(
        "  {:<13} {:<36} {:>10} {:>8} {:>10}",
        "SERVICE", "LOG", "SIZE", "ROTATED", "TOTAL"
    );
    for l in &logs {
        println!(
            "  {:<13} {:<36} {:>10} {:>8} {:>10}",
            l.service,
            l.path,
            l.size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "-".to_string()),
            l.rotated,
            human_bytes(l.total_bytes)
        );
    }
    Ok(())
}

pub async fn logrotate_set(
    db_path: &Path,
    max_size: Option<u32>,
    keep: Option<u32>,
    compression: Option<&str>,
) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    if max_size.is_none() && keep.is_none() && compression.is_none() {
        anyhow::bail!("nothing to change — pass --max-size, --keep and/or --compression");
    }
    let db = Database::new(db_path).await?;
    let mut cfg = lr::load(db.pool()).await;
    if let Some(v) = max_size {
        cfg.max_size_mb = v;
    }
    if let Some(v) = keep {
        cfg.keep = v;
    }
    if let Some(c) = compression {
        cfg.compression = lr::Compression::parse(c).ok_or_else(|| {
            anyhow::anyhow!("unknown compression {c:?} (gzip, bzip2, xz, zstd, none)")
        })?;
    }
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    lr::save(db.pool(), &cfg).await?;
    println!(
        "Saved: rotate above {} MB, keep {}, compression {}.",
        cfg.max_size_mb,
        cfg.keep,
        cfg.compression.as_str()
    );
    if cfg!(target_os = "freebsd") {
        lr::write_conf(&cfg).await?;
        match lr::run_now().await {
            Ok(msg) => println!("{msg}"),
            Err(e) => println!("Policy written; immediate newsyslog pass failed: {e}"),
        }
    }
    Ok(())
}

pub async fn logrotate_rotate(db_path: &Path, path: Option<&str>) -> anyhow::Result<()> {
    use aifw_core::log_rotation as lr;
    if !cfg!(target_os = "freebsd") {
        anyhow::bail!("log rotation is only available on the FreeBSD appliance");
    }
    // Make sure the fragment reflects the stored policy before rotating.
    let db = Database::new(db_path).await?;
    let cfg = lr::load(db.pool()).await;
    lr::write_conf(&cfg).await?;
    let msg = match path {
        Some(p) => lr::rotate_now(p).await?,
        None => lr::run_now().await?,
    };
    println!("{msg}");
    Ok(())
}

async fn syslog_load(
    db_path: &Path,
) -> anyhow::Result<(Database, aifw_common::syslog::SyslogConfig)> {
    let db = Database::new(db_path).await?;
    aifw_common::syslog::migrate(db.pool()).await?;
    let cfg = aifw_common::syslog::load(db.pool()).await;
    Ok((db, cfg))
}

fn syslog_print_effect() {
    println!("Change takes effect within 60 seconds (all AiFw services poll for syslog config).");
}

pub async fn syslog_show(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let (_db, cfg) = syslog_load(db_path).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg)?);
        return Ok(());
    }
    let facility_label = aifw_common::syslog::facility_name(cfg.facility)
        .map(|n| format!("{} ({n})", cfg.facility))
        .unwrap_or_else(|| cfg.facility.to_string());
    println!("Remote syslog forwarding");
    println!(
        "  Enabled:        {}",
        if cfg.enabled { "yes" } else { "no" }
    );
    println!(
        "  Server:         {}",
        if cfg.host.is_empty() {
            "(not configured)".to_string()
        } else {
            format!("{}:{}", cfg.host, cfg.port)
        }
    );
    println!("  Transport:      {}", cfg.transport.as_str());
    println!("  Format:         {}", cfg.format.as_str());
    println!("  Facility:       {facility_label}");
    println!(
        "  Hostname:       {}",
        if cfg.hostname_override.is_empty() {
            "(system hostname)"
        } else {
            &cfg.hostname_override
        }
    );
    println!("  Categories:");
    println!(
        "    pf logs:      {}",
        if cfg.pf_enabled { "on" } else { "off" }
    );
    println!(
        "    IDS alerts:   {}",
        if cfg.ids_enabled { "on" } else { "off" }
    );
    println!(
        "    app logs:     {}{}",
        if cfg.app_enabled { "on" } else { "off" },
        if cfg.app_enabled {
            format!(" (min level {})", cfg.app_min_level)
        } else {
            String::new()
        }
    );
    println!(
        "  Local storage:  {}",
        if cfg.disable_local {
            "disabled while forwarding"
        } else {
            "kept"
        }
    );
    Ok(())
}

pub async fn syslog_enable(db_path: &Path, enabled: bool) -> anyhow::Result<()> {
    let (db, mut cfg) = syslog_load(db_path).await?;
    cfg.enabled = enabled;
    if let Err(e) = cfg.validate() {
        anyhow::bail!("{e} — set one with: aifw syslog set --host <server>");
    }
    aifw_common::syslog::save(db.pool(), &cfg).await?;
    if enabled {
        println!(
            "Remote syslog forwarding enabled ({}:{} over {}).",
            cfg.host,
            cfg.port,
            cfg.transport.as_str()
        );
        if !cfg.pf_enabled && !cfg.ids_enabled && !cfg.app_enabled {
            println!(
                "  Note: no categories are on yet — enable some with e.g. 'aifw syslog set --pf true'."
            );
        }
    } else {
        println!("Remote syslog forwarding disabled.");
    }
    syslog_print_effect();
    Ok(())
}

pub async fn syslog_set(db_path: &Path, opts: SyslogSetOpts) -> anyhow::Result<()> {
    let (db, mut cfg) = syslog_load(db_path).await?;
    if let Some(h) = opts.host {
        cfg.host = h;
    }
    if let Some(p) = opts.port {
        cfg.port = p;
    }
    if let Some(t) = opts.transport {
        cfg.transport = match t.to_ascii_lowercase().as_str() {
            "udp" => aifw_common::syslog::Transport::Udp,
            "tcp" => aifw_common::syslog::Transport::Tcp,
            other => anyhow::bail!("transport must be udp or tcp (got '{other}')"),
        };
    }
    if let Some(f) = opts.format {
        cfg.format = match f.to_ascii_lowercase().as_str() {
            "rfc3164" | "bsd" => aifw_common::syslog::SyslogFormat::Rfc3164,
            "rfc5424" => aifw_common::syslog::SyslogFormat::Rfc5424,
            other => anyhow::bail!("format must be rfc3164 (bsd) or rfc5424 (got '{other}')"),
        };
    }
    if let Some(f) = opts.facility {
        cfg.facility = aifw_common::syslog::facility_from_name(&f).ok_or_else(|| {
            anyhow::anyhow!("unknown facility '{f}' (use a name like local0 or a number 0-23)")
        })?;
    }
    if let Some(h) = opts.hostname {
        cfg.hostname_override = h;
    }
    if let Some(v) = opts.pf {
        cfg.pf_enabled = v;
    }
    if let Some(v) = opts.ids {
        cfg.ids_enabled = v;
    }
    if let Some(v) = opts.app {
        cfg.app_enabled = v;
    }
    if let Some(l) = opts.app_min_level {
        cfg.app_min_level = l.to_ascii_lowercase();
    }
    if let Some(v) = opts.disable_local {
        cfg.disable_local = v;
    }
    cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
    aifw_common::syslog::save(db.pool(), &cfg).await?;
    println!("Syslog settings updated.");
    if !cfg.enabled {
        println!("  Forwarding is currently disabled — turn it on with 'aifw syslog enable'.");
    }
    syslog_print_effect();
    Ok(())
}

pub async fn syslog_test(
    db_path: &Path,
    host: Option<String>,
    port: Option<u16>,
) -> anyhow::Result<()> {
    let (_db, mut cfg) = syslog_load(db_path).await?;
    if let Some(h) = host {
        cfg.host = h;
    }
    if let Some(p) = port {
        cfg.port = p;
    }
    anyhow::ensure!(
        !cfg.host.trim().is_empty(),
        "no syslog server configured — set one with 'aifw syslog set --host <server>' or pass --host"
    );
    match aifw_common::syslog::test_send(&cfg, "AiFw remote syslog test message (CLI)").await {
        Ok(()) => {
            println!(
                "Test message sent to {}:{} over {} ({}).",
                cfg.host,
                cfg.port,
                cfg.transport.as_str(),
                cfg.format.as_str()
            );
            if cfg.transport == aifw_common::syslog::Transport::Udp {
                println!("  UDP is fire-and-forget — check the server received it.");
            }
        }
        Err(e) => anyhow::bail!("test send failed: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod syslog_cli_tests {
    use super::*;

    #[tokio::test]
    async fn set_and_show_round_trip() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-syslog-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");

        syslog_set(
            &db_path,
            SyslogSetOpts {
                host: Some("192.0.2.20".into()),
                port: Some(1514),
                transport: Some("tcp".into()),
                format: Some("rfc5424".into()),
                facility: Some("local3".into()),
                hostname: None,
                pf: Some(true),
                ids: None,
                app: None,
                app_min_level: None,
                disable_local: None,
            },
        )
        .await
        .unwrap();

        let (_db, cfg) = syslog_load(&db_path).await.unwrap();
        assert_eq!(cfg.host, "192.0.2.20");
        assert_eq!(cfg.port, 1514);
        assert_eq!(cfg.transport, aifw_common::syslog::Transport::Tcp);
        assert_eq!(cfg.format, aifw_common::syslog::SyslogFormat::Rfc5424);
        assert_eq!(cfg.facility, 19);
        assert!(cfg.pf_enabled);
        assert!(!cfg.enabled);

        syslog_enable(&db_path, true).await.unwrap();
        let (_db, cfg) = syslog_load(&db_path).await.unwrap();
        assert!(cfg.enabled);

        // Invalid facility is rejected before anything is saved.
        let bad = syslog_set(
            &db_path,
            SyslogSetOpts {
                host: None,
                port: None,
                transport: None,
                format: None,
                facility: Some("nope".into()),
                hostname: None,
                pf: None,
                ids: None,
                app: None,
                app_min_level: None,
                disable_local: None,
            },
        )
        .await;
        assert!(bad.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod human_bytes_tests {
    use super::human_bytes;

    #[test]
    fn scales_with_binary_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1 KB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024 / 2), "1.5 GB");
    }
}
