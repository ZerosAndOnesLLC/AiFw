//! `aifw config …` — export/import/history/rollback/diff.

use aifw_core::Database;
use std::path::Path;

// --- Config commands ---

async fn create_config_manager(db_path: &Path) -> anyhow::Result<aifw_core::ConfigManager> {
    let db = Database::new(db_path).await?;
    let mgr = aifw_core::ConfigManager::new(db.pool().clone());
    mgr.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(mgr)
}

/// Run `service <name> <action>` and fail with its stderr on a non-zero
/// exit (#325) instead of printing a success line regardless.
pub fn service_ctl(name: &str, action: &str) -> anyhow::Result<()> {
    let out = std::process::Command::new("service")
        .args([name, action])
        .output()
        .map_err(|e| anyhow::anyhow!("service {name} {action}: failed to run: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "service {name} {action} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub async fn config_show(db_path: &Path) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    match mgr.get_active().await.map_err(|e| anyhow::anyhow!(e))? {
        Some((version, config)) => {
            println!("Active config version: {version}");
            println!("Resources: {}", config.resource_count());
            println!("Hash: {}", config.hash());
            println!();
            // #313: display surface — never print live keys.
            let mut shown = config.clone();
            aifw_core::config_secrets::redact(&mut shown);
            println!("{}", shown.to_json());
        }
        None => {
            println!("No active configuration. Run 'aifw-setup' or 'aifw config import'.");
        }
    }
    Ok(())
}

/// Backup passphrase from `--passphrase-file` (first line) or the
/// `AIFW_BACKUP_PASSPHRASE` environment variable (#313).
fn backup_passphrase(passphrase_file: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(path) = passphrase_file {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading passphrase file {path}: {e}"))?;
        let line = content.lines().next().unwrap_or("").trim_end_matches('\r');
        if line.is_empty() {
            anyhow::bail!("passphrase file {path} is empty");
        }
        return Ok(Some(line.to_string()));
    }
    Ok(std::env::var("AIFW_BACKUP_PASSPHRASE")
        .ok()
        .filter(|p| !p.is_empty()))
}

pub async fn config_export(
    db_path: &Path,
    secrets: &str,
    passphrase_file: Option<&str>,
) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let Some((_, mut config)) = mgr.get_active().await.map_err(|e| anyhow::anyhow!(e))? else {
        anyhow::bail!("no active configuration");
    };
    match secrets {
        "plain" => {
            eprintln!(
                "warning: export contains live keys and passwords in the clear — protect the output"
            );
        }
        "passphrase" => {
            let Some(pw) = backup_passphrase(passphrase_file)? else {
                anyhow::bail!(
                    "--secrets passphrase needs --passphrase-file or $AIFW_BACKUP_PASSPHRASE"
                );
            };
            aifw_core::config_secrets::seal_with_passphrase(&mut config, &pw)
                .map_err(|e| anyhow::anyhow!(e))?;
        }
        _ => aifw_core::config_secrets::redact(&mut config),
    }
    print!("{}", config.to_json());
    Ok(())
}

pub async fn config_import(
    db_path: &Path,
    file: &str,
    passphrase_file: Option<&str>,
) -> anyhow::Result<()> {
    use aifw_core::config_secrets as cs;
    let mgr = create_config_manager(db_path).await?;
    let content = std::fs::read_to_string(file)?;
    let mut config =
        aifw_core::FirewallConfig::from_json(&content).map_err(|e| anyhow::anyhow!(e))?;

    // #313: unlock wrapped secrets, then fill redacted ones from the active
    // config so the stored version is full-fidelity.
    if matches!(cs::state(&config), cs::SecretsState::Passphrase { .. }) {
        let Some(pw) = backup_passphrase(passphrase_file)? else {
            anyhow::bail!(
                "this backup's secrets are passphrase-protected — pass --passphrase-file or set $AIFW_BACKUP_PASSPHRASE"
            );
        };
        cs::open_with_passphrase(&mut config, &pw)
            .map_err(|e| anyhow::anyhow!("could not unlock backup secrets: {e}"))?;
    }
    if !cs::redacted_refs(&config).is_empty() {
        let current = mgr
            .get_active()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .map(|(_, c)| c)
            .unwrap_or_default();
        let unresolved = cs::resolve_redacted(&mut config, &current);
        if !unresolved.is_empty() {
            let names: Vec<String> = unresolved.iter().map(|r| r.to_string()).collect();
            anyhow::bail!(
                "backup was exported without secrets and this box does not hold them: {}",
                names.join(", ")
            );
        }
    }

    println!("Importing config: {} resources", config.resource_count());

    // Save and mark as applied (no pf apply on CLI import — use 'aifw reload' after)
    let version = mgr
        .save_version(
            &config,
            "cli-import",
            Some(&format!("imported from {file}")),
        )
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    mgr.mark_applied(version)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("Imported as config version {version}");
    println!("Run 'aifw reload' to apply to pf");
    Ok(())
}

pub async fn config_history(db_path: &Path, limit: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let versions = mgr.history(limit).await.map_err(|e| anyhow::anyhow!(e))?;

    if versions.is_empty() {
        println!("No config versions found.");
        return Ok(());
    }

    println!(
        "{:<8} {:<10} {:<12} {:<22} {:<10} COMMENT",
        "VERSION", "STATUS", "RESOURCES", "CREATED", "BY"
    );
    println!("{}", "-".repeat(90));

    for v in &versions {
        let status = if v.applied {
            "ACTIVE"
        } else if v.rolled_back {
            "ROLLED_BACK"
        } else {
            "saved"
        };
        let ts = &v.created_at[..19]; // trim timezone
        println!(
            "{:<8} {:<10} {:<12} {:<22} {:<10} {}",
            v.version,
            status,
            v.resource_count,
            ts,
            v.created_by,
            v.comment.as_deref().unwrap_or(""),
        );
    }

    let total = mgr.version_count().await.map_err(|e| anyhow::anyhow!(e))?;
    println!("\n{total} total version(s)");
    Ok(())
}

pub async fn config_rollback(db_path: &Path, version: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;

    println!("Rolling back to config version {version}...");
    mgr.rollback(version, |_config| async { Ok(()) })
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    println!("Rolled back to version {version}");
    println!("Run 'aifw reload' to apply to pf");
    Ok(())
}

pub async fn config_diff(db_path: &Path, v1: i64, v2: i64) -> anyhow::Result<()> {
    let mgr = create_config_manager(db_path).await?;
    let diff = mgr.diff(v1, v2).await.map_err(|e| anyhow::anyhow!(e))?;

    println!("Config diff: v{} vs v{}", diff.v1, diff.v2);
    println!();
    if diff.identical {
        println!("  Configs are identical (same hash)");
    } else {
        println!("  Hash v{}: {}", diff.v1, &diff.v1_hash[..16]);
        println!("  Hash v{}: {}", diff.v2, &diff.v2_hash[..16]);
        println!();
        println!(
            "  Rules:     {} -> {} (+{} -{})",
            diff.rules_diff.v1_count,
            diff.rules_diff.v2_count,
            diff.rules_diff.added,
            diff.rules_diff.removed
        );
        println!(
            "  NAT:       {} -> {} (+{} -{})",
            diff.nat_diff.v1_count,
            diff.nat_diff.v2_count,
            diff.nat_diff.added,
            diff.nat_diff.removed
        );
        println!("  Total:     {} -> {}", diff.total_v1, diff.total_v2);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::backup_passphrase;

    #[test]
    fn passphrase_file_first_line_wins_and_empty_is_error() {
        let dir = std::env::temp_dir().join(format!("aifw-cli-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pw");
        std::fs::write(&f, "hunter2\r\nsecond line\n").unwrap();
        assert_eq!(
            backup_passphrase(Some(f.to_str().unwrap()))
                .unwrap()
                .as_deref(),
            Some("hunter2")
        );
        std::fs::write(&f, "\n").unwrap();
        assert!(
            backup_passphrase(Some(f.to_str().unwrap())).is_err(),
            "empty file is an error"
        );
        assert!(backup_passphrase(Some(dir.join("missing").to_str().unwrap())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
