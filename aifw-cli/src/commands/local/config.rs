//! `aifw local config-export` — export straight from the database, the
//! only way to get secrets in the clear.

use aifw_core::Database;
use std::path::Path;

// --- Config commands ---

async fn create_config_manager(db_path: &Path) -> anyhow::Result<aifw_core::ConfigManager> {
    let db = Database::new(db_path).await?;
    let mgr = aifw_core::ConfigManager::new(db.pool().clone());
    mgr.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(mgr)
}

/// Backup passphrase from `--passphrase-file` (first line) or the
/// `AIFW_BACKUP_PASSPHRASE` environment variable (#313).
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
            let Some(pw) = crate::commands::config::backup_passphrase(passphrase_file)? else {
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
