//! Rollback to the previous release backup.

use tracing::{info, warn};

use super::*;

/// Rollback to the previous version from backup.
pub async fn rollback() -> Result<String, UpdaterError> {
    let backup_ver = format!("{}/version", BACKUP_DIR);
    if !std::path::Path::new(&backup_ver).exists() {
        return Err(UpdaterError::NoBackup);
    }

    let version = tokio::fs::read_to_string(&backup_ver)
        .await
        .map_err(|_| UpdaterError::NoBackup)?
        .trim()
        .to_string();

    info!("Rolling back to v{}...", version);

    // Restore binaries
    for bin in &all_binaries() {
        let src = format!("{}/bin/{}", BACKUP_DIR, bin);
        if std::path::Path::new(&src).exists() {
            let dst = format!("{}/{}", BIN_DIR, bin);
            if let Some(err) =
                step_failure(&crate::sudo::install(Some("755"), None, None, &src, &dst).await)
            {
                warn!(binary = %bin, error = %err, "rollback: binary restore failed");
            }
        }
    }

    // Restore rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("{}/rc.d/{}", BACKUP_DIR, script);
        if std::path::Path::new(&src).exists() {
            let dst = format!("/usr/local/etc/rc.d/{}", script);
            if let Some(err) =
                step_failure(&crate::sudo::install(Some("755"), None, None, &src, &dst).await)
            {
                warn!(script = %script, error = %err, "rollback: rc.d script restore failed");
            }
        }
    }

    // Restore UI
    let backup_ui = format!("{}/ui", BACKUP_DIR);
    if std::path::Path::new(&backup_ui).exists() {
        if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", UI_DIR]).await) {
            warn!(path = UI_DIR, error = %err, "rollback: failed to remove current UI dir");
        }
        if let Some(err) = step_failure(&crate::sudo::cp(&["-a", &backup_ui, UI_DIR]).await) {
            warn!(path = UI_DIR, error = %err, "rollback: UI restore failed");
        }
    }

    // Restore version file
    if let Some(err) = step_failure(&crate::sudo::cp(&[&backup_ver, VERSION_FILE]).await) {
        warn!(path = VERSION_FILE, error = %err, "rollback: version file restore failed");
    }

    info!("Rolled back to v{}", version);
    Ok(format!("Rolled back to v{}", version))
}

// --- Private helpers ---

pub(super) async fn backup_current() -> Result<(), UpdaterError> {
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", BACKUP_DIR]).await) {
        warn!(path = BACKUP_DIR, error = %err, "backup: failed to clear old backup dir");
    }
    // The mkdir helper takes exactly one target, so create each dir
    // separately (rather than one mkdir with two operands).
    for sub in ["bin", "rc.d"] {
        let dir = format!("{}/{}", BACKUP_DIR, sub);
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", &dir]).await) {
            warn!(path = %dir, error = %err, "backup: failed to create backup dir");
        }
    }

    for bin in &all_binaries() {
        let src = format!("{}/{}", BIN_DIR, bin);
        if std::path::Path::new(&src).exists()
            && let Some(err) = step_failure(
                &crate::sudo::cp(&["-p", &src, &format!("{}/bin/{}", BACKUP_DIR, bin)]).await,
            )
        {
            warn!(binary = %bin, error = %err, "backup: binary copy failed — rollback may be incomplete");
        }
    }

    // Backup rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("/usr/local/etc/rc.d/{}", script);
        if std::path::Path::new(&src).exists()
            && let Some(err) = step_failure(
                &crate::sudo::cp(&["-p", &src, &format!("{}/rc.d/{}", BACKUP_DIR, script)]).await,
            )
        {
            warn!(script = %script, error = %err, "backup: rc.d script copy failed");
        }
    }

    if std::path::Path::new(UI_DIR).exists()
        && let Some(err) =
            step_failure(&crate::sudo::cp(&["-a", UI_DIR, &format!("{}/ui", BACKUP_DIR)]).await)
    {
        warn!(path = UI_DIR, error = %err, "backup: UI copy failed — rollback may be incomplete");
    }

    if std::path::Path::new(VERSION_FILE).exists()
        && let Some(err) = step_failure(
            &crate::sudo::cp(&[VERSION_FILE, &format!("{}/version", BACKUP_DIR)]).await,
        )
    {
        warn!(path = VERSION_FILE, error = %err, "backup: version file copy failed — rollback will report no backup");
    }

    Ok(())
}

pub(super) async fn get_backup_info() -> (bool, Option<String>) {
    let ver_path = format!("{}/version", BACKUP_DIR);
    match tokio::fs::read_to_string(&ver_path).await {
        Ok(v) => (true, Some(v.trim().to_string())),
        Err(_) => (false, None),
    }
}
