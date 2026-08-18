//! Tarball install: verify, stage, back up, swap binaries/UI, post-install steps.

use tokio::process::Command;
use tracing::{debug, info, warn};

use super::*;

/// Install an AiFw update from a local tarball path.
///
/// This is the shared install primitive used by both `download_and_install`
/// (which downloads first, then delegates here) and the API's
/// `install-local` endpoint (which receives an uploaded tarball and
/// delegates here directly).
///
/// `expected_hash` — if `Some`, the tarball's sha256 is verified before
/// extraction.  Pass `None` only when the caller has already verified the
/// hash or when `--skip-checksum` was explicitly requested.
pub async fn install_from_path(
    tarball_path: &std::path::Path,
    expected_hash: Option<&str>,
) -> Result<String, UpdaterError> {
    let tarball_str = tarball_path
        .to_str()
        .ok_or_else(|| UpdaterError::Install("tarball path is not valid UTF-8".to_string()))?;

    // Optionally verify checksum
    if let Some(hash) = expected_hash {
        info!("Verifying checksum...");
        if !verify_sha256(tarball_str, hash).await? {
            return Err(UpdaterError::Checksum);
        }
    }

    // Backup current installation
    info!("Backing up current installation...");
    backup_current().await?;

    // Extract the tarball into a dedicated, always-clean staging dir.
    //
    // The tarball is extracted as root (via the sudo-tar helper), so anything
    // left over from a prior update is root-owned and the aifw user can't
    // remove it with std fs. Previously these accumulated in
    // <tarball_parent>/extracted and the installer selected one with
    // read_dir().next_entry() — an ARBITRARY directory-order pick — so a stale
    // older version (e.g. 5.96.8) got installed instead of the one just
    // downloaded, making every in-app upgrade a silent no-op.
    //
    // Fix: stage in a fixed path inside the /tmp/aifw-* allowlist (so the sudo
    // rm/tar helpers accept it), scrub it before AND after extraction (via the
    // sudo helper, since the content is root-owned), and select the update dir
    // DETERMINISTICALLY from the tarball's own top-level entry rather than
    // trusting directory order.
    const EXTRACT_DIR: &str = "/tmp/aifw-update-extract";
    // Scrub current + legacy staging. Root-owned, so the sudo helper is
    // required; best-effort because a clean run has nothing to remove.
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", EXTRACT_DIR]).await) {
        debug!(path = EXTRACT_DIR, error = %err, "update: staging dir scrub failed");
    }
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", "/tmp/aifw-update/extracted"]).await)
    {
        debug!(
            path = "/tmp/aifw-update/extracted",
            error = %err,
            "update: legacy staging dir scrub failed"
        );
    }
    let extract_dir = std::path::PathBuf::from(EXTRACT_DIR);
    tokio::fs::create_dir_all(&extract_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create extract dir: {}", e)))?;

    // Read the tarball's top-level directory name straight from the archive,
    // so we install exactly what we extracted regardless of any siblings.
    let listing = Command::new("tar")
        .args(["tf", tarball_str])
        .output()
        .await
        .map_err(|e| UpdaterError::Install(format!("tar list failed: {}", e)))?;
    if !listing.status.success() {
        return Err(UpdaterError::Install(format!(
            "tar list failed: {}",
            String::from_utf8_lossy(&listing.stderr)
        )));
    }
    let listing_text = String::from_utf8_lossy(&listing.stdout);

    // SEC-H11: path-traversal guard. Extraction runs as root via the sudo
    // helper, so an entry with an absolute path or a `..` component could
    // write outside EXTRACT_DIR. bsdtar strips these by default, but we do
    // not rely on that — reject the whole tarball up front.
    validate_tar_listing(&listing_text).map_err(UpdaterError::Install)?;

    let top_name = listing_text
        .lines()
        .find_map(|l| {
            l.trim_start_matches("./")
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| UpdaterError::Install("Empty tarball".to_string()))?;

    // Use the aifw-sudo-tar helper which rejects --use-compress-program /
    // --checkpoint-action / -I (SEC-C2 PE primitives). The helper also
    // restricts tarball + dest to staging dirs we already own.
    let output = crate::sudo::tar(&["xf", tarball_str, "-C", EXTRACT_DIR])
        .await
        .map_err(|e| UpdaterError::Install(format!("tar failed: {}", e)))?;

    if !output.status.success() {
        return Err(UpdaterError::Install(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let update_dir = extract_dir.join(&top_name);
    if !update_dir.is_dir() {
        return Err(UpdaterError::Install(format!(
            "extracted dir '{}' not found (corrupt tarball?)",
            top_name
        )));
    }

    // OS dependency gate (#612): a tarball built on a newer FreeBSD ships
    // binaries the running libc can't load (e.g. FBSD_1.9 on a 15.0 box) —
    // installing them takes the whole management plane down in a
    // crash-loop. Refuse before any file is swapped. Tarballs without the
    // stamp predate this scheme and install as before.
    if let Ok(required) = tokio::fs::read_to_string(update_dir.join("required-os")).await {
        let required = required.trim().to_string();
        if !required.is_empty()
            && let Some(current) = current_os_release().await
            && !os_satisfies(&current, &required)
        {
            return Err(UpdaterError::OsUpgradeRequired { required, current });
        }
    }

    // Install binaries from the tarball's bin/ directory.
    //
    // SEC-H11: only install names on the compiled-in allowlist derived from
    // the embedded manifest (`all_binaries()`). The local-upload install path
    // has an optional (bypassable) checksum, so a malicious tarball can carry
    // arbitrary `bin/<name>` files; without this gate an `UpdatesInstall`
    // actor could plant a new root-owned `aifw-*` binary under a trusted name.
    // Trade-off: a genuinely new binary in a future release is skipped by the
    // *currently running* updater (logged loudly) until the core binaries
    // update carries a manifest that lists it.
    info!("Installing binaries...");
    let allowed: std::collections::HashSet<String> = all_binaries().into_iter().collect();
    let bin_src = update_dir.join("bin");
    let mut installed = 0u32;
    if bin_src.exists() {
        let mut entries = tokio::fs::read_dir(&bin_src)
            .await
            .map_err(|e| UpdaterError::Install(format!("read bin dir: {}", e)))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| UpdaterError::Install(e.to_string()))?
        {
            if !entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            let src = entry.path();
            let name = match src.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !allowed.contains(&name) {
                warn!(
                    binary = %name,
                    "refusing to install binary not on the manifest allowlist (SEC-H11)"
                );
                continue;
            }
            let dst = format!("{}/{}", BIN_DIR, name);
            let src_str = src
                .to_str()
                .expect("src path is utf-8 (file_name validated above)");
            let output = crate::sudo::install(Some("755"), None, None, src_str, &dst)
                .await
                .map_err(|e| UpdaterError::Install(format!("Failed to install {}: {}", name, e)))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(UpdaterError::Install(format!(
                    "Failed to install {}: {}",
                    name, stderr
                )));
            }
            installed += 1;
        }
    }
    if installed == 0 {
        return Err(UpdaterError::Install(
            "No binaries found in update tarball".to_string(),
        ));
    }
    info!(count = installed, "binaries installed");

    // Install UI — both rm and cp go through the narrow helpers (SEC-C2).
    // The helpers restrict UI_DIR and a /tmp staging dir as the only legal
    // operands; a compromised aifw user can't sudo-cp /tmp/x to /root/.ssh.
    let ui_src = update_dir.join("ui");
    if ui_src.exists() {
        info!("Installing UI...");
        if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", UI_DIR]).await) {
            warn!(
                path = UI_DIR,
                error = %err,
                "update: failed to remove old UI dir — stale UI files may remain"
            );
        }
        let ui_src_str = ui_src
            .to_str()
            .ok_or_else(|| UpdaterError::Install("ui_src path is not UTF-8".into()))?;
        let output = crate::sudo::cp(&["-a", ui_src_str, UI_DIR])
            .await
            .map_err(|e| UpdaterError::Install(format!("Failed to install UI: {}", e)))?;
        if !output.status.success() {
            return Err(UpdaterError::Install(format!(
                "Failed to install UI: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // SEC-C1: runtime sudoers migration has been removed.
    //
    // The previous design ran nine `ensure_sudoers_*` functions here, each
    // re-writing /usr/local/etc/sudoers.d/aifw via the `aifw-sudo-install`
    // helper to add new narrow-helper grants on upgrade. That made the
    // helper script able to install ANY content into the sudoers file
    // (audited as a critical PE primitive). The helper's destination
    // allowlist no longer accepts that path; sudoers is now an install-time
    // artifact shipped by the update tarball / ISO / deploy.sh, written by
    // a privileged installer step.

    // Ensure required packages are installed — older installs may predate a
    // dependency (curl pre-5.x, strongswan pre-#530). Driven by the
    // manifest `packages` list so new deps flow to upgraded boxes.
    for pkg in &load_manifest().packages {
        let pkg = pkg.as_str();
        let check = Command::new("pkg").args(["info", "-q", pkg]).output().await;
        let pkg_installed = check.map(|o| o.status.success()).unwrap_or(false);
        if !pkg_installed {
            info!(package = pkg, "Installing missing dependency");
            if let Some(err) = step_failure(&crate::sudo::pkg("install", &["-y", pkg]).await) {
                warn!(package = pkg, error = %err, "update: dependency install failed");
            }
        }
    }

    // Keep the operator-facing copy of the release-signing public key in
    // sync with the running build (it changes only on key rotation).
    // Verification itself uses the compiled-in key, so this is best-effort.
    let on_disk_pubkey = tokio::fs::read_to_string(PUBKEY_PATH).await.ok();
    if on_disk_pubkey.as_deref() != Some(EMBEDDED_PUBKEY) {
        let staged = "/tmp/aifw-update-signing.pub";
        let stage_ok = tokio::fs::write(staged, EMBEDDED_PUBKEY).await.is_ok();
        if stage_ok {
            if let Some(err) = step_failure(
                &crate::sudo::install(
                    Some("0644"),
                    Some("root"),
                    Some("wheel"),
                    staged,
                    PUBKEY_PATH,
                )
                .await,
            ) {
                warn!(error = %err, "update: could not provision update-signing.pub");
            }
            if let Err(e) = tokio::fs::remove_file(staged).await {
                debug!(error = %e, "update: staged pubkey cleanup failed");
            }
        }
    }

    let manifest = load_manifest();

    // Install rc.d scripts. Same reasoning as binaries above: iterate the
    // tarball directory rather than the compiled-in manifest.rc_scripts list,
    // so a release that ships a new rc.d (e.g. aifw_ids in 5.76) gets
    // installed even when the running updater predates it.
    let rcd_src = update_dir.join("rc.d");
    if rcd_src.exists() {
        info!("Installing rc.d scripts...");
        if let Ok(mut entries) = tokio::fs::read_dir(&rcd_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/etc/rc.d/{}", name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: rc.d script install failed");
                }
            }
        }
    }

    // Install libexec scripts (restart driver, watchdog loop, motd
    // cleanup, login migrate). Same iterate-the-tarball pattern: a
    // release that adds a new libexec script (e.g. aifw-restart.sh in
    // 5.79.0) lands even when the running updater predates it.
    let libexec_src = update_dir.join("libexec");
    if libexec_src.exists() {
        info!("Installing libexec scripts...");
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", "/usr/local/libexec"]).await) {
            warn!(error = %err, "update: mkdir /usr/local/libexec failed");
        }
        if let Ok(mut entries) = tokio::fs::read_dir(&libexec_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/libexec/{}", name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: libexec script install failed");
                }
            }
        }
    }

    // Install sbin scripts (console, installer). Iterate tarball/sbin/ for
    // the same reason as above.
    let sbin_src = update_dir.join("sbin");
    if sbin_src.exists() {
        info!("Installing utility scripts...");
        if let Ok(mut entries) = tokio::fs::read_dir(&sbin_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("{}/{}", BIN_DIR, name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: utility script install failed");
                }
            }
        }
    }

    // Ensure required directories exist (new services may need them)
    for dir in &manifest.directories {
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", dir]).await) {
            warn!(path = %dir, error = %err, "update: required directory create failed");
        }
    }

    // Read the installed version from the tarball's version file
    let installed_version = {
        let ver_src = update_dir.join("version");
        if ver_src.exists() {
            let ver_src_str = ver_src
                .to_str()
                .ok_or_else(|| UpdaterError::Install("ver_src path is not UTF-8".into()))?;
            let output = crate::sudo::cp(&[ver_src_str, VERSION_FILE])
                .await
                .map_err(|e| {
                    UpdaterError::Install(format!("Failed to update version file: {}", e))
                })?;
            if !output.status.success() {
                warn!(
                    "Failed to update version file: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            tokio::fs::read_to_string(&ver_src)
                .await
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            String::new()
        }
    };

    // Install the component-revision record (#538) next to the version file
    // so an appliance can report exactly which AiFw + companion commits it
    // runs. Best-effort: pre-#538 tarballs don't contain it.
    {
        let comp_src = update_dir.join("components.json");
        if comp_src.exists() {
            match comp_src.to_str() {
                Some(comp_src_str) => {
                    if let Some(err) = step_failure(
                        &crate::sudo::cp(&[comp_src_str, "/usr/local/share/aifw/components.json"])
                            .await,
                    ) {
                        warn!(error = %err, "update: components.json install failed");
                    }
                }
                None => warn!("update: components.json path is not UTF-8; skipping"),
            }
        }
    }

    // Strip stale AiFw version from MOTD template. Idempotent and respects
    // the marker file that `system_apply::apply_banner` sets when the admin
    // edits MOTD via the UI.
    #[cfg(target_os = "freebsd")]
    {
        let result = Command::new("/usr/local/libexec/aifw-motd-cleanup.sh")
            .output()
            .await;
        if let Some(err) = step_failure(&result) {
            debug!(error = %err, "update: motd cleanup script failed");
        }
    }

    // One-shot migration: enforce password-protected console login on
    // existing installs that were shipped with autologin. Idempotent.
    #[cfg(target_os = "freebsd")]
    {
        let result = Command::new("/usr/local/libexec/aifw-login-migrate.sh")
            .output()
            .await;
        if let Some(err) = step_failure(&result) {
            warn!(error = %err, "update: console login migration script failed — autologin may remain enabled");
        }
    }

    // Cleanup extract dir. Contents are root-owned (sudo-tar), so std fs
    // remove_dir_all would fail silently and leak staging across updates —
    // exactly what let stale dirs pile up before. Use the sudo helper.
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", EXTRACT_DIR]).await) {
        debug!(path = EXTRACT_DIR, error = %err, "update: staging dir cleanup failed");
    }

    let version_display = if installed_version.is_empty() {
        "unknown".to_string()
    } else {
        installed_version.clone()
    };
    info!(version = %version_display, "AiFw install_from_path completed");
    Ok(version_display)
}

/// Download, verify, and install an AiFw update.
pub async fn download_and_install(info: &AifwUpdateInfo) -> Result<String, UpdaterError> {
    let tarball_url = info.tarball_url.as_deref().ok_or(UpdaterError::NoTarball)?;
    let checksum_url = info
        .checksum_url
        .as_deref()
        .ok_or(UpdaterError::NoTarball)?;
    let signature_url = info
        .checksum_signature_url
        .as_deref()
        .ok_or(UpdaterError::NoSignature)?;

    let tmp_dir = "/tmp/aifw-update";
    let tarball_path = std::path::PathBuf::from(format!("{}/update.tar.xz", tmp_dir));
    let checksum_path = format!("{}/update.tar.xz.sha256", tmp_dir);
    let signature_path = format!("{}/update.tar.xz.sha256.minisig", tmp_dir);

    // Clean and create temp dir. NotFound is the normal clean-run case.
    if let Err(e) = tokio::fs::remove_dir_all(tmp_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        debug!(path = tmp_dir, error = %e, "update: temp dir scrub failed");
    }
    tokio::fs::create_dir_all(tmp_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create temp dir: {}", e)))?;

    // Download tarball and checksum
    info!("Downloading AiFw update v{}...", info.latest_version);
    let tarball_path_str = tarball_path
        .to_str()
        .ok_or_else(|| UpdaterError::Install("tarball_path is not UTF-8".into()))?;
    http_download(tarball_url, tarball_path_str).await?;
    http_download(checksum_url, &checksum_path).await?;
    http_download(signature_url, &signature_path).await?;

    // Publisher authenticity is checked before trusting the checksum. The
    // public key is compiled into the running binary, so replacing a release
    // asset and its checksum is insufficient to authorize an install.
    verify_minisign_checksum(&checksum_path, &signature_path).await?;

    // Read and parse the expected hash from the downloaded checksum file
    let expected = tokio::fs::read_to_string(&checksum_path)
        .await
        .map_err(|e| UpdaterError::Download(format!("Failed to read checksum: {}", e)))?;
    let expected_hash = extract_hash(&expected);

    // Delegate to the shared install primitive (verifies hash, extracts, installs)
    let version = install_from_path(&tarball_path, Some(&expected_hash)).await?;

    // Cleanup temp dir
    if let Err(e) = tokio::fs::remove_dir_all(tmp_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        debug!(path = tmp_dir, error = %e, "update: temp dir cleanup failed");
    }

    let new_ver = if version.is_empty() {
        info.latest_version.clone()
    } else {
        version
    };
    info!(version = %new_ver, "AiFw updated");
    Ok(format!(
        "AiFw updated from v{} to v{}",
        info.current_version, new_ver
    ))
}
