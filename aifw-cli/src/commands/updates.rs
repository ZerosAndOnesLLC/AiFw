//! `aifw update …` — self-update, local install, OS upgrade.

use aifw_core::Database;
use std::path::Path;

use super::cluster::{AIFW_API_BASE, read_api_token};

// ============================================================
// Update commands
// ============================================================

pub async fn update_check(pre: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    println!(
        "Checking for AiFw updates{}...",
        if pre { " (including pre-releases)" } else { "" }
    );
    let info = updater::check_for_update(pre).await?;

    println!("  Current version: v{}", info.current_version);
    println!("  Latest version:  v{}", info.latest_version);
    if info.update_available {
        println!("  Update available!");
        if info.os_upgrade_required {
            println!(
                "  ⚠ Requires FreeBSD {} — upgrade the OS first:",
                info.required_os.as_deref().unwrap_or("newer")
            );
            println!(
                "    aifw update os-upgrade {}",
                info.required_os.as_deref().unwrap_or("<version>")
            );
        } else if info.tarball_url.is_some() {
            println!("  Run 'aifw update install' to update.");
        } else {
            println!("  No update tarball found in the release.");
        }
    } else {
        println!("  Already running the latest version.");
    }
    if let Some(blocked) = &info.blocked_version {
        println!(
            "  v{blocked} is also available and requires FreeBSD {} —",
            info.blocked_requires_os.as_deref().unwrap_or("newer")
        );
        println!(
            "  it unlocks after: aifw update os-upgrade {}",
            info.blocked_requires_os.as_deref().unwrap_or("<version>")
        );
    }
    if info.has_backup {
        println!(
            "  Backup: v{} (run 'aifw update rollback' to restore)",
            info.backup_version.as_deref().unwrap_or("unknown")
        );
    }
    Ok(())
}

pub async fn update_install(db_path: &Path, auto_restart: bool, pre: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    // #646: stand down while a FreeBSD release upgrade is in flight — the
    // install's service restart would interrupt the post-reboot finalize.
    // A missing/unreadable DB reads as "no upgrade recorded" (dev hosts) —
    // and is never created as a side effect of an update.
    if db_path.exists()
        && let Ok(db) = Database::new(db_path).await
        && let Some(job) = aifw_core::os_upgrade_state::load(db.pool()).await
        && job.is_in_flight()
    {
        anyhow::bail!("{}", aifw_core::os_upgrade_state::blocked_message(&job));
    }

    println!(
        "Checking for AiFw updates{}...",
        if pre { " (including pre-releases)" } else { "" }
    );
    let info = updater::check_for_update(pre).await?;

    if !info.update_available {
        println!(
            "Already running the latest version (v{}).",
            info.current_version
        );
        return Ok(());
    }

    // OS dependency gate (#612): don't download a release this OS can't
    // run. The tarball-level gate in the updater backstops this.
    if info.os_upgrade_required {
        let required = info.required_os.as_deref().unwrap_or("newer");
        anyhow::bail!(
            "AiFw v{} requires FreeBSD {required} but this system runs {}.\n\
             Upgrade the OS first: aifw update os-upgrade {required}",
            info.latest_version,
            updater::current_os_release()
                .await
                .unwrap_or_else(|| "unknown".to_string()),
        );
    }

    println!(
        "Updating AiFw from v{} to v{}...",
        info.current_version, info.latest_version
    );
    let msg = updater::download_and_install(&info).await?;
    println!("{}", msg);

    if info.reboot_recommended {
        println!();
        println!(
            "  ⚠ Reboot recommended for this release: {}",
            info.reboot_reason
                .as_deref()
                .unwrap_or("changes service-supervision tooling")
        );
        println!("  Use 'aifw update reboot' instead of 'aifw update restart'.");
        println!();
    }

    if auto_restart || prompt_restart_yes()? {
        println!("Restarting services...");
        updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!(
            "Update installed. Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it."
        );
    }
    Ok(())
}

pub async fn update_rollback(auto_restart: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    let msg = updater::rollback().await?;
    println!("{}", msg);

    if auto_restart || prompt_restart_yes()? {
        println!("Restarting services...");
        updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!("Rollback installed. Run 'aifw update restart' when ready to activate it.");
    }
    Ok(())
}

pub async fn update_restart() -> anyhow::Result<()> {
    use aifw_core::updater;
    println!("Restarting AiFw services...");
    updater::restart_services_sync().await;
    println!("Done.");
    Ok(())
}

pub async fn update_reboot() -> anyhow::Result<()> {
    use aifw_core::updater;
    updater::schedule_reboot().await?;
    println!("System reboot scheduled in 1 minute.");
    println!("Cancel with `shutdown -c` if needed.");
    Ok(())
}

/// Install AiFw from a local tarball by uploading it to the API's
/// install-local endpoint.  The API streams the file to disk, optionally
/// verifies the sha256 sidecar, and runs the same extract+install path
/// as remote installs.
pub async fn update_install_local(
    path: std::path::PathBuf,
    skip_checksum: bool,
    auto_restart: bool,
) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("tarball not found: {}", path.display());
    }
    if !path.extension().map(|e| e == "xz").unwrap_or(false) {
        anyhow::bail!("expected a .tar.xz file, got: {}", path.display());
    }

    let meta = tokio::fs::metadata(&path).await?;
    let size_mb = meta.len() / (1024 * 1024);

    if !auto_restart {
        use std::io::{BufRead, Write};
        println!(
            "Install from local tarball: {} ({} MB)",
            path.display(),
            size_mb
        );
        print!("Proceed? [y/N] ");
        // best-effort prompt flush; a broken stdout pipe is unactionable here
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let answer = line.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!(
        "Uploading {} ({} MB) to API...",
        path.file_name().unwrap_or_default().to_string_lossy(),
        size_mb
    );

    // Build a multipart form.  Load the tarball into memory (50-100 MB is
    // fine for local use) to avoid pulling in a streaming-body dependency
    // beyond what reqwest multipart already provides.
    let tarball_bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read tarball: {e}"))?;

    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut form = reqwest::multipart::Form::new().part(
        "tarball",
        reqwest::multipart::Part::bytes(tarball_bytes).file_name(filename),
    );

    if !skip_checksum {
        // Expect <file>.sha256 next to the tarball.
        let sha_path = {
            let mut p = path.clone();
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            p.set_file_name(format!("{}.sha256", name));
            p
        };
        if !sha_path.exists() {
            anyhow::bail!(
                "sha256 sidecar not found: {} — use --skip-checksum to bypass",
                sha_path.display()
            );
        }
        let sha_content = tokio::fs::read_to_string(&sha_path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read sha256 sidecar: {e}"))?;
        form = form.text("sha256", sha_content);
    }

    if auto_restart {
        form = form.text("restart", "true");
    }

    let client = reqwest::Client::builder()
        // Use a longer timeout for the upload — 50-100 MB over localhost
        // is fast, but give headroom for slow test VMs.
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    let token = read_api_token();
    let url = format!("{AIFW_API_BASE}/api/v1/updates/aifw/install-local");
    let mut req = client.post(&url).multipart(form);
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("install-local failed: {} {}", status, body);
    }

    let data: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let msg = data["message"].as_str().unwrap_or("install accepted");
    println!("{}", msg);
    println!("Check `aifw update history` for status.");

    if auto_restart {
        println!("Restarting services...");
        aifw_core::updater::restart_services_sync().await;
        println!("Done.");
    } else {
        println!("Run 'aifw update restart' (or 'aifw update reboot') when ready to activate it.");
    }

    Ok(())
}

/// Interactive confirmation. Returns true on y/yes (case-insensitive).
/// Defaults to no on bare Enter — restarts are user-visible outages, the
/// safe answer when the operator hasn't decided is "don't bounce yet".
fn prompt_restart_yes() -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    print!("Restart services now to activate? [y/N] ");
    // best-effort prompt flush; a broken stdout pipe is unactionable here
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

pub async fn update_os_check() -> anyhow::Result<()> {
    println!("Checking for OS and package updates...");

    let pkg = aifw_core::sudo::pkg("update", &[]).await?;
    if pkg.status.success() {
        println!("  Package catalog updated.");
    } else {
        println!(
            "  Package update failed: {}",
            String::from_utf8_lossy(&pkg.stderr).trim()
        );
    }

    let os = aifw_core::sudo::freebsd_update("fetch", &["--not-running-from-cron"]).await?;
    if os.status.success() {
        println!("  OS update check complete.");
    } else {
        println!(
            "  OS update check: {}",
            String::from_utf8_lossy(&os.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
    }

    // Show pending
    let pending = aifw_core::sudo::pkg("upgrade", &["-n"]).await?;
    let stdout = String::from_utf8_lossy(&pending.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.trim().starts_with("Upgrading") || l.trim().starts_with("Installing"))
        .count();
    if count > 0 {
        println!("  {} package(s) pending.", count);
    } else {
        println!("  Packages are up to date.");
    }

    Ok(())
}

pub async fn update_os_install() -> anyhow::Result<()> {
    println!("Installing OS and package updates...");

    let pkg = aifw_core::sudo::pkg("upgrade", &["-y"]).await?;
    let stdout = String::from_utf8_lossy(&pkg.stdout);
    let count = stdout
        .lines()
        .filter(|l| l.contains("Upgrading") || l.contains("Installing"))
        .count();
    println!("  {} package(s) updated.", count);

    let os = aifw_core::sudo::freebsd_update("install", &[]).await?;
    if os.status.success() {
        println!("  OS updates installed.");
    } else {
        println!("  No OS updates to install.");
    }

    if std::path::Path::new("/var/run/reboot-required").exists() {
        println!("  Reboot required to complete updates.");
    }

    Ok(())
}

/// FreeBSD release upgrade (#613): fetch + stage the target release,
/// install the new kernel, then hand back to the operator for the reboot.
/// The remaining install passes run automatically when aifw-api starts on
/// the new kernel (or manually via 'aifw update os-install').
pub async fn update_os_upgrade(target: &str, yes: bool) -> anyhow::Result<()> {
    use aifw_core::updater;

    let current = updater::current_os_release()
        .await
        .ok_or_else(|| anyhow::anyhow!("cannot determine the running FreeBSD release"))?;
    if updater::os_satisfies(&current, target) {
        println!("Already on FreeBSD {current}; {target} is not newer. Nothing to do.");
        return Ok(());
    }

    println!("FreeBSD release upgrade: {current} → {target}-RELEASE");
    println!("  1. Download and stage the release (can take a while)");
    println!("  2. Install the new kernel");
    println!("  3. Reboot — the remaining install finishes after boot");
    if !yes && !prompt_yes("Proceed with the OS upgrade?")? {
        println!("Aborted.");
        return Ok(());
    }

    println!("Downloading FreeBSD {target}-RELEASE (this is the long part)...");
    let fetch = aifw_core::sudo::freebsd_update_upgrade(target).await?;
    if !fetch.status.success() {
        anyhow::bail!(
            "release fetch failed: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        );
    }
    println!("Release staged. Installing the new kernel...");
    let install = aifw_core::sudo::freebsd_update("install", &[]).await?;
    if !install.status.success() {
        anyhow::bail!(
            "kernel install failed: {}",
            String::from_utf8_lossy(&install.stderr).trim()
        );
    }

    println!();
    println!("Kernel for {target}-RELEASE installed.");
    println!("Reboot now with 'aifw update reboot'. After boot, the remaining");
    println!("userland install runs automatically; check progress on the");
    println!("Updates page or with 'aifw update os-check'.");
    Ok(())
}

fn prompt_yes(question: &str) -> anyhow::Result<bool> {
    use std::io::{BufRead, Write};

    print!("{question} [y/N] ");
    // best-effort prompt flush; a broken stdout pipe is unactionable here
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}
