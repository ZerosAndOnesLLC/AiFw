//! Version discovery: running/installed version, GitHub release check, OS release + canary checks.

use tokio::process::Command;

use super::*;

/// Read the current installed AiFw version.
pub async fn get_current_version() -> String {
    tokio::fs::read_to_string(VERSION_FILE)
        .await
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
        .trim()
        .to_string()
}

/// Version compiled into the running binary. Used together with
/// `get_current_version()` to detect a pending restart: when the on-disk
/// version (just written by an update tarball install) differs from this
/// one, the new binary is on disk but not yet executing.
pub fn running_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// True when the on-disk version differs from the running binary's
/// compiled-in version. Drives the "restart pending" UI banner.
pub async fn restart_pending() -> bool {
    let on_disk = match tokio::fs::read_to_string(VERSION_FILE).await {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };
    !on_disk.is_empty() && on_disk != running_version()
}

/// Check GitHub Releases for a newer AiFw version.
///
/// Consults the release LIST (#624) and offers for install the newest
/// release the running OS can execute, while separately surfacing the
/// absolute newest when it needs a newer OS (drives the guided OS-upgrade
/// card). Both can exist at once: a FreeBSD 15.0 box mid-transition sees
/// "vNew requires 15.1" AND installs the newest 15.0-compatible release —
/// no publish-ordering gymnastics required.
///
/// When `include_prereleases` is false (field default), pre-releases are
/// skipped; when true (operator opted the box into the test channel),
/// they're eligible.
pub async fn check_for_update(include_prereleases: bool) -> Result<AifwUpdateInfo, UpdaterError> {
    let current = get_current_version().await;
    let json = http_get(GITHUB_RELEASES_URL).await?;
    let releases: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| UpdaterError::Json(e.to_string()))?;
    let list = releases
        .as_array()
        .ok_or_else(|| UpdaterError::Json("release list is not an array".to_string()))?;

    let os = current_os_release().await;
    let (release, blocked) = select_release(list, include_prereleases, os.as_deref())
        .ok_or_else(|| UpdaterError::Json("no releases found".to_string()))?;

    let tag = release["tag_name"].as_str().unwrap_or("v0.0.0");
    let latest = tag.strip_prefix('v').unwrap_or(tag);
    let notes = release["body"].as_str().unwrap_or("").to_string();
    let published = release["published_at"].as_str().unwrap_or("").to_string();

    let (tarball_url, checksum_url, checksum_signature_url) = release_asset_urls(release);

    let (has_backup, backup_version) = get_backup_info().await;
    let restart_pending = restart_pending().await;
    let (reboot_recommended, reboot_reason) = parse_reboot_hint(&notes);
    // Set only in the no-compatible-release fallback: the offered release
    // itself needs a newer OS, and the pre-#624 gate semantics apply.
    let required_os = parse_required_os(&notes);
    let os_upgrade_required = match (&required_os, &os) {
        (Some(req), Some(cur)) => !os_satisfies(cur, req),
        _ => false,
    };
    let (blocked_version, blocked_requires_os) = blocked.unzip();

    Ok(AifwUpdateInfo {
        update_available: version_newer(&current, latest),
        current_version: current,
        latest_version: latest.to_string(),
        release_notes: notes,
        published_at: published,
        tarball_url,
        checksum_url,
        checksum_signature_url,
        has_backup,
        backup_version,
        restart_pending,
        running_version: running_version().to_string(),
        reboot_recommended,
        reboot_reason,
        include_prereleases,
        required_os,
        os_upgrade_required,
        blocked_version,
        blocked_requires_os,
    })
}

/// Pick the release to offer for install and, separately, the newest
/// release the OS can't run yet (#624).
///
/// Returns `(install_candidate, Some((version, required_os)))` when a
/// newer-but-OS-blocked release exists above the candidate. When NO
/// visible release is compatible, falls back to the newest visible one —
/// the install-side gates (#612) still refuse it, and the pre-#624
/// `required_os`/`os_upgrade_required` fields describe it.
pub(super) fn select_release<'a>(
    list: &'a [serde_json::Value],
    include_prereleases: bool,
    current_os: Option<&str>,
) -> Option<(&'a serde_json::Value, Option<(String, String)>)> {
    let visible: Vec<&serde_json::Value> = list
        .iter()
        .filter(|r| {
            !r["draft"].as_bool().unwrap_or(false)
                && (include_prereleases || !r["prerelease"].as_bool().unwrap_or(false))
        })
        .collect();
    let newest = *visible.first()?;

    let compatible = visible.iter().copied().find(|r| {
        match parse_required_os(r["body"].as_str().unwrap_or("")) {
            // Unstamped releases predate the gate; treat as installable —
            // the tarball-level required-os check still backstops.
            None => true,
            Some(req) => current_os
                .map(|cur| os_satisfies(cur, &req))
                .unwrap_or(true),
        }
    });

    match compatible {
        Some(c) => {
            let blocked = if !std::ptr::eq(c, newest) {
                let ver = newest["tag_name"]
                    .as_str()
                    .unwrap_or("")
                    .trim_start_matches('v')
                    .to_string();
                parse_required_os(newest["body"].as_str().unwrap_or("")).map(|req| (ver, req))
            } else {
                None
            };
            Some((c, blocked))
        }
        None => Some((newest, None)),
    }
}

/// Look for `[reboot-recommended]` in release notes. If present, the
/// UI/CLI surface the reboot path as the primary action. Anything on the
/// same line after the marker becomes the human-readable reason.
///
/// Example release-note line:
///   `[reboot-recommended] changes service-supervision rc.d scripts`
pub(super) fn parse_reboot_hint(notes: &str) -> (bool, Option<String>) {
    const MARKER: &str = "[reboot-recommended]";
    for line in notes.lines() {
        if let Some(idx) = line.find(MARKER) {
            let tail = line[idx + MARKER.len()..].trim();
            let reason = if tail.is_empty() {
                None
            } else {
                Some(tail.to_string())
            };
            return (true, reason);
        }
    }
    (false, None)
}

/// Look for a `Requires-OS:` line in release notes and extract the FreeBSD
/// release it names (e.g. `Requires-OS: FreeBSD 15.1` → "15.1"). Written
/// into release bodies by CI and release.sh from the version the binaries
/// were built on; absent on older releases.
pub(super) fn parse_required_os(notes: &str) -> Option<String> {
    const MARKER: &str = "Requires-OS:";
    for line in notes.lines() {
        if let Some(idx) = line.find(MARKER) {
            let tail = &line[idx + MARKER.len()..];
            if let Some(ver) = extract_os_version(tail) {
                return Some(ver);
            }
        }
    }
    None
}

/// Pull the first `major.minor` token out of a string like
/// "FreeBSD 15.1" or "15.0-RELEASE-p11".
pub(super) fn extract_os_version(s: &str) -> Option<String> {
    for token in s.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if parse_os_release(token).is_some() {
            return Some(token.to_string());
        }
    }
    None
}

/// Parse "15.1" (optionally with a "-RELEASE..." suffix) into (major, minor).
pub(super) fn parse_os_release(s: &str) -> Option<(u32, u32)> {
    let base = s.split('-').next().unwrap_or(s);
    let mut parts = base.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

/// Essential system files that must exist and be non-empty after an OS
/// upgrade. A corrupted freebsd-update install once deleted
/// /bin/freebsd-version without replacing it (#636) — version checks alone
/// can't see that class of damage.
pub const OS_CANARY_FILES: [&str; 4] = [
    "/bin/sh",
    "/bin/freebsd-version",
    "/sbin/init",
    "/sbin/pfctl",
];

/// Return the canary files from `paths` that are missing or empty.
/// Empty result = system passes the post-upgrade sanity check.
pub fn missing_canaries(paths: &[&str]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| {
            std::fs::metadata(p)
                .map(|m| !m.is_file() || m.len() == 0)
                .unwrap_or(true)
        })
        .map(|p| p.to_string())
        .collect()
}

/// Running kernel release from `uname -r` ("15.1-RELEASE-p1"), or None
/// when unavailable. Distinct from [`current_os_release`] (userland):
/// mid-OS-upgrade the box boots the new kernel while the userland is
/// still old — that window is exactly when the post-reboot install
/// passes must run (#628).
pub async fn running_kernel_release() -> Option<String> {
    let out = Command::new("uname").arg("-r").output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// Running FreeBSD userland release ("15.0-RELEASE-p11"), or None when
/// `freebsd-version` isn't available (dev hosts, tests).
pub async fn current_os_release() -> Option<String> {
    let out = Command::new("freebsd-version")
        .arg("-u")
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// True when the running release `current` satisfies `required`
/// (major.minor compare; unparseable inputs are treated as satisfied so a
/// malformed stamp can never brick updates).
pub fn os_satisfies(current: &str, required: &str) -> bool {
    match (parse_os_release(current), parse_os_release(required)) {
        (Some(cur), Some(req)) => cur >= req,
        _ => true,
    }
}

pub(super) fn version_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
    parse(latest) > parse(current)
}
