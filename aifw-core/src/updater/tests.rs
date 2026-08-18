//! Unit tests for the updater (guard tests included).

use super::embedded::*;
use super::http::*;
use super::manifest::*;
use super::verify::*;
use super::version::*;

// SEC-H11 (#296): the tar-listing guard must reject any archive entry
// that would escape the extraction directory.
#[test]
fn tar_listing_rejects_traversal_and_absolute() {
    for bad in [
        "aifw-5.97/\n../evil",
        "../../etc/cron.d/x",
        "/etc/passwd",
        "aifw-5.97/bin/../../../root/.ssh/authorized_keys",
        "./../escape",
    ] {
        assert!(
            validate_tar_listing(bad).is_err(),
            "should reject listing: {bad:?}"
        );
    }
}

#[test]
fn tar_listing_accepts_normal_release() {
    let ok =
        "aifw-5.97.9/\naifw-5.97.9/bin/\naifw-5.97.9/bin/aifw-api\n./aifw-5.97.9/ui/index.html\n";
    assert!(validate_tar_listing(ok).is_ok());
}

// #624: install candidate = newest OS-compatible release; the newest
// OS-blocked one is surfaced separately. Both may exist at once.
#[test]
fn release_selection_offers_newest_compatible_and_surfaces_blocked() {
    let rel = |tag: &str, body: &str, pre: bool| {
        serde_json::json!({
            "tag_name": tag, "body": body,
            "prerelease": pre, "draft": false,
        })
    };
    let list = vec![
        rel("v5.113.1", "Requires-OS: FreeBSD 15.1", true),
        rel("v5.112.6", "Requires-OS: FreeBSD 15.0", true),
        rel("v5.109.2", "old release, no stamp", false),
    ];

    // 15.0 box, pre-release channel: installs v5.112.6, sees v5.113.1
    // blocked behind the 15.1 floor.
    let (chosen, blocked) = select_release(&list, true, Some("15.0-RELEASE-p11")).unwrap();
    assert_eq!(chosen["tag_name"], "v5.112.6");
    assert_eq!(blocked, Some(("5.113.1".to_string(), "15.1".to_string())));

    // 15.1 box: newest is compatible; nothing blocked.
    let (chosen, blocked) = select_release(&list, true, Some("15.1-RELEASE")).unwrap();
    assert_eq!(chosen["tag_name"], "v5.113.1");
    assert_eq!(blocked, None);

    // Stable channel skips pre-releases entirely: unstamped v5.109.2.
    let (chosen, blocked) = select_release(&list, false, Some("15.0-RELEASE")).unwrap();
    assert_eq!(chosen["tag_name"], "v5.109.2");
    assert_eq!(blocked, None);

    // No compatible release at all: fall back to the newest (the
    // install-side gate still refuses it), nothing separately blocked.
    let only_new = vec![rel("v6.0.0", "Requires-OS: FreeBSD 16.0", false)];
    let (chosen, blocked) = select_release(&only_new, false, Some("15.1-RELEASE")).unwrap();
    assert_eq!(chosen["tag_name"], "v6.0.0");
    assert_eq!(blocked, None);

    // Unknown OS (dev box): everything is treated as compatible.
    let (chosen, _) = select_release(&list, true, None).unwrap();
    assert_eq!(chosen["tag_name"], "v5.113.1");
}

// #612: the OS floor stamp in release notes must parse from the shapes
// CI and release.sh actually write.
#[test]
fn required_os_parses_from_release_notes() {
    assert_eq!(
        parse_required_os("## AiFw v5.113.0\n\nRequires-OS: FreeBSD 15.1\n"),
        Some("15.1".to_string())
    );
    assert_eq!(
        parse_required_os("Requires-OS: 15.1"),
        Some("15.1".to_string())
    );
    assert_eq!(
        parse_required_os("body without a marker\nFreeBSD 15.1 mentioned casually"),
        None
    );
    assert_eq!(parse_required_os("Requires-OS: soon"), None);
}

#[test]
fn os_release_parsing_handles_patch_suffixes() {
    assert_eq!(parse_os_release("15.1"), Some((15, 1)));
    assert_eq!(parse_os_release("15.0-RELEASE-p11"), Some((15, 0)));
    assert_eq!(parse_os_release("16.10-RELEASE"), Some((16, 10)));
    assert_eq!(parse_os_release("garbage"), None);
    assert_eq!(parse_os_release("15"), None);
}

// #612: version compare drives both the install gate and the UI hint.
// Minor 10 must beat minor 9 (numeric, not lexicographic), and
// unparseable stamps must never block an update.
#[test]
fn os_satisfies_compares_numerically_and_fails_open() {
    assert!(os_satisfies("15.1-RELEASE-p1", "15.1"));
    assert!(os_satisfies("15.10-RELEASE", "15.9"));
    assert!(os_satisfies("16.0-RELEASE", "15.1"));
    assert!(!os_satisfies("15.0-RELEASE-p11", "15.1"));
    assert!(!os_satisfies("14.3-RELEASE", "15.0"));
    assert!(os_satisfies("unknowable", "15.1"));
    assert!(os_satisfies("15.1-RELEASE", "not-a-version"));
}

// #612/#613: the embedded self-healing copy of the freebsd-update
// helper must keep the validated `upgrade` action — losing it silently
// breaks the OS upgrade flow on appliances (sudoers drift, #204).
#[test]
fn embedded_freebsd_update_helper_supports_upgrade() {
    let helper = EMBEDDED_SUDO_HELPERS
        .iter()
        .find(|(name, _)| *name == "aifw-sudo-freebsd-update")
        .map(|(_, body)| *body)
        .expect("aifw-sudo-freebsd-update must be embedded for self-healing");
    assert!(
        helper.contains("upgrade)"),
        "helper lost its upgrade action"
    );
    assert!(
        helper.contains("-RELEASE"),
        "helper must validate the X.Y-RELEASE target format"
    );
    assert!(
        helper.contains("yes |"),
        "upgrade must run non-interactively or merge prompts hang the daemon"
    );
    // #636 hardening: retries must survive half-upgraded and
    // corrupted states.
    assert!(
        helper.contains("--currently-running"),
        "upgrade must pin the source release to the userland (#636)"
    );
    assert!(
        helper.contains("reset)"),
        "helper lost its reset action — clean retry depends on it (#636)"
    );
    assert!(
        helper.contains("repair-base)"),
        "helper lost its repair-base action — stripped appliances can't upgrade without it (#641)"
    );
}

// #636: the canary check must flag missing/empty essentials and pass
// on files that exist.
#[test]
fn canary_check_flags_missing_files() {
    assert!(missing_canaries(&["/bin/sh"]).is_empty());
    assert_eq!(
        missing_canaries(&["/nonexistent/aifw-canary-test"]),
        vec!["/nonexistent/aifw-canary-test".to_string()]
    );
}

// SEC-H11 (#296): the install allowlist is derived from the embedded
// manifest and must contain the core binaries but not arbitrary names.
#[test]
fn binary_allowlist_covers_core_but_not_arbitrary() {
    let allowed: std::collections::HashSet<String> = all_binaries().into_iter().collect();
    assert!(
        allowed.contains("aifw-api"),
        "core binary must be allowlisted"
    );
    assert!(
        allowed.contains("aifw-daemon"),
        "core binary must be allowlisted"
    );
    assert!(
        !allowed.contains("aifw-evil"),
        "arbitrary aifw-* name must not be allowlisted"
    );
    assert!(!allowed.contains("evil"));
}

// Regression gate (#188-style): both root-run drivers must refresh the
// sudoers file from the canonical aifw-setup definition. An in-place
// tarball upgrade installs new aifw-sudo-* helpers but the aifw-uid
// updater cannot write sudoers (SEC-C1); these scripts are the only
// root-context hook that closes the gap. If someone strips the refresh,
// upgraded boxes silently regress to "sudo: a password is required" on
// every operation that calls a narrow helper (e.g. DNS resolver apply).
#[test]
fn test_restart_driver_refreshes_sudoers() {
    for (name, script) in [
        ("aifw-restart.sh", EMBEDDED_RESTART_SH),
        ("aifw-watchdog.sh", EMBEDDED_WATCHDOG_SH),
    ] {
        assert!(
            script.contains("aifw-setup --print-sudoers"),
            "{name} must regenerate sudoers from aifw-setup"
        );
        // Absolute path required (#601): a bare `visudo` isn't found
        // under the daemon(8) default PATH, silently disabling the
        // refresh on every boot.
        assert!(
            script.contains("VISUDO=/usr/local/sbin/visudo"),
            "{name} must resolve visudo by absolute path (not in daemon PATH)"
        );
        assert!(
            script.contains("\"$VISUDO\" -cf"),
            "{name} must validate sudoers with visudo before installing"
        );
        assert!(
            script.contains("/usr/local/etc/sudoers.d/aifw"),
            "{name} must install to the canonical sudoers path"
        );
        assert!(
            script.contains("refresh_sudoers"),
            "{name} must invoke the refresh_sudoers routine"
        );
    }
}

// #565: the restart driver (new-tarball code, runs as root) must
// install packages the old updater binary's embedded manifest didn't
// know about — the only reliable hook on a transitional upgrade.
#[test]
fn test_restart_driver_ensures_packages() {
    assert!(
        EMBEDDED_RESTART_SH.contains("aifw-setup --print-packages"),
        "aifw-restart.sh must query the new binary's package list"
    );
    assert!(
        EMBEDDED_RESTART_SH.contains("pkg install"),
        "aifw-restart.sh must install missing packages"
    );
    assert!(
        EMBEDDED_RESTART_SH.contains("ensure_packages"),
        "aifw-restart.sh must invoke the ensure_packages routine"
    );
}

// #564: aifw-console is root's login shell; it must exec `-c`
// commands (ssh/scp/sftp) instead of rendering the menu, and must
// exit — not busy-loop — when stdin hits EOF.
#[test]
fn test_console_passthrough_and_eof_exit() {
    let console = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../freebsd/overlay/usr/local/sbin/aifw-console"),
    )
    .expect("aifw-console exists in the overlay");
    assert!(
        console.contains(r#"exec /bin/sh -c "$@""#),
        "aifw-console must pass -c commands through to a real shell"
    );
    assert!(
        console.contains("read choice || exit"),
        "aifw-console menu must exit on stdin EOF, not busy-loop"
    );
}

#[test]
fn test_version_newer() {
    assert!(version_newer("5.3.3", "5.3.4"));
    assert!(version_newer("5.3.3", "5.4.0"));
    assert!(version_newer("5.3.3", "6.0.0"));
    assert!(!version_newer("5.3.3", "5.3.3"));
    assert!(!version_newer("5.3.4", "5.3.3"));
}

#[test]
fn test_extract_hash_freebsd() {
    let input = "SHA256 (aifw-update-5.3.4-amd64.tar.xz) = abc123def456";
    assert_eq!(extract_hash(input), "abc123def456");
}

#[test]
fn test_extract_hash_linux() {
    let input = "abc123def456  aifw-update-5.3.4-amd64.tar.xz";
    assert_eq!(extract_hash(input), "abc123def456");
}

#[test]
fn test_extract_hash_plain() {
    let input = "abc123def456";
    assert_eq!(extract_hash(input), "abc123def456");
}

// The compiled-in signing key is the trust root for every self-update:
// if the committed .pub file is reformatted into something this parser
// rejects, all appliances fail closed on the next release.
#[test]
fn embedded_update_signing_pubkey_parses() {
    let key = embedded_pubkey_b64().expect("embedded public key must parse");
    assert!(
        key.starts_with("RW"),
        "minisign keys are RW-prefixed: {key}"
    );
    assert!(!key.contains(char::is_whitespace));
    assert_eq!(key.len(), 56, "Ed25519 minisign pubkey is 56 base64 chars");
}

#[test]
fn release_assets_require_distinct_checksum_and_signature_sidecars() {
    let release = serde_json::json!({"assets": [
        {"name": "aifw-update-6.0.0-amd64.tar.xz", "browser_download_url": "tar"},
        {"name": "aifw-update-6.0.0-amd64.tar.xz.sha256", "browser_download_url": "sum"},
        {"name": "aifw-update-6.0.0-amd64.tar.xz.sha256.minisig", "browser_download_url": "sig"}
    ]});
    assert_eq!(
        release_asset_urls(&release),
        (Some("tar".into()), Some("sum".into()), Some("sig".into()))
    );
}

// Regression gate for #469: every overlay libexec script must carry the
// execute bit in git. Eight aifw-sudo-* helpers were committed mode 644,
// build-iso.sh's `cp -a` preserved that onto installed systems, and sudo
// reports a non-executable helper as "command not found" — bricking the
// in-app updater on every ISO install. The exec bit lives in the git
// index, so a plain checkout is enough to assert on.
#[test]
fn test_overlay_libexec_scripts_are_executable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../freebsd/overlay/usr/local/libexec");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("overlay libexec dir exists") {
        let entry = entry.expect("readable dir entry");
        if !entry.file_type().expect("file type").is_file() {
            continue;
        }
        let mode = entry.metadata().expect("metadata").permissions().mode();
        assert!(
            mode & 0o111 != 0,
            "{} is not executable (mode {:o}) — sudo will report it as \
             'command not found' on the appliance (#469)",
            entry.path().display(),
            mode
        );
        checked += 1;
    }
    assert!(checked > 0, "no files found in {}", dir.display());
}

// The embedded self-heal list must cover every aifw-sudo-* helper in the
// overlay, or an upgraded box misses helpers that never shipped in its
// original image (the tarball libexec/ install covers them too, but CI
// tarballs lacked libexec/ entirely until v5.97.6 — belt and suspenders).
#[test]
fn test_embedded_helpers_cover_overlay() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../freebsd/overlay/usr/local/libexec");
    for entry in std::fs::read_dir(&dir).expect("overlay libexec dir exists") {
        let name = entry.expect("readable dir entry").file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("aifw-sudo-") {
            continue;
        }
        assert!(
            EMBEDDED_SUDO_HELPERS.iter().any(|(n, _)| *n == name),
            "{} exists in the overlay but is missing from \
             EMBEDDED_SUDO_HELPERS in updater/embedded.rs",
            name
        );
    }
}

// manifest.json `packages` is the source of truth for runtime OS
// dependencies, but build-iso.sh and deploy.sh carry hardcoded copies
// (no jq in the ISO build chroot). Keep them in sync (#530 added
// strongswan this way).
#[test]
fn test_manifest_packages_synced_with_build_scripts() {
    let manifest = load_manifest();
    assert!(
        !manifest.packages.is_empty(),
        "manifest.json packages list is empty"
    );
    let build_iso = include_str!("../../../freebsd/build-iso.sh");
    let deploy = include_str!("../../../freebsd/deploy.sh");
    let iso_line = build_iso
        .lines()
        .find(|l| l.contains("pkg install -y"))
        .expect("build-iso.sh has a pkg install line");
    let deploy_line = deploy
        .lines()
        .find(|l| l.trim_start().starts_with("for pkg in "))
        .expect("deploy.sh has a dependency for-loop");
    for pkg in &manifest.packages {
        let pkg = pkg.as_str();
        assert!(
            iso_line.split_whitespace().any(|w| w == pkg),
            "package {pkg:?} from manifest.json missing from build-iso.sh pkg install line: {iso_line}"
        );
        assert!(
            deploy_line
                .split_whitespace()
                .any(|w| w.trim_end_matches(';') == pkg),
            "package {pkg:?} from manifest.json missing from deploy.sh dependency loop: {deploy_line}"
        );
    }
}

// Companion components are installed from crates.io at the versions
// pinned in manifest.json (#651, replacing the #538 git SHA pins).
// Every entry must carry a crate name and an exact published version,
// and the release build paths must consume those pins — a `.commit`
// reference reappearing means someone resurrected the retired
// clone-and-checkout scheme.
#[test]
fn test_external_repos_pin_crates_io_versions() {
    let manifest = load_manifest();
    assert!(
        !manifest.external_repos.is_empty(),
        "manifest.json external_repos list is empty"
    );
    for repo in &manifest.external_repos {
        assert!(
            !repo.crate_name.is_empty(),
            "external repo {} has no crate name",
            repo.name
        );
        assert!(
            repo.version.split('.').count() == 3
                && repo
                    .version
                    .split('.')
                    .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
            "external repo {} version {:?} is not a plain x.y.z crates.io version",
            repo.name,
            repo.version
        );
        assert!(
            !repo.binaries.is_empty(),
            "external repo {} lists no binaries",
            repo.name
        );
    }
    for (path, content) in [
        (
            "freebsd/build-local.sh",
            include_str!("../../../freebsd/build-local.sh"),
        ),
        (
            "freebsd/build-update.sh",
            include_str!("../../../freebsd/build-update.sh"),
        ),
        (
            ".github/workflows/build-iso.yml",
            include_str!("../../../.github/workflows/build-iso.yml"),
        ),
    ] {
        assert!(
            content.contains("cargo install --locked --version"),
            "{path} no longer installs companions from crates.io at the manifest pin"
        );
        assert!(
            !content.contains(".commit"),
            "{path} references the retired git SHA-pin field (.commit)"
        );
    }
}

/// #439: the compile-time embedded manifest must parse — this is what makes
/// the `expect` in `load_manifest` safe. Also pins the shape the installer
/// relies on (non-empty binaries, rc scripts and package set).
#[test]
fn embedded_manifest_parses() {
    let m: Manifest =
        serde_json::from_str(MANIFEST_JSON).expect("freebsd/manifest.json must parse");
    assert!(!m.binaries.local.is_empty());
    assert!(!m.rc_scripts.is_empty());
    assert!(!m.packages.is_empty());
    assert!(!all_binaries().is_empty());
}
