//! Compile-time constants: release URLs, install paths, and the helper scripts embedded so a fresh install can lay them down.

// Lists releases newest-first INCLUDING pre-releases (and drafts), unlike
// /releases/latest which silently skips them. Used only when the operator
// opts into the pre-release channel.
pub(super) const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/ZerosAndOnesLLC/AiFw/releases?per_page=20";
pub(super) const VERSION_FILE: &str = "/usr/local/share/aifw/version";
pub(super) const BACKUP_DIR: &str = "/usr/local/share/aifw/backup";
pub(super) const BIN_DIR: &str = "/usr/local/sbin";
pub(super) const UI_DIR: &str = "/usr/local/share/aifw/ui";

/// Manifest embedded at compile time from freebsd/manifest.json.
pub(super) const MANIFEST_JSON: &str = include_str!("../../../freebsd/manifest.json");

/// Restart-driver and watchdog scripts embedded into the binary at compile
/// time. Written to /usr/local/libexec/ on aifw-api startup so a transitional
/// upgrade — where the running updater predates `libexec/` iteration in
/// the install path — can still self-bootstrap. Without this, an old
/// updater installs new aifw-api binaries but leaves the supporting
/// scripts missing, and the next restart_services call falls back to the
/// fragile in-process loop. Embedding closes that loop.
pub(super) const EMBEDDED_RESTART_SH: &str =
    include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-restart.sh");
pub(super) const EMBEDDED_WATCHDOG_SH: &str =
    include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-watchdog.sh");

/// All `aifw-sudo-*` narrow-grant helper scripts, embedded at compile time.
/// `ensure_libexec_scripts()` writes them at every aifw-api startup so an
/// in-place tarball upgrade from a pre-#204 appliance (no narrow helpers on
/// disk yet) self-bootstraps the wrapper inventory. Without this, the new
/// code's `crate::sudo::*` wrappers would all fail (helper not found, sudo
/// refused) on cold-boot from an old image.
pub(super) const EMBEDDED_SUDO_HELPERS: &[(&str, &str)] = &[
    (
        "aifw-sudo-install",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-install"),
    ),
    (
        "aifw-sudo-write",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-write"),
    ),
    (
        "aifw-sudo-wg",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-wg"),
    ),
    (
        "aifw-sudo-freebsd-update",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-freebsd-update"),
    ),
    (
        "aifw-sudo-pkg",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-pkg"),
    ),
    (
        "aifw-sudo-service",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-service"),
    ),
    (
        "aifw-sudo-chown",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-chown"),
    ),
    (
        "aifw-sudo-ifconfig",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-ifconfig"),
    ),
    (
        "aifw-sudo-sysrc",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-sysrc"),
    ),
    (
        "aifw-sudo-dhclient",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-dhclient"),
    ),
    (
        "aifw-sudo-route",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-route"),
    ),
    (
        "aifw-sudo-pkill",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-pkill"),
    ),
    (
        "aifw-sudo-rm",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-rm"),
    ),
    (
        "aifw-sudo-mkdir",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-mkdir"),
    ),
    (
        "aifw-sudo-cp",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-cp"),
    ),
    (
        "aifw-sudo-tar",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-tar"),
    ),
    (
        "aifw-sudo-tcpdump",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-tcpdump"),
    ),
    (
        "aifw-sudo-swanctl",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-swanctl"),
    ),
    (
        "aifw-sudo-newsyslog",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-newsyslog"),
    ),
    (
        "aifw-sudo-dummynet",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-dummynet"),
    ),
    (
        "aifw-dummynet-control",
        include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-dummynet-control"),
    ),
];
