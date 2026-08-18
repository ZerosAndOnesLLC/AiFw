//! `freebsd/manifest.json` (embedded) — component lists and package set.

use serde::Deserialize;

use super::*;

#[derive(Deserialize)]
pub(super) struct Manifest {
    pub(super) binaries: ManifestBinaries,
    pub(super) external_repos: Vec<ExternalRepo>,
    pub(super) rc_scripts: Vec<String>,
    // `sbin_scripts` / `libexec_scripts` exist in manifest.json for the build
    // scripts; the updater ships those via LIBEXEC_SCRIPTS below, so they are
    // deliberately not deserialized here (serde ignores unknown keys).
    pub(super) directories: Vec<String>,
    /// OS packages the appliance needs at runtime. Installed by
    /// build-iso.sh at image build; the updater installs any that are
    /// missing so in-place upgrades pick up new dependencies (#530
    /// added strongswan this way).
    #[serde(default)]
    pub(super) packages: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct ManifestBinaries {
    pub(super) local: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct ExternalRepo {
    pub(super) binaries: Vec<String>,
    /// Human-readable companion name — used only in packaging-test failure
    /// messages. (`repo` is build-script-only and not deserialized; serde
    /// ignores unknown keys.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) name: String,
    /// crates.io package the build installs (#651, replaced the git SHA pins).
    /// Read only by the packaging guard tests, which assert every companion
    /// pin is a well-formed crate + semver so a bad manifest fails CI rather
    /// than the release build.
    #[serde(rename = "crate")]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) crate_name: String,
    /// Exact published version pinned for appliance artifacts. Test-only
    /// reader, see `crate_name`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) version: String,
}

/// OS packages this build requires, from the embedded manifest. Exposed
/// for `aifw-setup --print-packages`, which aifw-restart.sh queries to
/// install dependencies a transitional upgrade missed (#565: the old
/// updater binary's embedded manifest predates newly-added packages).
pub fn manifest_packages() -> Vec<String> {
    load_manifest().packages
}

/// Parse the embedded manifest. The `expect` is provably infallible: the
/// same bytes are parsed by `tests::embedded_manifest_parses`, so a
/// malformed `freebsd/manifest.json` fails the build's test run rather than
/// the first updater call on an appliance (#439).
pub(super) fn load_manifest() -> Manifest {
    serde_json::from_str(MANIFEST_JSON).expect("freebsd/manifest.json is invalid")
}

/// SEC-H11: reject a `tar tf` listing if any entry would escape the extract
/// directory — an absolute path or a `..` path component. Pure so it can be
/// unit-tested without touching the filesystem or a real tarball.
pub(super) fn validate_tar_listing(listing: &str) -> Result<(), String> {
    for raw in listing.lines() {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let path = entry.trim_start_matches("./");
        if entry.starts_with('/') || path.starts_with('/') || path.split('/').any(|c| c == "..") {
            return Err(format!(
                "refusing unsafe tarball: entry escapes extract dir: {entry}"
            ));
        }
    }
    Ok(())
}

/// All binary names from manifest (local + external).
pub(super) fn all_binaries() -> Vec<String> {
    let m = load_manifest();
    let mut bins = m.binaries.local;
    for repo in &m.external_repos {
        bins.extend(repo.binaries.iter().cloned());
    }
    bins
}
