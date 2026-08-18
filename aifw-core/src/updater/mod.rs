//! AiFw self-updater — checks GitHub Releases for new versions and installs updates.
//!
//! Component lists are driven by `freebsd/manifest.json` (single source of truth).
//! The manifest is embedded at compile time so no runtime file dependency.
//!
//! Split by concern (#439): see the submodules; everything the rest of the
//! workspace calls is re-exported here so `aifw_core::updater::*` paths
//! are unchanged.

mod embedded;
mod http;
mod install;
mod manifest;
mod rollback;
mod services;
mod types;
mod verify;
mod version;

#[cfg(test)]
mod tests;

// Private glob imports: every submodule sees its siblings' pub(super)
// items through `use super::*`, and the test module through `super::*`.
use embedded::*;
use http::*;
use manifest::*;
use rollback::*;
use types::*;
use verify::*;

pub use install::{download_and_install, install_from_path};
pub use manifest::manifest_packages;
pub use rollback::rollback;
pub use services::{
    SHUTDOWN_REBOOT_ARGS, ensure_libexec_scripts, ensure_rcvars, restart_services,
    restart_services_sync, schedule_reboot,
};
pub use types::{AifwUpdateInfo, UpdaterError};
pub use verify::extract_hash_pub;
pub use version::{
    OS_CANARY_FILES, check_for_update, current_os_release, get_current_version, missing_canaries,
    os_satisfies, restart_pending, running_kernel_release, running_version,
};
