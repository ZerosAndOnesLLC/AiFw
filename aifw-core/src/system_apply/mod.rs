//! Apply-layer for System settings.
//!
//! This module root holds no implementation (#477): it declares the
//! submodules and re-exports their surface. `types` carries the shared
//! data types; the apply functions come from `stub_impl` on Linux/WSL
//! (no-op, dev) and from `freebsd_impl` on FreeBSD (writes to /etc/*,
//! /boot/loader.conf, and runs service/sysrc commands).

pub mod freebsd_helpers;
pub mod types;

pub use types::*;

// ----- Linux/WSL (dev): no-op apply, stub info -----
#[cfg(not(target_os = "freebsd"))]
mod stub_impl;

#[cfg(not(target_os = "freebsd"))]
pub use stub_impl::{
    apply_banner, apply_console, apply_general, apply_ssh, collect_info,
    motd_user_edited_marker_set,
};

// ----- FreeBSD: real apply -----
#[cfg(target_os = "freebsd")]
mod freebsd_impl;

#[cfg(target_os = "freebsd")]
pub use freebsd_impl::{
    apply_banner, apply_console, apply_general, apply_ssh, collect_info,
    motd_user_edited_marker_set,
};
