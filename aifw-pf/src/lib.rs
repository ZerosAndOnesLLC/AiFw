#![warn(missing_docs)]
//! # aifw-pf
//!
//! Abstraction over FreeBSD `pf`. The [`backend::PfBackend`] trait is
//! implemented by an in-memory mock (Linux/WSL, for development and tests)
//! and an ioctl/pfctl backend (FreeBSD), selected at compile time via
//! `#[cfg(target_os)]`. Use [`create_backend`] to get the right one.

/// The [`PfBackend`] trait — the cross-platform pf abstraction all engines code against
pub mod backend;
/// Crate error type ([`PfError`]) covering device, ioctl, rule, table, and anchor failures
pub mod error;
#[cfg(test)]
mod tests;
/// Data types returned by backends: state entries, counters, table entries
pub mod types;

// Both backends always compile so cargo check on any host catches
// schema mismatches in the FreeBSD-only ioctl path. Only one is
// selected at runtime by create_backend() below.
/// Real FreeBSD backend — shells out to `sudo pfctl` (raw /dev/pf ioctl planned)
pub mod ioctl;
/// In-memory mock backend used on Linux/WSL for development and in tests
pub mod mock;

pub use backend::PfBackend;
pub use error::PfError;
pub use ioctl::PfIoctl;
pub use mock::PfMock;
pub use types::{PfState, PfStats, PfTableEntry};

/// Return the [`PfBackend`] for the current platform.
///
/// Backend selection is compile-time via `#[cfg(target_os)]`, not a runtime
/// flag: FreeBSD gets the real [`PfIoctl`] (pfctl/ioctl), every other target
/// gets the in-memory [`PfMock`]. The two `cfg` arms are mutually exclusive
/// and exhaustive, so exactly one is compiled in.
///
/// The `.expect` on FreeBSD is justified: the daemon cannot function without
/// `/dev/pf`, and failing to open it is an unrecoverable boot-time condition
/// that should abort loudly rather than silently degrade.
pub fn create_backend() -> Box<dyn PfBackend> {
    #[cfg(not(target_os = "freebsd"))]
    {
        Box::new(PfMock::new())
    }
    #[cfg(target_os = "freebsd")]
    {
        Box::new(PfIoctl::new().expect("failed to open /dev/pf"))
    }
}
