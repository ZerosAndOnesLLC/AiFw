pub mod backend;
pub mod error;
#[cfg(test)]
mod tests;
pub mod types;

// Both backends always compile so cargo check on any host catches
// schema mismatches in the FreeBSD-only ioctl path. Only one is
// selected at runtime by create_backend() below.
pub mod ioctl;
pub mod mock;

pub use backend::PfBackend;
pub use error::PfError;
pub use ioctl::PfIoctl;
pub use mock::PfMock;
pub use types::{PfState, PfStats, PfTableEntry};

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
