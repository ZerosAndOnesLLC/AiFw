pub mod backend;
pub mod error;
#[cfg(test)]
mod tests;
pub mod types;

#[cfg(not(target_os = "freebsd"))]
pub mod mock;

#[cfg(target_os = "freebsd")]
pub mod ioctl;

pub use backend::PfBackend;
pub use error::PfError;
pub use types::{PfState, PfStats, PfTableEntry};

#[cfg(not(target_os = "freebsd"))]
pub use mock::PfMock;

#[cfg(target_os = "freebsd")]
pub use ioctl::PfIoctl;

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
