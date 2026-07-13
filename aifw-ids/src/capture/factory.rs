//! Platform capture-backend selection: BPF on FreeBSD, pcap elsewhere.

use super::types::{CaptureBackend, CaptureConfig};
use crate::Result;

#[cfg(target_os = "freebsd")]
use super::bpf;
#[cfg(not(target_os = "freebsd"))]
use super::pcap;

/// Create the appropriate capture backend for the current platform.
///
/// On FreeBSD, defaults to BPF. On other platforms, uses pcap (for development).
pub fn create_capture(interface: &str, config: &CaptureConfig) -> Result<Box<dyn CaptureBackend>> {
    #[cfg(target_os = "freebsd")]
    {
        Ok(Box::new(bpf::BpfCapture::open(interface, config)?))
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        Ok(Box::new(pcap::PcapCapture::open(interface, config)?))
    }
}
