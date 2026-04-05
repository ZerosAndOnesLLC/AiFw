use super::{CaptureBackend, CaptureConfig, CaptureStats, RawPacket};
use crate::Result;

/// FreeBSD BPF (Berkeley Packet Filter) capture backend.
///
/// Uses /dev/bpf to capture packets directly from network interfaces.
/// This is the default production backend on FreeBSD.
pub struct BpfCapture {
    interface: String,
    _config: CaptureConfig,
    stats: CaptureStats,
}

impl CaptureBackend for BpfCapture {
    fn open(interface: &str, config: &CaptureConfig) -> Result<Self> {
        tracing::info!(interface, "BPF capture opened");
        Ok(Self {
            interface: interface.to_string(),
            _config: config.clone(),
            stats: CaptureStats::default(),
        })
    }

    fn next_packet(&mut self) -> Option<RawPacket> {
        // TODO: implement BPF read via /dev/bpf ioctl
        None
    }

    fn stats(&self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        tracing::info!(interface = %self.interface, "BPF capture closed");
    }
}
