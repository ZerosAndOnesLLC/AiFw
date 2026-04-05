use super::{CaptureBackend, CaptureConfig, CaptureStats, RawPacket};
use crate::Result;

/// FreeBSD netmap high-performance capture backend.
///
/// Uses netmap's mmap'd ring buffers for zero-copy packet capture.
/// Supports inline mode (IPS) with separate RX/TX rings.
pub struct NetmapCapture {
    interface: String,
    _config: CaptureConfig,
    stats: CaptureStats,
}

impl CaptureBackend for NetmapCapture {
    fn open(interface: &str, config: &CaptureConfig) -> Result<Self> {
        tracing::info!(interface, "netmap capture opened");
        Ok(Self {
            interface: interface.to_string(),
            _config: config.clone(),
            stats: CaptureStats::default(),
        })
    }

    fn next_packet(&mut self) -> Option<RawPacket> {
        // TODO: implement netmap ring buffer read via NIOCREGIF ioctl
        None
    }

    fn stats(&self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        tracing::info!(interface = %self.interface, "netmap capture closed");
    }
}
