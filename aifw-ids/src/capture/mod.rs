pub mod pcap;

#[cfg(target_os = "freebsd")]
pub mod bpf;
#[cfg(target_os = "freebsd")]
pub mod netmap;

use crate::Result;

/// Configuration for packet capture
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Maximum bytes to capture per packet
    pub snaplen: u32,
    /// Capture in promiscuous mode
    pub promiscuous: bool,
    /// Kernel buffer size in bytes
    pub buffer_size: u32,
    /// BPF filter string (e.g., "tcp port 80")
    pub bpf_filter: Option<String>,
    /// Read timeout in milliseconds
    pub timeout_ms: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: 65535,
            promiscuous: true,
            buffer_size: 16 * 1024 * 1024, // 16MB
            bpf_filter: None,
            timeout_ms: 100,
        }
    }
}

/// A raw captured packet — timestamp + data
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Packet timestamp as microseconds since epoch
    pub timestamp_us: i64,
    /// Packet data (owned copy; zero-copy variant uses slices in hot path)
    pub data: Vec<u8>,
    /// Original wire length (may be > data.len() if snaplen truncated)
    pub orig_len: usize,
}

/// Statistics from a capture backend
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub packets_if_dropped: u64,
}

/// Trait for packet capture backends.
///
/// Each backend captures packets from a network interface and yields them
/// one at a time via `next_packet()`. The hot path is synchronous to avoid
/// async overhead on the packet-processing threads.
pub trait CaptureBackend: Send {
    /// Open the interface for capture.
    fn open(interface: &str, config: &CaptureConfig) -> Result<Self>
    where
        Self: Sized;

    /// Get the next packet. Returns `None` on timeout (no packet available).
    /// This is the hot path — called in a tight loop by worker threads.
    fn next_packet(&mut self) -> Option<RawPacket>;

    /// Get capture statistics.
    fn stats(&self) -> CaptureStats;

    /// Close the capture handle.
    fn close(&mut self);
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = CaptureConfig::default();
        assert_eq!(cfg.snaplen, 65535);
        assert!(cfg.promiscuous);
        assert!(cfg.bpf_filter.is_none());
    }

    #[test]
    fn test_raw_packet() {
        let pkt = RawPacket {
            timestamp_us: 1000000,
            data: vec![0u8; 64],
            orig_len: 64,
        };
        assert_eq!(pkt.data.len(), 64);
    }
}
