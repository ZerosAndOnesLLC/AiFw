//! Packet-capture data model and the `CaptureBackend` trait implemented
//! by the per-platform backends (pcap, bpf, netmap).

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

/// A raw captured packet — timestamp + data.
///
/// `data` uses `SmallVec` with a 1600-byte inline buffer (one Ethernet MTU);
/// the common-case packet incurs zero heap allocation. Jumbo frames or other
/// >1600-byte payloads spill to the heap automatically.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// Packet timestamp as microseconds since epoch
    pub timestamp_us: i64,
    /// Packet bytes — inline up to 1600, heap-spilled beyond.
    pub data: smallvec::SmallVec<[u8; 1600]>,
    /// Original wire length (may be > data.len() if snaplen truncated)
    pub orig_len: usize,
}

/// Statistics from a capture backend
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// Packets delivered to the capture handle
    pub packets_received: u64,
    /// Packets dropped because the kernel buffer was full
    pub packets_dropped: u64,
    /// Packets dropped by the network interface itself
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
            data: smallvec::SmallVec::from_slice(&[0u8; 64]),
            orig_len: 64,
        };
        assert_eq!(pkt.data.len(), 64);
    }
}
