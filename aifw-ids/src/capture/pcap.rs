use super::{CaptureBackend, CaptureConfig, CaptureStats, RawPacket};
use crate::Result;

/// pcap-based capture backend for development on Linux/WSL/macOS.
///
/// Uses an in-memory packet queue for testing, or can be connected to a
/// real interface via libpcap FFI (feature-gated, not required for dev).
pub struct PcapCapture {
    interface: String,
    _config: CaptureConfig,
    /// Injected packets for testing
    queue: Vec<RawPacket>,
    queue_pos: usize,
    stats: CaptureStats,
}

impl PcapCapture {
    /// Inject packets for testing purposes.
    pub fn inject_packets(&mut self, packets: Vec<RawPacket>) {
        self.queue = packets;
        self.queue_pos = 0;
    }
}

impl CaptureBackend for PcapCapture {
    fn open(interface: &str, config: &CaptureConfig) -> Result<Self> {
        tracing::info!(interface, snaplen = config.snaplen, "pcap capture opened (mock)");
        Ok(Self {
            interface: interface.to_string(),
            _config: config.clone(),
            queue: Vec::new(),
            queue_pos: 0,
            stats: CaptureStats::default(),
        })
    }

    fn next_packet(&mut self) -> Option<RawPacket> {
        if self.queue_pos < self.queue.len() {
            let pkt = self.queue[self.queue_pos].clone();
            self.queue_pos += 1;
            self.stats.packets_received += 1;
            Some(pkt)
        } else {
            None
        }
    }

    fn stats(&self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        tracing::info!(interface = %self.interface, "pcap capture closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_open_and_capture() {
        let config = CaptureConfig::default();
        let mut cap = PcapCapture::open("eth0", &config).unwrap();

        // No packets initially
        assert!(cap.next_packet().is_none());

        // Inject test packets
        cap.inject_packets(vec![
            RawPacket {
                timestamp_us: 1000,
                data: vec![0xAA; 64],
                orig_len: 64,
            },
            RawPacket {
                timestamp_us: 2000,
                data: vec![0xBB; 128],
                orig_len: 128,
            },
        ]);

        let p1 = cap.next_packet().unwrap();
        assert_eq!(p1.timestamp_us, 1000);
        assert_eq!(p1.data[0], 0xAA);

        let p2 = cap.next_packet().unwrap();
        assert_eq!(p2.timestamp_us, 2000);

        assert!(cap.next_packet().is_none());
        assert_eq!(cap.stats().packets_received, 2);

        cap.close();
    }
}
