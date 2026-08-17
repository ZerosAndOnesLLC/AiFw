use super::{CaptureBackend, CaptureConfig, CaptureStats, RawPacket};
use crate::Result;

use std::ffi::CString;
use std::os::unix::io::RawFd;

// BPF ioctl constants (FreeBSD)
const BIOCSETIF: libc::c_ulong = 0x8020426C; // _IOW('B', 108, struct ifreq)
const BIOCSBLEN: libc::c_ulong = 0xC0044266; // _IOWR('B', 102, u_int)
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270; // _IOW('B', 112, u_int)
const BIOCSETF: libc::c_ulong = 0x80104267; // _IOW('B', 103, struct bpf_program)
const BIOCGSTATS: libc::c_ulong = 0x4008426F; // _IOR('B', 111, struct bpf_stat)
const BIOCPROMISC: libc::c_ulong = 0x20004269; // _IO('B', 105)
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426D; // _IOW('B', 109, struct timeval)
const BIOCGBLEN: libc::c_ulong = 0x40044266; // _IOR('B', 102, u_int)

/// BPF packet header (prepended to each packet in the buffer), decoded
/// field-by-field from the kernel-filled bytes. `struct bpf_hdr` is
/// `{ struct timeval bh_tstamp; u_int32_t bh_caplen; u_int32_t
/// bh_datalen; u_short bh_hdrlen; }` — the timeval is two `c_long`s (16
/// bytes on 64-bit, 8 on 32-bit). Packets in the buffer are only
/// `BPF_WORDALIGN`ed (4/8 bytes), which the old pointer cast to a
/// `#[repr(C)]` struct silently relied on to also satisfy the timeval's
/// alignment; reading the fields out of the byte slice needs no
/// alignment at all and no `unsafe` (#306 / SEC-M9).
struct BpfHeader {
    bh_tstamp_sec: libc::c_long,
    bh_tstamp_usec: libc::c_long,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}

impl BpfHeader {
    /// Bytes the fixed part of the header occupies (`bh_hdrlen` in the
    /// header itself is authoritative for where the payload starts).
    const LEN: usize = 2 * std::mem::size_of::<libc::c_long>() + 4 + 4 + 2;

    /// Decode from the first [`Self::LEN`] bytes of `b` (native endian).
    /// Returns `None` if the slice is too short.
    fn parse(b: &[u8]) -> Option<Self> {
        const L: usize = std::mem::size_of::<libc::c_long>();
        if b.len() < Self::LEN {
            return None;
        }
        let long_at = |off: usize| -> libc::c_long {
            let mut buf = [0u8; L];
            buf.copy_from_slice(&b[off..off + L]);
            libc::c_long::from_ne_bytes(buf)
        };
        let u32_at = |off: usize| u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let u16_at = |off: usize| u16::from_ne_bytes([b[off], b[off + 1]]);
        Some(Self {
            bh_tstamp_sec: long_at(0),
            bh_tstamp_usec: long_at(L),
            bh_caplen: u32_at(2 * L),
            bh_datalen: u32_at(2 * L + 4),
            bh_hdrlen: u16_at(2 * L + 8),
        })
    }
}

/// ifreq struct for BIOCSETIF
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_data: [u8; 16],
}

/// timeval for BIOCSRTIMEOUT
#[repr(C)]
struct Timeval {
    tv_sec: libc::c_long,
    tv_usec: libc::c_long,
}

/// BPF stats
#[repr(C)]
struct BpfStat {
    bs_recv: libc::c_uint,
    bs_drop: libc::c_uint,
}

/// FreeBSD BPF (Berkeley Packet Filter) capture backend.
///
/// Reads packets directly from /dev/bpf — zero-copy kernel-to-userspace
/// packet capture with no shell process overhead.
pub struct BpfCapture {
    fd: RawFd,
    interface: String,
    buffer: Vec<u8>,
    buf_len: usize,
    buf_pos: usize,
    buf_read: usize,
    stats: CaptureStats,
}

impl CaptureBackend for BpfCapture {
    fn open(interface: &str, config: &CaptureConfig) -> Result<Self> {
        // Find an available /dev/bpf device
        let fd = open_bpf_device()?;

        // Set buffer size
        let mut buf_size = config.buffer_size as libc::c_uint;
        // SAFETY: `fd` is a valid bpf descriptor from open_bpf_device; both
        // ioctls read/write the single `c_uint` pointed to by `&mut buf_size`,
        // which lives on the stack for the whole block.
        unsafe {
            if libc::ioctl(fd, BIOCSBLEN, &mut buf_size) < 0 {
                // If we can't set it, read the default
                libc::ioctl(fd, BIOCGBLEN, &mut buf_size);
            }
        }

        // Bind to interface
        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            ifr_data: [0u8; 16],
        };
        let name_bytes = interface.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // SAFETY: `fd` is valid and `ifr` is a fully-initialized `Ifreq` whose
        // name field was bounded to 15 bytes above. On failure we close `fd`
        // (still valid here) before returning.
        unsafe {
            if libc::ioctl(fd, BIOCSETIF, &ifr) < 0 {
                let err = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(crate::IdsError::Capture(format!(
                    "BIOCSETIF failed for {interface}: {err}"
                )));
            }
        }

        // Enable immediate mode (don't wait for buffer to fill)
        let enable: libc::c_uint = 1;
        // SAFETY: `fd` is valid; `&enable` points to a live stack `c_uint`.
        unsafe {
            libc::ioctl(fd, BIOCIMMEDIATE, &enable);
        }

        // Enable promiscuous mode if requested
        if config.promiscuous {
            // SAFETY: `fd` is valid; BIOCPROMISC takes no argument.
            unsafe {
                libc::ioctl(fd, BIOCPROMISC);
            }
        }

        // Set read timeout
        let timeout = Timeval {
            tv_sec: 0,
            tv_usec: (config.timeout_ms as libc::c_long) * 1000,
        };
        // SAFETY: `fd` is valid; `&timeout` points to a live stack `Timeval`.
        unsafe {
            libc::ioctl(fd, BIOCSRTIMEOUT, &timeout);
        }

        // Apply BPF filter if specified (compile-time filter for performance)
        if let Some(ref _filter) = config.bpf_filter {
            // For now, accept all packets. A full BPF compiler would go here.
            // The IDS engine does its own filtering via rule matching.
            let _ = BIOCSETF; // suppress unused
        }

        let buf_len = buf_size as usize;
        tracing::info!(
            interface,
            buffer_size = buf_len,
            promiscuous = config.promiscuous,
            "BPF capture opened on /dev/bpf"
        );

        Ok(Self {
            fd,
            interface: interface.to_string(),
            buffer: vec![0u8; buf_len],
            buf_len,
            buf_pos: 0,
            buf_read: 0,
            stats: CaptureStats::default(),
        })
    }

    fn next_packet(&mut self) -> Option<RawPacket> {
        // If we've consumed all packets in the current buffer, read more
        if self.buf_pos >= self.buf_read {
            // SAFETY: `self.fd` is a valid bpf descriptor and `self.buffer` is a
            // `Vec<u8>` of `self.buf_len` bytes, so writing up to `buf_len` bytes
            // through its pointer stays in bounds.
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buf_len,
                )
            };
            if n <= 0 {
                return None; // Timeout or error
            }
            self.buf_read = n as usize;
            self.buf_pos = 0;
        }

        // Parse BPF header at current position
        let Some(hdr) = BpfHeader::parse(&self.buffer[self.buf_pos..self.buf_read]) else {
            self.buf_pos = self.buf_read; // Consumed
            return None;
        };

        let caplen = hdr.bh_caplen as usize;
        let hdrlen = hdr.bh_hdrlen as usize;
        let datalen = hdr.bh_datalen as usize;

        // Data starts after the BPF header
        let data_start = self.buf_pos + hdrlen;
        let data_end = data_start + caplen;

        if data_end > self.buf_read {
            self.buf_pos = self.buf_read;
            return None;
        }

        let timestamp_us = hdr.bh_tstamp_sec as i64 * 1_000_000 + hdr.bh_tstamp_usec as i64;

        // BPF on Ethernet interfaces includes the Ethernet header.
        // Skip the 14-byte Ethernet header to get raw IP.
        let eth_hdr_len = 14;
        let (pkt_data, orig_len) = if caplen > eth_hdr_len {
            (
                &self.buffer[data_start + eth_hdr_len..data_end],
                datalen.saturating_sub(eth_hdr_len),
            )
        } else {
            (&self.buffer[data_start..data_end], datalen)
        };

        // SmallVec inline buffer (1600 B) absorbs all sub-MTU packets with
        // zero heap allocation — the common case on a typical interface.
        let packet = RawPacket {
            timestamp_us,
            data: smallvec::SmallVec::from_slice(pkt_data),
            orig_len,
        };

        // Advance to next packet — BPF_WORDALIGN is 8 bytes on 64-bit FreeBSD
        let total = hdrlen + caplen;
        let aligned = (total + 7) & !7; // BPF_WORDALIGN (8-byte on 64-bit)
        self.buf_pos += aligned;

        self.stats.packets_received += 1;
        Some(packet)
    }

    fn stats(&self) -> CaptureStats {
        let mut stats = self.stats.clone();
        // Read kernel stats
        let mut bpf_stats = BpfStat {
            bs_recv: 0,
            bs_drop: 0,
        };
        // SAFETY: `self.fd` is valid; BIOCGSTATS writes a `struct bpf_stat`
        // into the live stack `bpf_stats`.
        unsafe {
            if libc::ioctl(self.fd, BIOCGSTATS, &mut bpf_stats) == 0 {
                stats.packets_received = bpf_stats.bs_recv as u64;
                stats.packets_dropped = bpf_stats.bs_drop as u64;
            }
        }
        stats
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            // SAFETY: `self.fd` is a valid, open descriptor (guarded by >= 0)
            // that we own; it is set to -1 immediately after so we never
            // double-close.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
            tracing::info!(interface = %self.interface, "BPF capture closed");
        }
    }
}

impl Drop for BpfCapture {
    fn drop(&mut self) {
        self.close();
    }
}

/// Open an available /dev/bpf device (tries bpf0..bpf255)
fn open_bpf_device() -> Result<RawFd> {
    for i in 0..256 {
        let path =
            CString::new(format!("/dev/bpf{i}")).expect("/dev/bpf{i} format has no interior null");
        // SAFETY: `path` is a valid nul-terminated C string that outlives the
        // call; `open` merely reads it and returns a new descriptor or -1.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        if fd >= 0 {
            return Ok(fd);
        }
    }
    Err(crate::IdsError::Capture(
        "no available /dev/bpf device (tried bpf0..bpf255)".to_string(),
    ))
}

#[cfg(test)]
mod header_tests {
    use super::BpfHeader;

    #[test]
    fn parses_fields_from_unaligned_bytes() {
        const L: usize = std::mem::size_of::<libc::c_long>();
        let mut raw = vec![0xAAu8]; // one leading byte → misaligned start
        raw.extend_from_slice(&(1_700_000_000 as libc::c_long).to_ne_bytes());
        raw.extend_from_slice(&(123_456 as libc::c_long).to_ne_bytes());
        raw.extend_from_slice(&64u32.to_ne_bytes());
        raw.extend_from_slice(&1500u32.to_ne_bytes());
        raw.extend_from_slice(&((2 * L + 10 + 6) as u16).to_ne_bytes());
        raw.extend_from_slice(&[0u8; 8]);
        let hdr = BpfHeader::parse(&raw[1..]).expect("enough bytes");
        assert_eq!(hdr.bh_tstamp_sec, 1_700_000_000);
        assert_eq!(hdr.bh_tstamp_usec, 123_456);
        assert_eq!(hdr.bh_caplen, 64);
        assert_eq!(hdr.bh_datalen, 1500);
        assert_eq!(hdr.bh_hdrlen as usize, 2 * L + 16);
        assert!(BpfHeader::parse(&raw[1..BpfHeader::LEN]).is_some());
        assert!(BpfHeader::parse(&raw[1..BpfHeader::LEN - 1]).is_none());
    }
}
