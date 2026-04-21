use crate::flow::{Flow, FlowDirection};

use super::{AppProto, ParseResult, ProbeResult, ProtocolParser, StickyBuffers};

/// TLS parser — extracts SNI, JA3 fingerprint, version, cipher suites from ClientHello.
pub struct TlsParser;

// TLS record type constants
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;

// TLS extension type constants
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_ALPN: u16 = 0x0010;

impl ProtocolParser for TlsParser {
    fn name(&self) -> &str {
        "tls"
    }

    fn app_proto(&self) -> AppProto {
        AppProto::Tls
    }

    fn default_ports(&self) -> &[u16] {
        &[443, 8443, 993, 995, 465, 636]
    }

    fn probe(&self, payload: &[u8], _direction: FlowDirection) -> ProbeResult {
        if payload.len() < 5 {
            return ProbeResult::NeedMore;
        }

        // TLS record: type=0x16 (handshake), version 0x0301-0x0303
        if payload[0] == TLS_HANDSHAKE && payload[1] == 0x03 && payload[2] <= 0x03 {
            ProbeResult::Match
        } else {
            ProbeResult::NoMatch
        }
    }

    fn parse(
        &self,
        _flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        if payload.len() < 6 {
            return ParseResult::Incomplete;
        }

        // Skip TLS record header (5 bytes), check handshake type
        let handshake_type = payload[5];

        match (direction, handshake_type) {
            (FlowDirection::ToServer, TLS_CLIENT_HELLO) => {
                self.parse_client_hello(&payload[5..], buffers)
            }
            (FlowDirection::ToClient, TLS_SERVER_HELLO) => {
                self.parse_server_hello(&payload[5..], buffers)
            }
            _ => ParseResult::Ok,
        }
    }
}

impl TlsParser {
    fn parse_client_hello(&self, data: &[u8], buffers: &mut StickyBuffers) -> ParseResult {
        // Handshake header: type(1) + length(3) + client_version(2) + random(32)
        if data.len() < 38 {
            return ParseResult::Incomplete;
        }

        let mut pos = 1 + 3; // skip type + length
        let client_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2; // version

        // Store TLS version
        let version_str = match client_version {
            0x0301 => "1.0",
            0x0302 => "1.1",
            0x0303 => "1.2",
            _ => "unknown",
        };
        buffers.insert("tls.version".into(), version_str.as_bytes().to_vec());

        pos += 32; // skip random

        if pos >= data.len() {
            return ParseResult::Incomplete;
        }

        // Session ID length + skip
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        if pos + 2 > data.len() {
            return ParseResult::Incomplete;
        }

        // Cipher suites
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut ja3_ciphers = Vec::new();
        if pos + cipher_suites_len <= data.len() {
            let mut cs_pos = pos;
            while cs_pos + 2 <= pos + cipher_suites_len {
                let suite = u16::from_be_bytes([data[cs_pos], data[cs_pos + 1]]);
                // Skip GREASE values (0x?a?a pattern)
                if suite & 0x0f0f != 0x0a0a {
                    ja3_ciphers.push(suite.to_string());
                }
                cs_pos += 2;
            }
        }
        pos += cipher_suites_len;

        if pos >= data.len() {
            return ParseResult::Incomplete;
        }

        // Compression methods
        let comp_len = data[pos] as usize;
        pos += 1 + comp_len;

        // Extensions
        if pos + 2 > data.len() {
            // No extensions, compute JA3 with what we have
            let ja3_str = format!(
                "{},{},{},{},{}",
                client_version,
                ja3_ciphers.join("-"),
                "",
                "",
                ""
            );
            let ja3_hash = md5_hex(&ja3_str);
            buffers.insert("tls.ja3".into(), ja3_hash.into_bytes());
            return ParseResult::Ok;
        }

        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut ja3_extensions = Vec::new();
        let mut ja3_elliptic_curves = Vec::new();
        let mut ja3_ec_point_formats = Vec::new();
        let ext_end = (pos + extensions_len).min(data.len());

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            // Skip GREASE extension types
            if ext_type & 0x0f0f != 0x0a0a {
                ja3_extensions.push(ext_type.to_string());
            }

            if pos + ext_len > ext_end {
                break;
            }

            match ext_type {
                EXT_SERVER_NAME => {
                    // Parse SNI
                    if let Some(sni) = self.parse_sni(&data[pos..pos + ext_len]) {
                        buffers.insert("tls.sni".into(), sni.as_bytes().to_vec());
                    }
                }
                0x000a => {
                    // Supported groups / elliptic curves
                    if ext_len >= 2 {
                        let list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                        let mut i = 2;
                        while i + 2 <= 2 + list_len && pos + i + 2 <= ext_end {
                            let curve = u16::from_be_bytes([data[pos + i], data[pos + i + 1]]);
                            if curve & 0x0f0f != 0x0a0a {
                                ja3_elliptic_curves.push(curve.to_string());
                            }
                            i += 2;
                        }
                    }
                }
                0x000b => {
                    // EC point formats
                    if ext_len >= 1 {
                        let list_len = data[pos] as usize;
                        for i in 0..list_len {
                            if pos + 1 + i < ext_end {
                                ja3_ec_point_formats.push(data[pos + 1 + i].to_string());
                            }
                        }
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    // Override version with highest supported version
                    if ext_len >= 3 {
                        let list_len = data[pos] as usize;
                        let mut highest = 0u16;
                        let mut i = 1;
                        while i + 2 <= 1 + list_len && pos + i + 2 <= ext_end {
                            let v = u16::from_be_bytes([data[pos + i], data[pos + i + 1]]);
                            if v > highest && v & 0x0f0f != 0x0a0a {
                                highest = v;
                            }
                            i += 2;
                        }
                        if highest == 0x0304 {
                            buffers.insert("tls.version".into(), b"1.3".to_vec());
                        }
                    }
                }
                EXT_ALPN => {
                    if ext_len >= 2
                        && let Some(alpn) = self.parse_alpn(&data[pos..pos + ext_len])
                    {
                        buffers.insert("tls.alpn".into(), alpn.into_bytes());
                    }
                }
                _ => {}
            }

            pos += ext_len;
        }

        // Compute JA3 hash
        let ja3_str = format!(
            "{},{},{},{},{}",
            client_version,
            ja3_ciphers.join("-"),
            ja3_extensions.join("-"),
            ja3_elliptic_curves.join("-"),
            ja3_ec_point_formats.join("-"),
        );
        let ja3_hash = md5_hex(&ja3_str);
        buffers.insert("tls.ja3".into(), ja3_hash.into_bytes());
        buffers.insert("tls.ja3_string".into(), ja3_str.into_bytes());

        ParseResult::Ok
    }

    fn parse_server_hello(&self, data: &[u8], buffers: &mut StickyBuffers) -> ParseResult {
        // Minimal: type(1) + length(3) + version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1)
        if data.len() < 39 {
            return ParseResult::Incomplete;
        }

        let mut pos = 4; // skip type + length
        let server_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 34; // version + random

        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        if pos + 3 > data.len() {
            return ParseResult::Incomplete;
        }

        let cipher_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let _compression = data[pos];
        pos += 1;

        // JA3S: version,cipher,extensions
        let mut ja3s_extensions = Vec::new();

        if pos + 2 <= data.len() {
            let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = (pos + ext_len).min(data.len());

            while pos + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                if ext_type & 0x0f0f != 0x0a0a {
                    ja3s_extensions.push(ext_type.to_string());
                }
                pos += 4 + ext_data_len;
            }
        }

        let ja3s_str = format!(
            "{},{},{}",
            server_version,
            cipher_suite,
            ja3s_extensions.join("-"),
        );
        let ja3s_hash = md5_hex(&ja3s_str);
        buffers.insert("tls.ja3s".into(), ja3s_hash.into_bytes());
        buffers.insert("tls.ja3s_string".into(), ja3s_str.into_bytes());

        ParseResult::Ok
    }

    fn parse_sni(&self, data: &[u8]) -> Option<String> {
        // SNI extension: list_length(2) + type(1) + name_length(2) + name
        if data.len() < 5 {
            return None;
        }
        let _list_len = u16::from_be_bytes([data[0], data[1]]);
        let name_type = data[2];
        if name_type != 0 {
            return None;
        } // host_name type
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + name_len {
            return None;
        }
        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    }

    fn parse_alpn(&self, data: &[u8]) -> Option<String> {
        if data.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;
        let mut protocols = Vec::new();
        while pos < 2 + list_len && pos < data.len() {
            let proto_len = data[pos] as usize;
            pos += 1;
            if pos + proto_len <= data.len()
                && let Ok(s) = std::str::from_utf8(&data[pos..pos + proto_len])
            {
                protocols.push(s.to_string());
            }
            pos += proto_len;
        }
        if protocols.is_empty() {
            None
        } else {
            Some(protocols.join(","))
        }
    }
}

/// Simple MD5 hex digest (for JA3 fingerprints).
/// Implemented inline to avoid adding an md5 crate dependency.
fn md5_hex(input: &str) -> String {
    // Minimal MD5 implementation for JA3
    let digest = md5_compute(input.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal MD5 implementation (RFC 1321).
fn md5_compute(message: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let orig_len_bits = (message.len() as u64) * 8;
    let mut msg = message.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_probe_tls() {
        let parser = TlsParser;
        // TLS 1.2 ClientHello start
        let payload = &[0x16, 0x03, 0x01, 0x00, 0x05, TLS_CLIENT_HELLO];
        assert_eq!(
            parser.probe(payload, FlowDirection::ToServer),
            ProbeResult::Match
        );

        // Not TLS
        assert_eq!(
            parser.probe(b"GET /", FlowDirection::ToServer),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn test_probe_short() {
        let parser = TlsParser;
        assert_eq!(
            parser.probe(&[0x16, 0x03], FlowDirection::ToServer),
            ProbeResult::NeedMore
        );
    }
}
