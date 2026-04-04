use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// TOTP parameters (RFC 6238)
const DIGITS: u32 = 6;
const PERIOD: u64 = 30;
const TOLERANCE: u64 = 1; // ±1 time step

/// Generate a random TOTP secret (20 bytes = 160 bits, base32 encoded)
pub fn generate_secret() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// Generate a provisioning URI for QR code generation
/// Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30
pub fn provisioning_uri(secret: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}",
        url_encode(issuer),
        url_encode(account),
        secret,
        url_encode(issuer),
        DIGITS,
        PERIOD,
    )
}

/// Verify a TOTP code against a secret, with ±1 time step tolerance
pub fn verify(secret: &str, code: &str) -> bool {
    let Ok(secret_bytes) = base32_decode(secret) else {
        return false;
    };

    let Ok(code_num) = code.parse::<u32>() else {
        return false;
    };

    if code.len() != DIGITS as usize {
        return false;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let current_step = now / PERIOD;

    // Check current step ± tolerance
    for offset in 0..=TOLERANCE {
        if generate_code_at_step(&secret_bytes, current_step + offset) == code_num {
            return true;
        }
        if offset > 0 && current_step >= offset {
            if generate_code_at_step(&secret_bytes, current_step - offset) == code_num {
                return true;
            }
        }
    }

    false
}

/// Generate the current TOTP code for a secret (for testing)
#[cfg(test)]
pub fn generate_current(secret: &str) -> Option<String> {
    let secret_bytes = base32_decode(secret).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let step = now / PERIOD;
    let code = generate_code_at_step(&secret_bytes, step);
    Some(format!("{:06}", code))
}

/// Generate a TOTP code for a specific time step
fn generate_code_at_step(secret: &[u8], step: u64) -> u32 {
    let msg = step.to_be_bytes();
    let hash = hmac_sha1(secret, &msg);

    // Dynamic truncation (RFC 4226)
    let offset = (hash[19] & 0x0f) as usize;
    let binary = ((hash[offset] & 0x7f) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32);

    binary % 10u32.pow(DIGITS)
}

// ============================================================
// Recovery codes
// ============================================================

/// Generate a set of one-time recovery codes
pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let u = uuid::Uuid::new_v4();
            let bytes = u.as_bytes();
            // Format as XXXX-XXXX-XXXX (alphanumeric)
            format!(
                "{:04X}-{:04X}-{:04X}",
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
            )
        })
        .collect()
}

// ============================================================
// HMAC-SHA1 (pure Rust, no external crate)
// ============================================================

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let block_size = 64;

    let key_padded = if key.len() > block_size {
        let h = sha1(key);
        let mut padded = [0u8; 64];
        padded[..20].copy_from_slice(&h);
        padded
    } else {
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_padded[i];
        opad[i] ^= key_padded[i];
    }

    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// ============================================================
// Base32 encoding/decoding (RFC 4648)
// ============================================================

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        buffer <<= 5 - bits;
        result.push(BASE32_ALPHABET[(buffer & 0x1f) as usize] as char);
    }

    result
}

fn base32_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let encoded = encoded.trim_end_matches('=').to_uppercase();
    let mut buffer: u64 = 0;
    let mut bits = 0;
    let mut result = Vec::new();

    for ch in encoded.chars() {
        let val = match ch {
            'A'..='Z' => ch as u64 - 'A' as u64,
            '2'..='7' => ch as u64 - '2' as u64 + 26,
            _ => return Err(format!("invalid base32 character: {ch}")),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Ok(result)
}

fn url_encode(s: &str) -> String {
    s.replace(' ', "%20").replace(':', "%3A").replace('@', "%40")
}

// ============================================================
// Request/Response types
// ============================================================

#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpLoginRequest {
    pub username: String,
    pub password: String,
    pub totp_code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpDisableRequest {
    pub code: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let s1 = generate_secret();
        let s2 = generate_secret();
        assert!(!s1.is_empty());
        assert_ne!(s1, s2);
        // Should be valid base32
        assert!(base32_decode(&s1).is_ok());
    }

    #[test]
    fn test_provisioning_uri() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "admin", "AiFw");
        assert!(uri.starts_with("otpauth://totp/AiFw:admin?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn test_generate_and_verify() {
        let secret = generate_secret();
        let code = generate_current(&secret).unwrap();
        assert_eq!(code.len(), 6);
        assert!(verify(&secret, &code));
    }

    #[test]
    fn test_verify_wrong_code() {
        let secret = generate_secret();
        assert!(!verify(&secret, "000000"));
    }

    #[test]
    fn test_verify_bad_format() {
        let secret = generate_secret();
        assert!(!verify(&secret, "12345"));    // too short
        assert!(!verify(&secret, "1234567"));  // too long
        assert!(!verify(&secret, "abcdef"));   // not numeric
    }

    #[test]
    fn test_verify_bad_secret() {
        assert!(!verify("!!invalid!!", "123456"));
    }

    #[test]
    fn test_recovery_codes() {
        let codes = generate_recovery_codes(8);
        assert_eq!(codes.len(), 8);
        // All unique
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 8);
        // Format: XXXX-XXXX-XXXX
        for code in &codes {
            assert_eq!(code.len(), 14);
            assert_eq!(&code[4..5], "-");
            assert_eq!(&code[9..10], "-");
        }
    }

    #[test]
    fn test_base32_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_known_base32() {
        // RFC 4648 test vectors
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn test_hmac_sha1_known_vector() {
        // RFC 2202 test case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha1(&key, data);
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "b617318655057264e28bc0b6fb378c8ef146be00");
    }
}
