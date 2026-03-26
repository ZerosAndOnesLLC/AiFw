// Re-export TOTP functions. These are duplicated from aifw-api/src/auth/totp.rs
// because aifw-setup is a standalone binary that shouldn't depend on aifw-api.
// In a future refactor, extract shared crypto into aifw-common.

use std::time::{SystemTime, UNIX_EPOCH};

const DIGITS: u32 = 6;
const PERIOD: u64 = 30;
const TOLERANCE: u64 = 1;

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    let u1 = uuid::Uuid::new_v4();
    let u2 = uuid::Uuid::new_v4();
    bytes[..16].copy_from_slice(u1.as_bytes());
    bytes[16..20].copy_from_slice(&u2.as_bytes()[..4]);
    base32_encode(&bytes)
}

pub fn provisioning_uri(secret: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits={}&period={}",
        issuer, account, secret, issuer, DIGITS, PERIOD,
    )
}

pub fn verify(secret: &str, code: &str) -> bool {
    let Ok(secret_bytes) = base32_decode(secret) else { return false };
    let Ok(code_num) = code.parse::<u32>() else { return false };
    if code.len() != DIGITS as usize { return false }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let step = now / PERIOD;

    for offset in 0..=TOLERANCE {
        if generate_code(&secret_bytes, step + offset) == code_num { return true }
        if offset > 0 && step >= offset {
            if generate_code(&secret_bytes, step - offset) == code_num { return true }
        }
    }
    false
}

pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    (0..count).map(|_| {
        let u = uuid::Uuid::new_v4();
        let b = u.as_bytes();
        format!("{:04X}-{:04X}-{:04X}", u16::from_be_bytes([b[0],b[1]]), u16::from_be_bytes([b[2],b[3]]), u16::from_be_bytes([b[4],b[5]]))
    }).collect()
}

fn generate_code(secret: &[u8], step: u64) -> u32 {
    let hash = hmac_sha1(secret, &step.to_be_bytes());
    let offset = (hash[19] & 0x0f) as usize;
    let binary = ((hash[offset] & 0x7f) as u32) << 24
        | (hash[offset+1] as u32) << 16
        | (hash[offset+2] as u32) << 8
        | (hash[offset+3] as u32);
    binary % 10u32.pow(DIGITS)
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let key_padded = if key.len() > 64 {
        let h = sha1(key); let mut p = [0u8;64]; p[..20].copy_from_slice(&h); p
    } else {
        let mut p = [0u8;64]; p[..key.len()].copy_from_slice(key); p
    };
    let mut ipad = [0x36u8;64]; let mut opad = [0x5cu8;64];
    for i in 0..64 { ipad[i] ^= key_padded[i]; opad[i] ^= key_padded[i]; }
    let mut inner = Vec::with_capacity(64+msg.len());
    inner.extend_from_slice(&ipad); inner.extend_from_slice(msg);
    let ih = sha1(&inner);
    let mut outer = Vec::with_capacity(84);
    outer.extend_from_slice(&opad); outer.extend_from_slice(&ih);
    sha1(&outer)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let (mut h0,mut h1,mut h2,mut h3,mut h4) = (0x67452301u32,0xEFCDAB89u32,0x98BADCFEu32,0x10325476u32,0xC3D2E1F0u32);
    let bl = (data.len() as u64)*8;
    let mut p = data.to_vec(); p.push(0x80);
    while p.len()%64!=56 { p.push(0); }
    p.extend_from_slice(&bl.to_be_bytes());
    for chunk in p.chunks(64) {
        let mut w=[0u32;80];
        for i in 0..16 { w[i]=u32::from_be_bytes([chunk[i*4],chunk[i*4+1],chunk[i*4+2],chunk[i*4+3]]); }
        for i in 16..80 { w[i]=(w[i-3]^w[i-8]^w[i-14]^w[i-16]).rotate_left(1); }
        let(mut a,mut b,mut c,mut d,mut e)=(h0,h1,h2,h3,h4);
        for i in 0..80 {
            let(f,k)=match i { 0..=19=>((b&c)|((!b)&d),0x5A827999u32), 20..=39=>(b^c^d,0x6ED9EBA1u32), 40..=59=>((b&c)|(b&d)|(c&d),0x8F1BBCDCu32), _=>(b^c^d,0xCA62C1D6u32) };
            let t=a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e=d;d=c;c=b.rotate_left(30);b=a;a=t;
        }
        h0=h0.wrapping_add(a);h1=h1.wrapping_add(b);h2=h2.wrapping_add(c);h3=h3.wrapping_add(d);h4=h4.wrapping_add(e);
    }
    let mut r=[0u8;20];
    r[0..4].copy_from_slice(&h0.to_be_bytes()); r[4..8].copy_from_slice(&h1.to_be_bytes());
    r[8..12].copy_from_slice(&h2.to_be_bytes()); r[12..16].copy_from_slice(&h3.to_be_bytes());
    r[16..20].copy_from_slice(&h4.to_be_bytes()); r
}

const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
fn base32_encode(data: &[u8]) -> String {
    let mut r=String::new(); let mut buf:u64=0; let mut bits=0;
    for &b in data { buf=(buf<<8)|b as u64; bits+=8; while bits>=5 { bits-=5; r.push(B32[((buf>>bits)&0x1f)as usize]as char); } }
    if bits>0 { buf<<=5-bits; r.push(B32[(buf&0x1f)as usize]as char); } r
}
fn base32_decode(s: &str) -> Result<Vec<u8>,()> {
    let s=s.trim_end_matches('=').to_uppercase();
    let mut buf:u64=0; let mut bits=0; let mut r=Vec::new();
    for c in s.chars() {
        let v = match c { 'A'..='Z' => (c as u64) - ('A' as u64), '2'..='7' => (c as u64) - ('2' as u64) + 26, _ => return Err(()) };
        buf=(buf<<5)|v; bits+=5; if bits>=8 { bits-=8; r.push((buf>>bits)as u8); }
    } Ok(r)
}
