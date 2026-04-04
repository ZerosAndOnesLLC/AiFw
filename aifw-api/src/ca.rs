use axum::{extract::{Path, State}, http::StatusCode, Json};
use chrono::Utc;
use rcgen::{CertificateParams, DnType, DnValue, IsCa, BasicConstraints, KeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use crate::AppState;

// ============================================================
// Types
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CaInfo {
    pub initialized: bool,
    pub subject: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertRecord {
    pub id: String,
    pub cert_type: String, // "server" | "client"
    pub common_name: String,
    pub sans: String,      // comma-separated
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub status: String,    // "active" | "revoked" | "expired"
    pub revoked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateCaRequest {
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub validity_days: Option<u32>,
    #[allow(dead_code)]
    pub key_type: Option<String>, // "ec" | "rsa2048" | "rsa4096"
}

#[derive(Debug, Deserialize)]
pub struct IssueCertRequest {
    pub cert_type: String,        // "server" | "client"
    pub common_name: String,
    pub sans: Option<Vec<String>>, // DNS names and/or IPs
    pub validity_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct IssueCertResponse {
    pub id: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub ca_certificate_pem: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============================================================
// DB Migration
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS ca_root (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cert_pem TEXT NOT NULL,
            key_pem TEXT NOT NULL,
            subject TEXT NOT NULL,
            serial TEXT NOT NULL,
            not_before TEXT NOT NULL,
            not_after TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS ca_certificates (
            id TEXT PRIMARY KEY,
            cert_type TEXT NOT NULL,
            common_name TEXT NOT NULL,
            sans TEXT NOT NULL DEFAULT '',
            serial TEXT NOT NULL,
            cert_pem TEXT NOT NULL,
            key_pem TEXT NOT NULL,
            not_before TEXT NOT NULL,
            not_after TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            revoked_at TEXT,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    Ok(())
}

// ============================================================
// Helpers
// ============================================================

fn sha256_fingerprint(pem: &str) -> String {
    let mut hasher = Sha256::new();
    // Extract DER from PEM
    let der = pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    if let Ok(bytes) = base64_decode(&der) {
        hasher.update(&bytes);
    } else {
        hasher.update(pem.as_bytes());
    }
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

// SHA-256 implementation (FIPS 180-4)
struct Sha256 { state: [u32; 8], buf: Vec<u8> }

const SHA256_K: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
            buf: Vec::new(),
        }
    }
    fn update(&mut self, data: &[u8]) { self.buf.extend_from_slice(data); }
    fn finalize(self) -> [u8; 32] {
        let bit_len = (self.buf.len() as u64) * 8;
        let mut data = self.buf;
        data.push(0x80);
        while data.len() % 64 != 56 { data.push(0); }
        data.extend_from_slice(&bit_len.to_be_bytes());

        let mut h = self.state;
        for chunk in data.chunks(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
            }
            for i in 16..64 {
                let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
                let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
                w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
                (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g; g = f; f = e; e = d.wrapping_add(t1);
                d = c; c = b; b = a; a = t1.wrapping_add(t2);
            }
            h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
        }
        let mut result = [0u8; 32];
        for i in 0..8 { result[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
        result
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' { continue; }
        let val = TABLE.iter().position(|&t| t == c).ok_or(())? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 { bits -= 8; out.push((buf >> bits) as u8); buf &= (1 << bits) - 1; }
    }
    Ok(out)
}

fn next_serial() -> String {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    let serial: u64 = u64::from_be_bytes([bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7]]);
    format!("{:X}", serial)
}

// ============================================================
// Handlers
// ============================================================

pub async fn get_ca_info(
    State(state): State<AppState>,
) -> Result<Json<CaInfo>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT subject, serial, not_before, not_after, fingerprint, algorithm FROM ca_root WHERE id = 1",
    ).fetch_optional(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some((subject, serial, not_before, not_after, fingerprint, algorithm)) => {
            Ok(Json(CaInfo { initialized: true, subject, serial, not_before, not_after, fingerprint, algorithm }))
        }
        None => {
            Ok(Json(CaInfo {
                initialized: false, subject: String::new(), serial: String::new(),
                not_before: String::new(), not_after: String::new(),
                fingerprint: String::new(), algorithm: String::new(),
            }))
        }
    }
}

pub async fn generate_ca(
    State(state): State<AppState>,
    Json(req): Json<GenerateCaRequest>,
) -> Result<(StatusCode, Json<CaInfo>), StatusCode> {
    let cn = req.common_name.as_deref().unwrap_or("AiFw Root CA");
    let org = req.organization.as_deref().unwrap_or("AiFw");
    let days = req.validity_days.unwrap_or(3650);
    let serial = next_serial();

    let key_pair = KeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.distinguished_name.push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));
    params.distinguished_name.push(DnType::OrganizationName, DnValue::Utf8String(org.to_string()));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    let cert = params.self_signed(&key_pair).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let fingerprint = sha256_fingerprint(&cert_pem);
    let now = Utc::now().to_rfc3339();
    let not_before = now.clone();
    let not_after = (Utc::now() + chrono::Duration::days(days as i64)).to_rfc3339();
    let subject = format!("CN={}, O={}", cn, org);

    // Delete old CA if exists and insert new
    let _ = sqlx::query("DELETE FROM ca_root WHERE id = 1").execute(&state.pool).await;
    sqlx::query(
        "INSERT INTO ca_root (id, cert_pem, key_pem, subject, serial, not_before, not_after, fingerprint, algorithm, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
    )
    .bind(&cert_pem).bind(&key_pem).bind(&subject).bind(&serial)
    .bind(&not_before).bind(&not_after).bind(&fingerprint).bind("ECDSA P-256").bind(&now)
    .execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(CaInfo {
        initialized: true, subject, serial, not_before, not_after, fingerprint, algorithm: "ECDSA P-256".to_string(),
    })))
}

pub async fn get_ca_cert_pem(
    State(state): State<AppState>,
) -> Result<String, StatusCode> {
    let row = sqlx::query_as::<_, (String,)>("SELECT cert_pem FROM ca_root WHERE id = 1")
        .fetch_optional(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    row.map(|r| r.0).ok_or(StatusCode::NOT_FOUND)
}

pub async fn issue_cert(
    State(state): State<AppState>,
    Json(req): Json<IssueCertRequest>,
) -> Result<(StatusCode, Json<IssueCertResponse>), StatusCode> {
    // Load CA
    let ca = sqlx::query_as::<_, (String, String)>("SELECT cert_pem, key_pem FROM ca_root WHERE id = 1")
        .fetch_optional(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?; // CA not initialized

    let ca_key = KeyPair::from_pem(&ca.1).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Rebuild CA cert params for signing
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let days = req.validity_days.unwrap_or(365);
    let serial = next_serial();
    let id = Uuid::new_v4().to_string();

    // Build SANs
    let mut san_names: Vec<String> = vec![req.common_name.clone()];
    if let Some(ref sans) = req.sans {
        san_names.extend(sans.iter().cloned());
    }
    san_names.sort();
    san_names.dedup();

    let mut san_types = Vec::new();
    for san in &san_names {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            san_types.push(rcgen::SanType::IpAddress(ip));
        } else if let Ok(dns) = san.clone().try_into() {
            san_types.push(rcgen::SanType::DnsName(dns));
        }
    }

    let cert_key = KeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.distinguished_name.push(DnType::CommonName, DnValue::Utf8String(req.common_name.clone()));
    params.subject_alt_names = san_types;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days as i64);

    match req.cert_type.as_str() {
        "server" => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        "client" => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    let cert = params.signed_by(&cert_key, &ca_cert, &ca_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let cert_pem = cert.pem();
    let key_pem = cert_key.serialize_pem();
    let now = Utc::now().to_rfc3339();
    let not_before = now.clone();
    let not_after = (Utc::now() + chrono::Duration::days(days as i64)).to_rfc3339();
    let sans_str = san_names.join(",");

    sqlx::query(
        "INSERT INTO ca_certificates (id, cert_type, common_name, sans, serial, cert_pem, key_pem, not_before, not_after, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', ?10)"
    )
    .bind(&id).bind(&req.cert_type).bind(&req.common_name).bind(&sans_str).bind(&serial)
    .bind(&cert_pem).bind(&key_pem).bind(&not_before).bind(&not_after).bind(&now)
    .execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(IssueCertResponse {
        id, certificate_pem: cert_pem, private_key_pem: key_pem, ca_certificate_pem: ca.0,
    })))
}

pub async fn list_certs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<CertRecord>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String, String, Option<String>, String)>(
        "SELECT id, cert_type, common_name, sans, serial, not_before, not_after, status, revoked_at, created_at FROM ca_certificates ORDER BY created_at DESC"
    ).fetch_all(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let certs: Vec<CertRecord> = rows.into_iter().map(|(id, ct, cn, sans, serial, nb, na, status, ra, ca)| {
        let actual_status = if status == "active" && na < Utc::now().to_rfc3339() { "expired".to_string() } else { status };
        CertRecord { id, cert_type: ct, common_name: cn, sans, serial, not_before: nb, not_after: na, status: actual_status, revoked_at: ra, created_at: ca }
    }).collect();

    Ok(Json(ApiResponse { data: certs }))
}

pub async fn get_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String, String, String, String, Option<String>, String)>(
        "SELECT id, cert_type, common_name, sans, serial, cert_pem, not_before, not_after, status, revoked_at, created_at FROM ca_certificates WHERE id = ?1"
    ).bind(&id).fetch_optional(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(serde_json::json!({
        "id": row.0, "cert_type": row.1, "common_name": row.2, "sans": row.3,
        "serial": row.4, "certificate_pem": row.5, "not_before": row.6, "not_after": row.7,
        "status": row.8, "revoked_at": row.9, "created_at": row.10,
    })))
}

pub async fn download_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<String, StatusCode> {
    let (cert_pem,) = sqlx::query_as::<_, (String,)>("SELECT cert_pem FROM ca_certificates WHERE id = ?1")
        .bind(&id).fetch_one(&state.pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(cert_pem)
}

pub async fn download_cert_key(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<String, StatusCode> {
    let (key_pem,) = sqlx::query_as::<_, (String,)>("SELECT key_pem FROM ca_certificates WHERE id = ?1")
        .bind(&id).fetch_one(&state.pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(key_pem)
}

pub async fn revoke_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query("UPDATE ca_certificates SET status = 'revoked', revoked_at = ?1 WHERE id = ?2 AND status = 'active'")
        .bind(&now).bind(&id).execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Json(MessageResponse { message: format!("Certificate {id} revoked") }))
}

pub async fn delete_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM ca_certificates WHERE id = ?1")
        .bind(&id).execute(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: format!("Certificate {id} deleted") }))
}

pub async fn get_crl(
    State(state): State<AppState>,
) -> Result<String, StatusCode> {
    // Simple text-based CRL listing revoked serials
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT serial, common_name, revoked_at FROM ca_certificates WHERE status = 'revoked' ORDER BY revoked_at DESC"
    ).fetch_all(&state.pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut crl = String::from("# AiFw Certificate Revocation List\n");
    crl.push_str(&format!("# Generated: {}\n", Utc::now().to_rfc3339()));
    crl.push_str(&format!("# Revoked certificates: {}\n\n", rows.len()));
    for (serial, cn, revoked_at) in &rows {
        crl.push_str(&format!("Serial: {} CN: {} Revoked: {}\n", serial, cn, revoked_at));
    }
    Ok(crl)
}
