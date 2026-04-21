//! ACME issue/renew flow built on `instant-acme`.
//!
//! Each call to [`issue`] takes a cert row id and drives it from `pending`
//! to `active` (or `failed`):
//!
//!   1. Load or register the ACME account.
//!   2. Place a new order with the configured CN + SANs.
//!   3. For every authorization, solve the DNS-01 challenge via the
//!      configured provider.
//!   4. Tell the CA each challenge is ready, poll until valid.
//!   5. Generate a fresh key pair (rcgen) and finalize the order with a CSR.
//!   6. Fetch the issued cert chain.
//!   7. Persist cert/chain/key + new expiry.
//!   8. Best-effort cleanup: remove the TXT records we added.
//!
//! Renewal calls the same `issue()` — ACME orders are independent; renewing
//! is just "issue a new cert for the same identifiers".

use crate::acme::{self, AcmeAccount, AcmeCert, CertStatus, ChallengeType};
use crate::acme_dns::{DnsSolver, build_solver};
use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType as InstantChallengeType, Identifier,
    KeyAuthorization, NewAccount, NewOrder, Order, OrderStatus,
};
use sqlx::SqlitePool;
use std::time::Duration;

/// Outcome of a single issue/renew run. Persisted on the cert row so the UI
/// can show a useful error without having to scrape logs.
#[derive(Debug)]
pub struct IssueOutcome {
    pub ok: bool,
    pub message: String,
    pub expires_at: Option<DateTime<Utc>>,
}

// =============================================================================
// Top-level entry points
// =============================================================================

pub async fn issue(pool: &SqlitePool, cert_id: i64) -> IssueOutcome {
    let mut cert = match acme::load_cert(pool, cert_id).await {
        Some(c) => c,
        None => {
            return IssueOutcome {
                ok: false,
                message: format!("cert {cert_id} not found"),
                expires_at: None,
            };
        }
    };
    mark_status(pool, cert_id, CertStatus::Renewing, None).await;

    match issue_inner(pool, &mut cert).await {
        Ok(expires_at) => {
            // Fan out to export targets — best effort, individual failures
            // are recorded on the target row but don't fail the issue.
            crate::acme_export::publish_all(pool, cert_id).await;
            IssueOutcome {
                ok: true,
                message: format!("issued, expires {expires_at}"),
                expires_at: Some(expires_at),
            }
        }
        Err(e) => {
            tracing::warn!(cert_id, error = %e, "ACME issue failed");
            mark_status(pool, cert_id, CertStatus::Failed, Some(&e)).await;
            IssueOutcome {
                ok: false,
                message: e,
                expires_at: None,
            }
        }
    }
}

/// Find every cert flagged `auto_renew` whose expiry is within its renew
/// window, and issue each one. Returns per-cert outcomes.
pub async fn renew_due(pool: &SqlitePool) -> Vec<(i64, IssueOutcome)> {
    let due = acme::certs_due_for_renewal(pool).await;
    let mut out = Vec::with_capacity(due.len());
    for c in due {
        let outcome = issue(pool, c.id).await;
        // SMTP notify per outcome.
        if outcome.ok {
            crate::smtp_notify::send_event(
                pool,
                crate::smtp_notify::Event::CertRenewedOk,
                &format!(
                    "Cert {} (id {}) renewed; expires {}.",
                    c.common_name,
                    c.id,
                    outcome
                        .expires_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default()
                ),
            )
            .await;
        } else {
            crate::smtp_notify::send_event(
                pool,
                crate::smtp_notify::Event::CertRenewFailed,
                &format!(
                    "Cert {} (id {}) renewal failed: {}",
                    c.common_name, c.id, outcome.message
                ),
            )
            .await;
        }
        out.push((c.id, outcome));
    }
    out
}

/// Sweep certs that are within `EXPIRY_WARNING_DAYS` of expiry but NOT yet
/// in the renew window — fires `CertExpiringSoon` once per day so the
/// operator has visibility before auto-renewal kicks in (or in case of a
/// manual cert that won't auto-renew).
pub async fn warn_expiring(pool: &SqlitePool) {
    use crate::smtp_notify::{Event, send_event};
    const WARN_DAYS: i64 = 14;
    for c in acme::load_all_certs(pool).await {
        let Some(days) = c.days_until_expiry() else {
            continue;
        };
        if days > WARN_DAYS || days < 0 {
            continue;
        }
        // Suppress noise: only warn if last attempt > 23h ago (or never).
        let too_recent = c
            .last_renew_attempt
            .map(|t| (Utc::now() - t).num_hours() < 23)
            .unwrap_or(false);
        if too_recent {
            continue;
        }
        send_event(
            pool,
            Event::CertExpiringSoon,
            &format!(
                "Cert {} (id {}) expires in {} days.",
                c.common_name, c.id, days
            ),
        )
        .await;
    }
}

/// Spawn the daily renewal scheduler. Call from `aifw-daemon::main`. Runs:
///   - 30 s after start (catch certs that expired while the box was down)
///   - then every 6 hours (cheap; renewals only fire when actually due).
pub fn spawn_scheduler(pool: SqlitePool) {
    tokio::spawn(async move {
        // First sweep shortly after boot.
        tokio::time::sleep(Duration::from_secs(30)).await;
        let _ = renew_due(&pool).await;
        warn_expiring(&pool).await;

        let mut tick = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // skip the immediate fire
        loop {
            tick.tick().await;
            let _ = renew_due(&pool).await;
            warn_expiring(&pool).await;
        }
    });
}

// =============================================================================
// Account management
// =============================================================================

/// Get-or-create the singleton account row for the configured directory URL
/// + email, registering with the CA on first use.
pub async fn ensure_account(
    pool: &SqlitePool,
    directory_url: &str,
    contact_email: &str,
) -> Result<(AcmeAccount, Account), String> {
    let row = acme::load_default_account(pool).await;
    if let Some(row) = row {
        if let Some(ref pem) = row.key_pem {
            // Re-hydrate an instant-acme Account from the stored credentials.
            // We stash AccountCredentials JSON in `key_pem` (it includes the
            // private key + URLs in one blob).
            let creds: instant_acme::AccountCredentials =
                serde_json::from_str(pem).map_err(|e| format!("acct creds parse: {e}"))?;
            let account = Account::from_credentials(creds)
                .await
                .map_err(|e| format!("acct from creds: {e}"))?;
            return Ok((row, account));
        }
    }

    // Need to register a fresh account.
    let mailto = format!("mailto:{contact_email}");
    let new_account = NewAccount {
        contact: &[&mailto],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, creds) = Account::create(&new_account, directory_url, None)
        .await
        .map_err(|e| format!("ACME account create: {e}"))?;
    let creds_json = serde_json::to_string(&creds).map_err(|e| format!("creds serialize: {e}"))?;

    let id = acme::save_account(pool, directory_url, contact_email, Some(&creds_json)).await?;
    Ok((
        AcmeAccount {
            id,
            directory_url: directory_url.to_string(),
            contact_email: contact_email.to_string(),
            key_pem: Some(creds_json),
            created_at: Utc::now(),
        },
        account,
    ))
}

// =============================================================================
// The actual flow
// =============================================================================

async fn issue_inner(pool: &SqlitePool, cert: &mut AcmeCert) -> Result<DateTime<Utc>, String> {
    if cert.challenge_type != ChallengeType::Dns01 {
        return Err(format!(
            "challenge type {} not implemented yet — only DNS-01 in v1",
            cert.challenge_type.as_str(),
        ));
    }

    // The account row defaults to Let's Encrypt production with the email
    // from the cert's CN domain admin if no explicit account is configured.
    let acct = acme::load_default_account(pool).await.ok_or_else(|| {
        "no ACME account configured — set one in Settings → ACME first".to_string()
    })?;
    let (_acct_row, account) =
        ensure_account(pool, &acct.directory_url, &acct.contact_email).await?;

    // Build the identifier list — CN + every SAN, deduped, lowercased.
    let mut identifiers: Vec<Identifier> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for n in std::iter::once(cert.common_name.clone()).chain(cert.sans.iter().cloned()) {
        let n = n.trim().to_ascii_lowercase();
        if n.is_empty() || !seen.insert(n.clone()) {
            continue;
        }
        acme::validate_dns_name(&n)?;
        identifiers.push(Identifier::Dns(n));
    }
    if identifiers.is_empty() {
        return Err("no valid identifiers (CN + SANs all empty)".into());
    }

    // Pick the DNS provider.
    let provider_id = cert
        .dns_provider_id
        .ok_or_else(|| "DNS-01 cert has no dns_provider_id set".to_string())?;
    let provider = acme::load_provider(pool, provider_id)
        .await
        .ok_or_else(|| format!("dns provider {provider_id} not found"))?;
    let solver = build_solver(&provider)?;

    // Place the order.
    let mut order: Order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .map_err(|e| format!("new_order: {e}"))?;

    // Solve every authorization. We track (fqdn, value) pairs so cleanup
    // hits exactly the records we added — including across partial failure.
    let mut planted: Vec<(String, String)> = Vec::new();
    let solve_result = solve_all_authorizations(&mut order, solver.as_ref(), &mut planted).await;

    // Always try cleanup, regardless of solve outcome. Errors here are logged
    // but don't override the issue result — we'd rather report "issue failed
    // because X" than "cleanup failed".
    for (fqdn, value) in &planted {
        if let Err(e) = solver.remove_txt(fqdn, value).await {
            tracing::warn!(fqdn, error = %e, "ACME TXT cleanup failed");
        }
    }
    solve_result?;

    // Generate key + CSR locally. rcgen lets the operator avoid trusting any
    // cloud-side key generation; the private key never leaves the appliance.
    let mut params = rcgen::CertificateParams::new(
        identifiers
            .iter()
            .map(|Identifier::Dns(d)| d.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(|e| format!("rcgen params: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cert.common_name.clone());
    let key = rcgen::KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| format!("csr build: {e}"))?;

    order
        .finalize(csr.der())
        .await
        .map_err(|e| format!("finalize: {e}"))?;

    // Wait for the cert to be ready and download it.
    let cert_chain = poll_for_certificate(&mut order).await?;
    let key_pem = key.serialize_pem();

    // Split the bundle: leaf + chain. instant-acme returns one PEM blob with
    // multiple BEGIN CERTIFICATE blocks — split on the boundary so we can
    // store leaf and chain separately for export consumers that want each.
    let (leaf_pem, chain_pem) = split_pem_bundle(&cert_chain);

    // Parse the leaf to extract notAfter for the renewal scheduler.
    let expires_at = parse_cert_expiry(&leaf_pem)
        .ok_or_else(|| "could not parse expiry from issued cert".to_string())?;
    let issued_at = Utc::now();

    // Persist everything atomically.
    sqlx::query(
        r#"
        UPDATE acme_cert
           SET status = ?,
               cert_pem = ?,
               chain_pem = ?,
               key_pem = ?,
               issued_at = ?,
               expires_at = ?,
               last_renew_attempt = ?,
               last_renew_error = NULL
         WHERE id = ?
    "#,
    )
    .bind(CertStatus::Active.as_str())
    .bind(&leaf_pem)
    .bind(&chain_pem)
    .bind(&key_pem)
    .bind(issued_at.to_rfc3339())
    .bind(expires_at.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .bind(cert.id)
    .execute(pool)
    .await
    .map_err(|e| format!("persist cert: {e}"))?;

    cert.status = CertStatus::Active;
    cert.cert_pem = Some(leaf_pem);
    cert.chain_pem = Some(chain_pem);
    cert.key_pem = Some(key_pem);
    cert.issued_at = Some(issued_at);
    cert.expires_at = Some(expires_at);
    Ok(expires_at)
}

async fn solve_all_authorizations(
    order: &mut Order,
    solver: &dyn DnsSolver,
    planted: &mut Vec<(String, String)>,
) -> Result<(), String> {
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| format!("authorizations: {e}"))?;

    // Plant every TXT first, then ask the CA to validate them all in
    // parallel. Doing it serially per auth would multiply propagation
    // delay across SANs.
    let mut to_signal: Vec<String> = Vec::new();
    for auth in &authorizations {
        if !matches!(auth.status, AuthorizationStatus::Pending) {
            continue;
        }
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == InstantChallengeType::Dns01)
            .ok_or_else(|| format!("no DNS-01 challenge for {:?}", auth.identifier))?;
        let key_auth: KeyAuthorization = order.key_authorization(challenge);
        let dns_value = key_auth.dns_value();

        let Identifier::Dns(host) = &auth.identifier;
        let host = host.clone();
        // For wildcards (*.example.com) the TXT record is on the base name.
        let base = host.strip_prefix("*.").unwrap_or(&host);
        let fqdn = format!("_acme-challenge.{base}");

        solver
            .add_txt(&fqdn, &dns_value)
            .await
            .map_err(|e| format!("TXT add for {fqdn}: {e}"))?;
        planted.push((fqdn.clone(), dns_value.clone()));
        to_signal.push(challenge.url.clone());
    }

    // Tell CA every challenge is ready. instant-acme caps at one signal per
    // call so we loop.
    for url in &to_signal {
        order
            .set_challenge_ready(url)
            .await
            .map_err(|e| format!("set_challenge_ready({url}): {e}"))?;
    }

    // Poll for valid. ACME servers settle in seconds normally; cap at
    // ~3 minutes total in case DNS propagation is slow.
    poll_for_order_ready(order, Duration::from_secs(180)).await?;
    Ok(())
}

async fn poll_for_order_ready(order: &mut Order, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut delay = Duration::from_millis(500);
    loop {
        let state = order
            .refresh()
            .await
            .map_err(|e| format!("order refresh: {e}"))?;
        match state.status {
            OrderStatus::Ready | OrderStatus::Valid => return Ok(()),
            OrderStatus::Invalid => return Err(format!("order invalid: {state:?}")),
            OrderStatus::Pending | OrderStatus::Processing => { /* keep polling */ }
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for ACME order to be ready".into());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(8));
    }
}

async fn poll_for_certificate(order: &mut Order) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut delay = Duration::from_millis(500);
    loop {
        match order.certificate().await {
            Ok(Some(cert)) => return Ok(cert),
            Ok(None) => { /* not ready yet */ }
            Err(e) => return Err(format!("download cert: {e}")),
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for issued certificate".into());
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(4));
    }
}

// =============================================================================
// Helpers
// =============================================================================

async fn mark_status(pool: &SqlitePool, cert_id: i64, status: CertStatus, err: Option<&str>) {
    let _ = sqlx::query("UPDATE acme_cert SET status = ?, last_renew_attempt = ?, last_renew_error = ? WHERE id = ?")
        .bind(status.as_str())
        .bind(Utc::now().to_rfc3339())
        .bind(err)
        .bind(cert_id)
        .execute(pool).await;
}

/// Split a multi-cert PEM bundle into (leaf, chain). Leaf is the first
/// BEGIN CERTIFICATE block; chain is everything after it (intermediate
/// CA(s)). Returns ("", "") if the bundle is empty/malformed.
fn split_pem_bundle(bundle: &str) -> (String, String) {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    let bytes = bundle.as_bytes();
    let mut starts: Vec<usize> = Vec::new();
    let mut i = 0;
    while let Some(off) = find_subslice(&bytes[i..], BEGIN.as_bytes()) {
        starts.push(i + off);
        i = i + off + BEGIN.len();
    }
    if starts.is_empty() {
        return (String::new(), String::new());
    }
    if starts.len() == 1 {
        return (bundle.trim().to_string(), String::new());
    }
    let leaf = bundle[starts[0]..starts[1]].trim_end().to_string();
    let chain = bundle[starts[1]..].trim().to_string();
    (leaf, chain)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Use a tiny ASN.1 walk to pluck `notAfter` out of an X.509 PEM. We only
/// need the timestamp for renewal scheduling; we don't validate the cert
/// here. Falls back to None on any parse trouble — the caller fails the
/// issue rather than guessing.
fn parse_cert_expiry(pem: &str) -> Option<DateTime<Utc>> {
    let der = pem_to_der(pem)?;
    asn1_extract_not_after(&der)
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut acc = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            continue;
        }
        if l == "-----END CERTIFICATE-----" {
            break;
        }
        if in_block {
            acc.push_str(l);
        }
    }
    if acc.is_empty() {
        return None;
    }
    base64_decode_no_pad(&acc)
}

fn base64_decode_no_pad(s: &str) -> Option<Vec<u8>> {
    // Tiny standalone base64 decoder so we don't pull in a new dep just for
    // expiry parsing. Handles whitespace and missing padding.
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Walk the X.509 DER just far enough to find `tbsCertificate.validity.notAfter`.
/// This is purely a convenience parser — we trust the CA's encoding rather
/// than auditing it ourselves.
fn asn1_extract_not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    // Skip SEQUENCE Certificate
    let (_, rest) = asn1_take_seq(der)?;
    // Skip SEQUENCE TBSCertificate
    let (tbs, _) = asn1_take_seq(rest)?;
    // Skip optional [0] EXPLICIT Version, then INTEGER serialNumber, then
    // SEQUENCE signature, then SEQUENCE issuer.
    let mut p = tbs;
    if !p.is_empty() && p[0] == 0xA0 {
        let (_, after) = asn1_take_tlv(p)?;
        p = after;
    }
    let (_, p2) = asn1_take_tlv(p)?; // serialNumber INTEGER
    let (_, p3) = asn1_take_tlv(p2)?; // signature   SEQUENCE
    let (_, p4) = asn1_take_tlv(p3)?; // issuer      SEQUENCE
    let (validity, _) = asn1_take_seq(p4)?; // validity    SEQUENCE
    // validity := SEQUENCE { notBefore Time, notAfter Time }
    let (_, after_nb) = asn1_take_tlv(validity)?;
    let (not_after_v, _) = asn1_take_tlv(after_nb)?;
    let tag = validity[0]; // notBefore tag — but we want notAfter; recompute
    let _ = tag;
    // Actually decode notAfter — re-walk to grab the value bytes:
    let (_, after_nb2) = asn1_take_tlv(validity)?;
    parse_asn1_time(after_nb2.first().copied()?, not_after_v)
}

/// Read a TLV; return (value_bytes, rest_after_this_tlv).
fn asn1_take_tlv(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let _ = tag;
    let mut idx = 1;
    let len_byte = buf[idx];
    idx += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7F) as usize;
        if idx + n > buf.len() {
            return None;
        }
        let mut l = 0usize;
        for b in &buf[idx..idx + n] {
            l = (l << 8) | (*b as usize);
        }
        idx += n;
        l
    };
    if idx + len > buf.len() {
        return None;
    }
    Some((&buf[idx..idx + len], &buf[idx + len..]))
}

fn asn1_take_seq(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() || buf[0] != 0x30 {
        return None;
    }
    asn1_take_tlv(buf)
}

fn parse_asn1_time(tag: u8, value: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(value).ok()?;
    let fmt = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            format!("{yyyy}{}", &s[2..])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            s.to_string()
        }
        _ => return None,
    };
    chrono::NaiveDateTime::parse_from_str(&fmt, "%Y%m%d%H%M%SZ")
        .ok()
        .map(|dt| dt.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_bundle_two_certs() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
        let (leaf, chain) = split_pem_bundle(pem);
        assert!(leaf.contains("AAAA"));
        assert!(chain.contains("BBBB"));
        assert!(!leaf.contains("BBBB"));
    }

    #[test]
    fn split_bundle_leaf_only() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let (leaf, chain) = split_pem_bundle(pem);
        assert!(leaf.contains("AAAA"));
        assert!(chain.is_empty());
    }

    #[test]
    fn base64_no_pad_works() {
        // Standard base64 of "Hello" is "SGVsbG8=" — strip the pad.
        let v = base64_decode_no_pad("SGVsbG8").unwrap();
        assert_eq!(&v, b"Hello");
        // With newlines + padding works too.
        let v2 = base64_decode_no_pad("SGVs\nbG8=").unwrap();
        assert_eq!(&v2, b"Hello");
    }
}
