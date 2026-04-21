//! DNS-01 challenge solvers.
//!
//! Each provider implements [`DnsSolver`]. The ACME engine calls
//! `add_txt(...)` before telling the CA the challenge is ready, then
//! `remove_txt(...)` after the cert is issued (success or failure).
//!
//! Adding a new provider:
//!  1. Add a variant to [`acme::DnsProviderKind`].
//!  2. Add a struct here that implements [`DnsSolver`].
//!  3. Add a match arm in [`build_solver`].
//!  4. Wire UI form fields for any provider-specific config in `extra`.

use crate::acme::{AcmeDnsProvider, DnsProviderKind};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

/// Maximum time we'll spend polling for a TXT record to become visible
/// after adding it. Some providers propagate in seconds; some take a few
/// minutes. Anything slower will fail the ACME challenge for unrelated
/// reasons (the order has its own deadline) so 5 minutes is the cap.
pub const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(300);

#[async_trait]
pub trait DnsSolver: Send + Sync {
    /// Publish a TXT record `_acme-challenge.<host> = <value>`. Returns once
    /// the record is at least *posted* with the provider; propagation is the
    /// engine's job to poll for.
    async fn add_txt(&self, fqdn: &str, value: &str) -> Result<(), String>;

    /// Best-effort cleanup. Errors are logged but never fail the issue flow.
    async fn remove_txt(&self, fqdn: &str, value: &str) -> Result<(), String>;
}

/// A/AAAA upsert API used by the DDNS subsystem. Same provider rows that
/// solve DNS-01 challenges are reused here — Cloudflare API tokens with
/// `Zone:DNS:Edit` and Route53 IAM keys with
/// `route53:ChangeResourceRecordSets` already grant both.
#[async_trait]
pub trait DnsRecordWriter: Send + Sync {
    async fn upsert_a(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String>;
    async fn upsert_aaaa(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String>;
}

/// Build a concrete solver for a configured provider row.
pub fn build_solver(p: &AcmeDnsProvider) -> Result<Box<dyn DnsSolver>, String> {
    match p.kind {
        DnsProviderKind::Cloudflare => Ok(Box::new(Cloudflare::new(p)?)),
        DnsProviderKind::Route53 => Ok(Box::new(Route53::new(p)?)),
        DnsProviderKind::Manual => Ok(Box::new(Manual {
            name: p.name.clone(),
        })),
        // DigitalOcean and rfc2136 are stubbed for v1 — return a clear
        // error rather than silently accepting and timing out at the CA.
        DnsProviderKind::DigitalOcean => Err("DigitalOcean DNS-01 not implemented yet".into()),
        DnsProviderKind::Rfc2136 => Err("rfc2136 DNS-01 not implemented yet".into()),
    }
}

/// Companion factory: build a DDNS-capable A/AAAA writer for the same
/// provider row. Manual is intentionally unsupported here — a manual
/// provider can't push A records on a 5-minute schedule by definition.
pub fn build_record_writer(p: &AcmeDnsProvider) -> Result<Box<dyn DnsRecordWriter>, String> {
    match p.kind {
        DnsProviderKind::Cloudflare => Ok(Box::new(Cloudflare::new(p)?)),
        DnsProviderKind::Route53 => Ok(Box::new(Route53::new(p)?)),
        DnsProviderKind::Manual => {
            Err("manual provider can't auto-update A/AAAA — pick Cloudflare or Route53".into())
        }
        DnsProviderKind::DigitalOcean => Err("DigitalOcean DDNS not implemented yet".into()),
        DnsProviderKind::Rfc2136 => Err("rfc2136 DDNS not implemented yet".into()),
    }
}

// =============================================================================
// Cloudflare — REST API with a scoped API token (Zone:DNS:Edit)
// =============================================================================

pub struct Cloudflare {
    token: String,
    /// Cloudflare zone ID. Either supplied in `extra.zone_id` or resolved
    /// from the configured `zone` name on first use.
    zone_id: tokio::sync::OnceCell<String>,
    zone_name: String,
}

impl Cloudflare {
    fn new(p: &AcmeDnsProvider) -> Result<Self, String> {
        let token = p
            .api_token
            .clone()
            .ok_or_else(|| "Cloudflare provider missing API token".to_string())?;
        let zone_id = tokio::sync::OnceCell::new();
        if let Some(z) = p.extra.get("zone_id").and_then(|v| v.as_str()) {
            // Fine to ignore the result — OnceCell::set_blocking isn't needed here.
            let _ = zone_id.set(z.to_string());
        }
        Ok(Self {
            token,
            zone_id,
            zone_name: p.zone.clone(),
        })
    }

    async fn client(&self) -> reqwest::Client {
        // Per-call client — keeps the dep tree small, avoids global state.
        // The TXT add/remove pair runs at most a few times per cert so the
        // small per-call overhead is fine.
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest builder")
    }

    async fn resolve_zone_id(&self) -> Result<String, String> {
        if let Some(z) = self.zone_id.get() {
            return Ok(z.clone());
        }
        let c = self.client().await;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            self.zone_name
        );
        #[derive(serde::Deserialize)]
        struct Resp {
            result: Vec<Zone>,
            success: bool,
        }
        #[derive(serde::Deserialize)]
        struct Zone {
            id: String,
        }
        let resp: Resp = c
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("cf zone list: {e}"))?
            .error_for_status()
            .map_err(|e| format!("cf zone list status: {e}"))?
            .json()
            .await
            .map_err(|e| format!("cf zone list parse: {e}"))?;
        if !resp.success || resp.result.is_empty() {
            return Err(format!(
                "Cloudflare returned no zone matching '{}'",
                self.zone_name
            ));
        }
        let id = resp.result.into_iter().next().unwrap().id;
        let _ = self.zone_id.set(id.clone());
        Ok(id)
    }

    async fn find_record_id(&self, zone_id: &str, fqdn: &str, value: &str) -> Option<String> {
        let c = self.client().await;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=TXT&name={fqdn}&content=%22{}%22",
            urlencoding(value),
        );
        #[derive(serde::Deserialize)]
        struct Resp {
            result: Vec<Rec>,
        }
        #[derive(serde::Deserialize)]
        struct Rec {
            id: String,
        }
        let resp: Resp = c
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        resp.result.into_iter().next().map(|r| r.id)
    }
}

#[async_trait]
impl DnsSolver for Cloudflare {
    async fn add_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        let c = self.client().await;
        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
        let body = serde_json::json!({
            "type": "TXT",
            "name": fqdn,
            "content": value,
            "ttl": 60,
        });
        let resp = c
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("cf TXT create: {e}"))?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(format!("cf TXT create non-2xx: {txt}"));
        }
        Ok(())
    }

    async fn remove_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        let Some(rec_id) = self.find_record_id(&zone_id, fqdn, value).await else {
            // Already gone — that's fine.
            return Ok(());
        };
        let c = self.client().await;
        let url =
            format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rec_id}");
        let resp = c
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("cf TXT delete: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("cf TXT delete non-2xx: {}", resp.status()));
        }
        Ok(())
    }
}

impl Cloudflare {
    /// Look up the existing record id (if any) for a given (type, name).
    /// Used by upsert_a/aaaa to decide between POST (create) and PUT (update)
    /// since Cloudflare doesn't have a one-shot upsert.
    async fn find_record_id_typed(&self, zone_id: &str, fqdn: &str, rtype: &str) -> Option<String> {
        let c = self.client().await;
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={rtype}&name={fqdn}",
        );
        #[derive(serde::Deserialize)]
        struct Resp {
            result: Vec<Rec>,
        }
        #[derive(serde::Deserialize)]
        struct Rec {
            id: String,
        }
        let resp: Resp = c
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        resp.result.into_iter().next().map(|r| r.id)
    }

    async fn upsert(&self, fqdn: &str, rtype: &str, content: &str, ttl: u32) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        let c = self.client().await;
        let body = serde_json::json!({
            "type": rtype,
            "name": fqdn,
            "content": content,
            "ttl": ttl,
        });
        let resp = if let Some(id) = self.find_record_id_typed(&zone_id, fqdn, rtype).await {
            let url =
                format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}");
            c.put(&url)
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
        } else {
            let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");
            c.post(&url)
                .bearer_auth(&self.token)
                .json(&body)
                .send()
                .await
        }
        .map_err(|e| format!("cf {rtype} upsert: {e}"))?;
        if !resp.status().is_success() {
            let txt = resp.text().await.unwrap_or_default();
            return Err(format!("cf {rtype} upsert non-2xx: {txt}"));
        }
        Ok(())
    }
}

#[async_trait]
impl DnsRecordWriter for Cloudflare {
    async fn upsert_a(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv4() {
            return Err(format!("upsert_a got non-v4 address {ip}"));
        }
        self.upsert(fqdn, "A", &ip.to_string(), ttl).await
    }
    async fn upsert_aaaa(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv6() {
            return Err(format!("upsert_aaaa got non-v6 address {ip}"));
        }
        self.upsert(fqdn, "AAAA", &ip.to_string(), ttl).await
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// =============================================================================
// Route 53 — uses the aws-sdk we already have for S3 backups
// =============================================================================

pub struct Route53 {
    access_key: String,
    secret_key: String,
    region: String,
    zone_name: String,
    /// Hosted zone ID — either supplied in `extra.zone_id` or resolved on
    /// first use via ListHostedZonesByName.
    zone_id: tokio::sync::OnceCell<String>,
}

impl Route53 {
    fn new(p: &AcmeDnsProvider) -> Result<Self, String> {
        let access_key = p.api_token.clone().ok_or_else(|| {
            "Route53 provider missing access key (use api_token field)".to_string()
        })?;
        let secret_key = p
            .aws_secret_key
            .clone()
            .ok_or_else(|| "Route53 provider missing secret access key".to_string())?;
        let region = p
            .extra
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1")
            .to_string();
        let zone_id = tokio::sync::OnceCell::new();
        if let Some(z) = p.extra.get("zone_id").and_then(|v| v.as_str()) {
            let _ = zone_id.set(z.to_string());
        }
        Ok(Self {
            access_key,
            secret_key,
            region,
            zone_name: p.zone.clone(),
            zone_id,
        })
    }

    async fn client(&self) -> aws_sdk_route53::Client {
        use aws_credential_types::{Credentials, provider::SharedCredentialsProvider};
        let creds = Credentials::new(&self.access_key, &self.secret_key, None, None, "aifw-acme");
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new(self.region.clone()))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .load()
            .await;
        aws_sdk_route53::Client::new(&cfg)
    }

    async fn resolve_zone_id(&self) -> Result<String, String> {
        if let Some(z) = self.zone_id.get() {
            return Ok(z.clone());
        }
        let c = self.client().await;
        let target = format!("{}.", self.zone_name.trim_end_matches('.'));
        let resp = c
            .list_hosted_zones_by_name()
            .dns_name(&target)
            .max_items(1)
            .send()
            .await
            .map_err(|e| format!("route53 list zones: {e}"))?;
        let zone = resp
            .hosted_zones
            .into_iter()
            .next()
            .ok_or_else(|| format!("Route53: no hosted zone matching '{}'", self.zone_name))?;
        if zone.name() != target {
            return Err(format!(
                "Route53 returned zone '{}' but configured was '{}'",
                zone.name(),
                target
            ));
        }
        // Strip the "/hostedzone/" prefix Route53 returns on the zone id.
        let raw = zone.id().trim_start_matches("/hostedzone/").to_string();
        let _ = self.zone_id.set(raw.clone());
        Ok(raw)
    }

    async fn change_txt(
        &self,
        fqdn: &str,
        value: &str,
        action: aws_sdk_route53::types::ChangeAction,
    ) -> Result<(), String> {
        use aws_sdk_route53::types::{
            Change, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
        };
        let zone_id = self.resolve_zone_id().await?;
        let c = self.client().await;
        let rr_value = format!("\"{}\"", value); // Route53 requires quoted TXT values
        let rrset = ResourceRecordSet::builder()
            .name(format!("{}.", fqdn.trim_end_matches('.')))
            .r#type(RrType::Txt)
            .ttl(60)
            .resource_records(
                ResourceRecord::builder()
                    .value(&rr_value)
                    .build()
                    .map_err(|e| format!("rr build: {e}"))?,
            )
            .build()
            .map_err(|e| format!("rrset build: {e}"))?;
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()
            .map_err(|e| format!("change build: {e}"))?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| format!("batch build: {e}"))?;
        c.change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| format!("route53 ChangeRRSets: {e}"))?;
        Ok(())
    }
}

#[async_trait]
impl DnsSolver for Route53 {
    async fn add_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        self.change_txt(fqdn, value, aws_sdk_route53::types::ChangeAction::Upsert)
            .await
    }
    async fn remove_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        self.change_txt(fqdn, value, aws_sdk_route53::types::ChangeAction::Delete)
            .await
    }
}

impl Route53 {
    async fn upsert_addr(
        &self,
        fqdn: &str,
        rtype: aws_sdk_route53::types::RrType,
        ip: IpAddr,
        ttl: u32,
    ) -> Result<(), String> {
        use aws_sdk_route53::types::{
            Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet,
        };
        let zone_id = self.resolve_zone_id().await?;
        let c = self.client().await;
        let rrset = ResourceRecordSet::builder()
            .name(format!("{}.", fqdn.trim_end_matches('.')))
            .r#type(rtype)
            .ttl(ttl as i64)
            .resource_records(
                ResourceRecord::builder()
                    .value(ip.to_string())
                    .build()
                    .map_err(|e| format!("rr build: {e}"))?,
            )
            .build()
            .map_err(|e| format!("rrset build: {e}"))?;
        let change = Change::builder()
            .action(ChangeAction::Upsert)
            .resource_record_set(rrset)
            .build()
            .map_err(|e| format!("change build: {e}"))?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| format!("batch build: {e}"))?;
        c.change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| format!("route53 ChangeRRSets: {e}"))?;
        Ok(())
    }
}

#[async_trait]
impl DnsRecordWriter for Route53 {
    async fn upsert_a(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv4() {
            return Err(format!("upsert_a got non-v4 address {ip}"));
        }
        self.upsert_addr(fqdn, aws_sdk_route53::types::RrType::A, ip, ttl)
            .await
    }
    async fn upsert_aaaa(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv6() {
            return Err(format!("upsert_aaaa got non-v6 address {ip}"));
        }
        self.upsert_addr(fqdn, aws_sdk_route53::types::RrType::Aaaa, ip, ttl)
            .await
    }
}

// =============================================================================
// Manual — admin pastes the TXT into their DNS by hand
// =============================================================================

pub struct Manual {
    name: String,
}

#[async_trait]
impl DnsSolver for Manual {
    async fn add_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        // Surfaces in the cert's last_renew_error so the operator can see
        // exactly what to paste. The engine treats this as "challenge
        // started" — the operator must add the record then click "Renew now"
        // again to finish.
        Err(format!(
            "MANUAL_DNS_ACTION_REQUIRED on provider '{}': add a TXT record at '{}' with value '{}', then re-run the issue.",
            self.name, fqdn, value,
        ))
    }
    async fn remove_txt(&self, _fqdn: &str, _value: &str) -> Result<(), String> {
        // Nothing to do — the operator can clean up by hand.
        Ok(())
    }
}
