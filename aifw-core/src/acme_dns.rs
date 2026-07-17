//! DNS-01 challenge solvers.
//!
//! Each provider implements [`DnsSolver`]. The ACME engine calls
//! `add_txt(...)` before telling the CA the challenge is ready, then
//! `remove_txt(...)` after the cert is issued (success or failure).
//!
//! Adding a new provider:
//!  1. Add a variant to [`crate::acme::DnsProviderKind`].
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

/// A DNS provider that can publish and clean up DNS-01 challenge TXT records
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
    /// Create or update the A record for `fqdn`. Fails if `ip` is not IPv4.
    /// `ttl` is in seconds.
    async fn upsert_a(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String>;
    /// Create or update the AAAA record for `fqdn`. Fails if `ip` is not
    /// IPv6. `ttl` is in seconds.
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

/// Cloudflare DNS-01 solver / DDNS record writer using a scoped API token
/// (`Zone:DNS:Edit`) against the v4 REST API
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
        let id = resp
            .result
            .into_iter()
            .next()
            .expect("resp.result non-empty (checked above)")
            .id;
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
// Route 53 — SigV4-signed reqwest calls against the plain XML REST API.
//
// PERF-I2 (#410): previously used aws-sdk-route53, whose smithy runtime
// chain gated the whole workspace build. We only ever issue two API calls
// (ListHostedZonesByName + ChangeResourceRecordSets), so they're signed
// with the standalone `aws-sigv4` crate and sent through the reqwest
// client we already ship. Route 53 is a global service: the endpoint is
// route53.amazonaws.com and requests are signed for us-east-1 regardless
// of any configured region (the SDK did the same internally).
// =============================================================================

/// Route 53 API base. The date segment is the API version, not a region.
const R53_BASE: &str = "https://route53.amazonaws.com/2013-04-01";
/// XML namespace required on ChangeResourceRecordSets request bodies.
const R53_XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
/// Global-service signing region (fixed by AWS for Route 53).
const R53_REGION: &str = "us-east-1";

/// AWS Route 53 DNS-01 solver / DDNS record writer authenticated with an
/// explicit access-key pair (`api_token` = access key id)
pub struct Route53 {
    access_key: String,
    secret_key: String,
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
        let zone_id = tokio::sync::OnceCell::new();
        if let Some(z) = p.extra.get("zone_id").and_then(|v| v.as_str()) {
            let _ = zone_id.set(z.to_string());
        }
        Ok(Self {
            access_key,
            secret_key,
            zone_name: p.zone.clone(),
            zone_id,
        })
    }

    /// Sign and send one Route 53 request. `body` is the XML request body
    /// for POSTs, empty for GETs. Returns the response body on 2xx.
    async fn signed_request(&self, method: &str, url: &str, body: &str) -> Result<String, String> {
        use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
        use aws_sigv4::sign::v4;

        let identity = aws_credential_types::Credentials::new(
            &self.access_key,
            &self.secret_key,
            None,
            None,
            "aifw-acme",
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(R53_REGION)
            .name("route53")
            .time(std::time::SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| format!("route53 signing params: {e}"))?
            .into();

        // Headers passed here are folded into the signature, so the real
        // request below must send exactly the same set.
        let signed_headers: Vec<(&str, &str)> = if body.is_empty() {
            Vec::new()
        } else {
            vec![("content-type", "application/xml")]
        };
        let signable = SignableRequest::new(
            method,
            url,
            signed_headers.iter().copied(),
            SignableBody::Bytes(body.as_bytes()),
        )
        .map_err(|e| format!("route53 signable request: {e}"))?;
        let (instructions, _signature) = sign(signable, &params)
            .map_err(|e| format!("route53 sign: {e}"))?
            .into_parts();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let mut req = match method {
            "POST" => client.post(url),
            _ => client.get(url),
        };
        for (name, value) in &signed_headers {
            req = req.header(*name, *value);
        }
        for (name, value) in instructions.headers() {
            req = req.header(name, value);
        }
        if !body.is_empty() {
            req = req.body(body.to_string());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("route53 request: {e}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // Route 53 error bodies are small XML docs naming the failure
            // (InvalidChangeBatch, AccessDenied, ...) — surface a snippet.
            let snippet: String = text.chars().take(300).collect();
            return Err(format!("route53 HTTP {status}: {snippet}"));
        }
        Ok(text)
    }

    async fn resolve_zone_id(&self) -> Result<String, String> {
        if let Some(z) = self.zone_id.get() {
            return Ok(z.clone());
        }
        let target = format!("{}.", self.zone_name.trim_end_matches('.'));
        let url = format!(
            "{R53_BASE}/hostedzonesbyname?dnsname={}&maxitems=1",
            urlencoding(&target)
        );
        let text = self.signed_request("GET", &url, "").await?;
        let parsed: ListHostedZonesByNameResponse =
            quick_xml::de::from_str(&text).map_err(|e| format!("route53 list zones parse: {e}"))?;
        let zone = parsed
            .hosted_zones
            .hosted_zone
            .into_iter()
            .next()
            .ok_or_else(|| format!("Route53: no hosted zone matching '{}'", self.zone_name))?;
        if zone.name != target {
            return Err(format!(
                "Route53 returned zone '{}' but configured was '{}'",
                zone.name, target
            ));
        }
        // Strip the "/hostedzone/" prefix Route53 returns on the zone id.
        let raw = zone.id.trim_start_matches("/hostedzone/").to_string();
        let _ = self.zone_id.set(raw.clone());
        Ok(raw)
    }

    /// Submit a single-change ChangeResourceRecordSets batch.
    async fn change_rrset(
        &self,
        action: &str,
        fqdn: &str,
        rtype: &str,
        value: &str,
        ttl: u32,
    ) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        let url = format!("{R53_BASE}/hostedzone/{zone_id}/rrset");
        let body = change_batch_xml(action, fqdn, rtype, value, ttl);
        self.signed_request("POST", &url, &body).await?;
        Ok(())
    }
}

/// Build the ChangeResourceRecordSets XML request body for one change.
fn change_batch_xml(action: &str, fqdn: &str, rtype: &str, value: &str, ttl: u32) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<ChangeResourceRecordSetsRequest xmlns="{ns}">"#,
            "<ChangeBatch><Changes><Change>",
            "<Action>{action}</Action>",
            "<ResourceRecordSet>",
            "<Name>{name}</Name>",
            "<Type>{rtype}</Type>",
            "<TTL>{ttl}</TTL>",
            "<ResourceRecords><ResourceRecord><Value>{value}</Value></ResourceRecord></ResourceRecords>",
            "</ResourceRecordSet>",
            "</Change></Changes></ChangeBatch>",
            "</ChangeResourceRecordSetsRequest>",
        ),
        ns = R53_XMLNS,
        action = action,
        name = xml_escape(&format!("{}.", fqdn.trim_end_matches('.'))),
        rtype = rtype,
        ttl = ttl,
        value = xml_escape(value),
    )
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct ListHostedZonesByNameResponse {
    #[serde(rename = "HostedZones")]
    hosted_zones: HostedZonesList,
}

#[derive(serde::Deserialize, Default)]
struct HostedZonesList {
    #[serde(rename = "HostedZone", default)]
    hosted_zone: Vec<HostedZoneEntry>,
}

#[derive(serde::Deserialize)]
struct HostedZoneEntry {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
}

#[async_trait]
impl DnsSolver for Route53 {
    async fn add_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        // Route53 requires quoted TXT values.
        self.change_rrset("UPSERT", fqdn, "TXT", &format!("\"{value}\""), 60)
            .await
    }
    async fn remove_txt(&self, fqdn: &str, value: &str) -> Result<(), String> {
        self.change_rrset("DELETE", fqdn, "TXT", &format!("\"{value}\""), 60)
            .await
    }
}

#[async_trait]
impl DnsRecordWriter for Route53 {
    async fn upsert_a(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv4() {
            return Err(format!("upsert_a got non-v4 address {ip}"));
        }
        self.change_rrset("UPSERT", fqdn, "A", &ip.to_string(), ttl)
            .await
    }
    async fn upsert_aaaa(&self, fqdn: &str, ip: IpAddr, ttl: u32) -> Result<(), String> {
        if !ip.is_ipv6() {
            return Err(format!("upsert_aaaa got non-v6 address {ip}"));
        }
        self.change_rrset("UPSERT", fqdn, "AAAA", &ip.to_string(), ttl)
            .await
    }
}

// =============================================================================
// Manual — admin pastes the TXT into their DNS by hand
// =============================================================================

/// Operator-managed DNS: `add_txt` always errors with the exact TXT record
/// to paste, so the operator adds it by hand and re-runs the issue
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_batch_xml_shape() {
        let xml = change_batch_xml(
            "UPSERT",
            "_acme-challenge.fw.example.com",
            "TXT",
            "\"tok-abc\"",
            60,
        );
        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(xml.contains(r#"xmlns="https://route53.amazonaws.com/doc/2013-04-01/""#));
        assert!(xml.contains("<Action>UPSERT</Action>"));
        // fqdn gets a trailing dot; TXT value keeps its quotes.
        assert!(xml.contains("<Name>_acme-challenge.fw.example.com.</Name>"));
        assert!(xml.contains("<Type>TXT</Type>"));
        assert!(xml.contains("<TTL>60</TTL>"));
        assert!(xml.contains("<Value>&quot;tok-abc&quot;</Value>"));
    }

    #[test]
    fn change_batch_xml_does_not_double_dot() {
        let xml = change_batch_xml("DELETE", "host.example.com.", "A", "203.0.113.7", 300);
        assert!(xml.contains("<Name>host.example.com.</Name>"));
        assert!(!xml.contains("com..</Name>"));
    }

    #[test]
    fn xml_escape_covers_specials() {
        assert_eq!(
            xml_escape(r#"a&b<c>d"e'f"#),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        assert_eq!(xml_escape("plain-value"), "plain-value");
    }

    #[test]
    fn parses_list_hosted_zones_by_name() {
        let xml = r#"<?xml version="1.0"?>
<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/Z0123456ABCDEF</Id>
      <Name>example.com.</Name>
      <CallerReference>ref-1</CallerReference>
      <Config><PrivateZone>false</PrivateZone></Config>
      <ResourceRecordSetCount>12</ResourceRecordSetCount>
    </HostedZone>
  </HostedZones>
  <DNSName>example.com.</DNSName>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListHostedZonesByNameResponse>"#;
        let parsed: ListHostedZonesByNameResponse = quick_xml::de::from_str(xml).unwrap();
        let zone = &parsed.hosted_zones.hosted_zone[0];
        assert_eq!(zone.id, "/hostedzone/Z0123456ABCDEF");
        assert_eq!(zone.name, "example.com.");
    }

    #[test]
    fn parses_empty_zone_list() {
        let xml = r#"<?xml version="1.0"?>
<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones/>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListHostedZonesByNameResponse>"#;
        let parsed: ListHostedZonesByNameResponse = quick_xml::de::from_str(xml).unwrap();
        assert!(parsed.hosted_zones.hosted_zone.is_empty());
    }
}
