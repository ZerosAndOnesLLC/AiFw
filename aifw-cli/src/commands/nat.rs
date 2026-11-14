//! `aifw nat …` — NAT rules (via the API; staged until `aifw apply`).

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum NatCmd {
    /// Add a NAT rule
    #[command(after_help = "\
EXAMPLES:
    # Source NAT a LAN behind a WAN address
    aifw nat add --type snat --interface em0 --src 192.168.1.0/24 --redirect 203.0.113.1

    # Port-forward WAN :80 to an internal host
    aifw nat add --type dnat --interface em0 --dst-port 80 --redirect 10.0.0.5 --redirect-port 8080

    # NAT64: IPv6-only clients reach IPv4 hosts (pf af-to, FreeBSD 15+).
    # --dst defaults to the well-known prefix 64:ff9b::/96; --redirect is
    # the IPv4 the firewall sources translated traffic from.
    aifw nat add --type nat64 --interface em1 --redirect 203.0.113.1

    # NAT46: IPv4-only clients reach an IPv6 service. The v6 server must
    # hold the RFC 6052 embedding of --dst in --redirect's /96 subnet
    # (print it with: aifw nat embed <redirect> <dst>).
    aifw nat add --type nat46 --interface em1 --dst 10.99.1.1 --redirect 2001:db8:2::1

    # Masquerade keeping the source port (SIP/VPN friendly)
    aifw nat add --type masquerade --interface em0 --src 192.168.1.0/24 --static-port

    # NAT bypass: don't NAT LAN → site-to-site VPN subnet (order before the masquerade rule)
    aifw nat add --type nonat --interface em0 --src 192.168.1.0/24 --dst 10.50.0.0/16")]
    Add(AddArgs),
    /// Change fields of a NAT rule (only the flags you pass)
    Edit(EditArgs),
    /// List NAT rules
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Show one NAT rule
    Show { id: String },
    /// Delete a NAT rule
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Enable a NAT rule
    Enable {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Disable a NAT rule without deleting it
    Disable {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Set the evaluation order (NAT rule ids, first evaluated first)
    Reorder {
        #[arg(required = true, num_args = 1..)]
        ids: Vec<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Show the generated pf NAT ruleset
    PfOutput,
    /// Print the RFC 6052 IPv6 address that embeds an IPv4 in a /96 prefix
    /// (what a NAT46 v6 server must hold)
    Embed {
        /// IPv6 /96 prefix, e.g. 2001:db8:2:: or 64:ff9b::/96
        prefix: String,
        /// IPv4 address to embed
        ipv4: String,
    },
}

#[derive(Debug, Args)]
pub struct NatFields {
    /// NAT type: snat, dnat, masquerade, binat, nat64, nat46, nonat
    #[arg(long = "type", visible_alias = "nat-type", value_name = "TYPE")]
    pub nat_type: Option<String>,
    /// Interface the rule applies on
    #[arg(long)]
    pub interface: Option<String>,
    /// tcp, udp, tcp/udp, icmp, any
    #[arg(long)]
    pub proto: Option<String>,
    #[arg(long)]
    pub src: Option<String>,
    #[arg(long)]
    pub src_port: Option<String>,
    /// Destination (nat64 defaults to 64:ff9b::/96)
    #[arg(long)]
    pub dst: Option<String>,
    #[arg(long)]
    pub dst_port: Option<String>,
    /// Translation target address
    #[arg(long)]
    pub redirect: Option<String>,
    #[arg(long)]
    pub redirect_port: Option<String>,
    #[arg(long)]
    pub label: Option<String>,
    /// Keep the source port (snat / masquerade)
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub static_port: Option<bool>,
    /// Translated destination for nat46/nat64
    #[arg(long)]
    pub af_to_dst: Option<String>,
    /// Read the rule (JSON/YAML, API request shape) from a file, or - for stdin
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,
    /// Apply to pf right away
    #[arg(long)]
    pub apply: bool,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[command(flatten)]
    pub f: NatFields,
    /// Create it disabled
    #[arg(long)]
    pub disabled: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    pub id: String,
    #[command(flatten)]
    pub f: NatFields,
}

impl NatFields {
    fn to_fields(&self) -> anyhow::Result<Fields> {
        let mut f = Fields::new()
            .opt("nat_type", self.nat_type.clone())
            .opt("interface", self.interface.clone())
            .opt("protocol", self.proto.clone())
            .opt("src_addr", self.src.clone())
            .opt("dst_addr", self.dst.clone())
            .opt("redirect_addr", self.redirect.clone())
            .opt("label", self.label.clone())
            .opt("static_port", self.static_port)
            .opt("af_to_dst", self.af_to_dst.clone());
        for (flag, prefix) in [
            (&self.src_port, "src_port"),
            (&self.dst_port, "dst_port"),
            (&self.redirect_port, "redirect_port"),
        ] {
            if let Some(p) = flag {
                let (a, b) = body::port_range(p)?;
                f = f
                    .set(&format!("{prefix}_start"), a)
                    .set(&format!("{prefix}_end"), b);
            }
        }
        Ok(f)
    }
}

/// Engine validation message → the CLI flag to fix.
pub fn nat_flag_hint(msg: &str) -> Option<&'static str> {
    if msg.contains("nat64 destination") {
        Some(
            "set --dst to an IPv6 /96 prefix, e.g. --dst 64:ff9b::/96 (or omit --dst for the default)",
        )
    } else if msg.contains("nat46 destination") {
        Some("set --dst to the IPv4 address being reached, e.g. --dst 10.99.1.1")
    } else if msg.contains("translation source") {
        Some(
            "set --redirect to a single address the firewall owns in the translated family (IPv4 for nat64, IPv6 for nat46)",
        )
    } else if msg.contains("support a redirect port") {
        Some("drop --redirect-port — af-to translates addresses, not ports")
    } else if msg.contains("source address must be") {
        Some("fix --src: it must match the rule's ingress family (IPv6 for nat64, IPv4 for nat46)")
    } else if msg.contains("static_port is only valid") {
        Some("drop --static-port — it only applies to --type snat / masquerade")
    } else if msg.contains("af_to_dst (translated destination) is only valid") {
        Some("drop --af-to-dst — it only applies to --type nat46 / nat64")
    } else if msg.contains("translated destination must be a single") {
        Some(
            "--af-to-dst must be one host address in the translated family (IPv6 for nat46, IPv4 for nat64)",
        )
    } else if msg.contains("no-nat rules") {
        Some("drop --redirect / --redirect-port — nonat exempts traffic and has no target")
    } else {
        None
    }
}

/// Attach a flag hint to a validation error from the API.
fn with_hint(e: aifw_client::ClientError) -> anyhow::Error {
    if let aifw_client::ClientError::Validation(msg) = &e
        && let Some(h) = nat_flag_hint(msg)
    {
        let hint = format!("hint: {h}");
        return anyhow::Error::new(e).context(hint);
    }
    e.into()
}

pub fn nat_embed(prefix: &str, ipv4: &str) -> anyhow::Result<String> {
    let p: std::net::Ipv6Addr = prefix
        .split('/')
        .next()
        .unwrap_or(prefix)
        .parse()
        .map_err(|_| CliError::Usage(format!("'{prefix}' is not a valid IPv6 prefix")))?;
    let v4: std::net::Ipv4Addr = ipv4
        .parse()
        .map_err(|_| CliError::Usage(format!("'{ipv4}' is not a valid IPv4 address")))?;
    Ok(aifw_common::embed_rfc6052(p, v4).to_string())
}

/// A NAT rule as returned → the request shape (PUT replaces optional fields).
pub fn to_request(r: &Value) -> Value {
    let port = |p: &Value, k: &str| p.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "nat_type": r["nat_type"],
        "interface": r["interface"],
        "protocol": r["protocol"],
        "src_addr": r["src_addr"],
        "src_port_start": port(&r["src_port"], "start"),
        "src_port_end": port(&r["src_port"], "end"),
        "dst_addr": r["dst_addr"],
        "dst_port_start": port(&r["dst_port"], "start"),
        "dst_port_end": port(&r["dst_port"], "end"),
        "redirect_addr": r["redirect"]["address"],
        "redirect_port_start": port(&r["redirect"]["port"], "start"),
        "redirect_port_end": port(&r["redirect"]["port"], "end"),
        "label": r["label"],
        "status": r["status"],
        "static_port": r["static_port"].as_bool().unwrap_or(false),
        "af_to_dst": r["af_to_dst"],
    })
}

fn endpoint(addr: &Value, port: &Value) -> String {
    let a = addr.as_str().unwrap_or("any");
    match (
        port.get("start").and_then(Value::as_u64),
        port.get("end").and_then(Value::as_u64),
    ) {
        (Some(s), Some(e)) if s == e => format!("{a}:{s}"),
        (Some(s), Some(e)) => format!("{a}:{s}-{e}"),
        _ => a.to_string(),
    }
}

fn table_row(r: &Value) -> Value {
    let mut row = r.clone();
    row["_src"] = json!(endpoint(&r["src_addr"], &r["src_port"]));
    row["_dst"] = json!(endpoint(&r["dst_addr"], &r["dst_port"]));
    row["_to"] = json!(match r["nat_type"].as_str() {
        Some("masquerade") => "(interface)".to_string(),
        Some("nonat") => "-".to_string(),
        _ => endpoint(&r["redirect"]["address"], &r["redirect"]["port"]),
    });
    row
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("TYPE", "/nat_type"),
    col("IFACE", "/interface"),
    col("PROTO", "/protocol"),
    col("SOURCE", "/_src"),
    col("DESTINATION", "/_dst"),
    col("TRANSLATE TO", "/_to"),
    col("STATUS", "/status"),
    col("LABEL", "/label"),
    wide("STATIC-PORT", "/static_port"),
    wide("AF-TO-DST", "/af_to_dst"),
];

/// The pf lines a rule compiles to (rendered locally from the returned rule).
fn pf_preview(rule: &Value) -> Vec<String> {
    serde_json::from_value::<aifw_common::NatRule>(rule.clone())
        .map(|r| r.to_pf_rules())
        .unwrap_or_default()
}

pub async fn run(ctx: &mut Ctx, cmd: NatCmd) -> anyhow::Result<()> {
    if let NatCmd::Embed { prefix, ipv4 } = &cmd {
        let addr = nat_embed(prefix, ipv4)?;
        ctx.io.println(&addr);
        return Ok(());
    }
    let client = ctx.client()?;
    match cmd {
        NatCmd::Embed { .. } => Ok(()),
        NatCmd::List { json } => {
            let v = client.get("/nat").await?;
            if json {
                return ctx.legacy_json(&v, None);
            }
            ctx.list_mapped(&v, COLS, table_row)
        }
        NatCmd::Show { id } => {
            let v = client.get("/nat").await?;
            let rule = crate::cli::output::rows(&v)
                .into_iter()
                .find(|r| r["id"] == json!(id))
                .cloned()
                .ok_or_else(|| aifw_client::ClientError::NotFound(format!("NAT rule {id}")))?;
            if ctx.format().is_structured() {
                return ctx.raw(&rule);
            }
            let row = table_row(&rule);
            ctx.detail(
                &row,
                &[
                    ("ID", "/id"),
                    ("Type", "/nat_type"),
                    ("Interface", "/interface"),
                    ("Protocol", "/protocol"),
                    ("Source", "/_src"),
                    ("Destination", "/_dst"),
                    ("Translate to", "/_to"),
                    ("Static port", "/static_port"),
                    ("AF-to dst", "/af_to_dst"),
                    ("Label", "/label"),
                    ("Status", "/status"),
                ],
            )?;
            for line in pf_preview(&rule) {
                ctx.io.println(&format!("pf: {line}"));
            }
            Ok(())
        }
        NatCmd::Add(a) => {
            let mut fields = a.f.to_fields()?;
            if a.disabled {
                fields = fields.set("status", "disabled");
            }
            let mut body = body::for_create(&mut ctx.io, a.f.file.as_deref(), fields)?;
            let ty = body["nat_type"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| {
                    CliError::Usage(
                        "--type is required (snat, dnat, masquerade, binat, nat64, nat46, nonat)"
                            .into(),
                    )
                })?;
            if body.get("interface").is_none_or(Value::is_null) {
                return Err(CliError::Usage("--interface is required".into()).into());
            }
            if body.get("protocol").is_none_or(Value::is_null) {
                body["protocol"] = json!("any");
            }
            // nat64 practically always targets the well-known prefix.
            if body.get("dst_addr").is_none_or(Value::is_null) {
                body["dst_addr"] = json!(if ty == "nat64" { "64:ff9b::/96" } else { "any" });
            }
            // masquerade / nonat have no translation target; the rest need one.
            if body.get("redirect_addr").is_none_or(Value::is_null) {
                if matches!(ty.as_str(), "masquerade" | "masq" | "nonat" | "no-nat") {
                    body["redirect_addr"] = json!("any");
                } else {
                    return Err(
                        CliError::Usage(format!("--redirect is required for --type {ty}")).into(),
                    );
                }
            }
            let v = client.post("/nat", &body).await.map_err(with_hint)?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                let rule = &v["data"];
                ctx.io.println(&format!(
                    "Added NAT rule {}",
                    rule["id"].as_str().unwrap_or("?")
                ));
                for line in pf_preview(rule) {
                    ctx.io.println(&format!("  pf: {line}"));
                }
            }
            super::rules::after_write(ctx, a.f.apply).await
        }
        NatCmd::Edit(a) => {
            let all = client.get("/nat").await?;
            let current = crate::cli::output::rows(&all)
                .into_iter()
                .find(|r| r["id"] == json!(a.id))
                .cloned()
                .ok_or_else(|| aifw_client::ClientError::NotFound(format!("NAT rule {}", a.id)))?;
            let body = body::for_update(
                &mut ctx.io,
                to_request(&current),
                a.f.file.as_deref(),
                a.f.to_fields()?,
            )?;
            let v = client
                .put(&format!("/nat/{}", a.id), &body)
                .await
                .map_err(with_hint)?;
            ctx.message(&v, &format!("Updated NAT rule {}", a.id))?;
            super::rules::after_write(ctx, a.f.apply).await
        }
        NatCmd::Remove { id, yes, apply } => {
            ctx.confirm(&format!("Delete NAT rule {id}?"), yes)?;
            let v = client.delete(&format!("/nat/{id}")).await?;
            ctx.message(&v, &format!("Removed NAT rule {id}"))?;
            super::rules::after_write(ctx, apply).await
        }
        NatCmd::Enable { id, apply } => set_status(ctx, &client, &id, "active", apply).await,
        NatCmd::Disable { id, apply } => set_status(ctx, &client, &id, "disabled", apply).await,
        NatCmd::Reorder { ids, apply } => {
            let v = client
                .put("/nat/reorder", &json!({ "rule_ids": ids }))
                .await?;
            ctx.message(&v, "NAT rules reordered")?;
            super::rules::after_write(ctx, apply).await
        }
        NatCmd::PfOutput => {
            let v = client.get("/nat/pf-output").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            for line in crate::cli::output::rows(&v) {
                ctx.io.println(line.as_str().unwrap_or_default());
            }
            Ok(())
        }
    }
}

async fn set_status(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    id: &str,
    status: &str,
    apply: bool,
) -> anyhow::Result<()> {
    let all = client.get("/nat").await?;
    let current = crate::cli::output::rows(&all)
        .into_iter()
        .find(|r| r["id"] == json!(id))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("NAT rule {id}")))?;
    let mut body = to_request(&current);
    body["status"] = json!(status);
    let v = client.put(&format!("/nat/{id}"), &body).await?;
    let verb = if status == "active" {
        "Enabled"
    } else {
        "Disabled"
    };
    ctx.message(&v, &format!("{verb} NAT rule {id}"))?;
    super::rules::after_write(ctx, apply).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_hints_map_engine_errors_to_cli_flags() {
        assert!(
            nat_flag_hint("static_port is only valid for SNAT")
                .unwrap()
                .contains("--static-port")
        );
        assert!(
            nat_flag_hint("af_to_dst (translated destination) is only valid for nat46")
                .unwrap()
                .contains("--af-to-dst")
        );
        assert!(
            nat_flag_hint("nat46 translated destination must be a single IPv6")
                .unwrap()
                .contains("--af-to-dst")
        );
        assert!(
            nat_flag_hint("rules do not support a redirect port")
                .unwrap()
                .contains("--redirect-port")
        );
        assert!(nat_flag_hint("something unrelated").is_none());
        // DNAT's "needs a port" error is not the af-to one.
        assert!(
            nat_flag_hint("DNAT/RDR rule requires a destination port or redirect port").is_none()
        );
    }

    #[test]
    fn nat_embed_validates_inputs() {
        assert_eq!(
            nat_embed("64:ff9b::/96", "10.1.2.3").unwrap(),
            "64:ff9b::a01:203"
        );
        assert!(
            nat_embed("64:ff9b::", "10.1.2.3").is_ok(),
            "bare address accepted"
        );
        assert!(nat_embed("not-v6", "10.1.2.3").is_err());
        assert!(nat_embed("64:ff9b::/96", "300.1.1.1").is_err());
    }

    #[test]
    fn request_round_trip_keeps_ports_and_target() {
        let rule = json!({
            "nat_type": "dnat", "interface": "em0", "protocol": "tcp",
            "src_addr": "any", "src_port": null, "dst_addr": "any",
            "dst_port": {"start": 80, "end": 80},
            "redirect": {"address": "10.0.0.5", "port": {"start": 8080, "end": 8080}},
            "label": "web", "status": "active", "static_port": false, "af_to_dst": null
        });
        let r = to_request(&rule);
        assert_eq!(r["dst_port_start"], 80);
        assert_eq!(r["redirect_addr"], "10.0.0.5");
        assert_eq!(r["redirect_port_end"], 8080);
        assert_eq!(table_row(&rule)["_to"], "10.0.0.5:8080");
    }
}
