//! `aifw acme …`, `aifw ddns …`, `aifw ca …` via the API.
//!
//! Endpoints that answer 200 with `{ok: false, message}` (renew, provider
//! test, DDNS update) exit non-zero. PEM downloads go to stdout or `-O`
//! (private keys are written 0600).

use std::path::PathBuf;
use std::time::Duration;

use clap::Subcommand;
use serde_json::{Value, json};

use super::resource::{Coll, Resource};
use crate::cli::body::Fields;
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

/// Print `{ok, message}` and fail when `ok` is false.
fn ok_message(ctx: &mut Ctx, v: &Value, fallback: &str) -> anyhow::Result<()> {
    ctx.message(v, fallback)?;
    if v["ok"] == json!(false) {
        return Err(
            CliError::CheckFailed(v["message"].as_str().unwrap_or(fallback).to_string()).into(),
        );
    }
    Ok(())
}

/// Write PEM text to stdout or a file (0600 for keys, 0644 otherwise).
fn save_pem(ctx: &mut Ctx, bytes: &[u8], out: Option<PathBuf>, secret: bool) -> anyhow::Result<()> {
    match out {
        Some(p) => {
            crate::cli::config::write_atomic(&p, bytes, if secret { 0o600 } else { 0o644 })?;
            ctx.io.eprintln(&format!(
                "Wrote {}{}",
                p.display(),
                if secret { " (0600)" } else { "" }
            ));
        }
        None => ctx.io.println(String::from_utf8_lossy(bytes).trim_end()),
    }
    Ok(())
}

// ------------------------------------------------------------------- ACME

#[derive(Debug, Subcommand)]
pub enum AcmeCmd {
    /// Show or set the ACME account
    Account {
        /// Contact email (setting it registers/updates the account)
        #[arg(long)]
        email: Option<String>,
        /// ACME directory (default: Let's Encrypt production)
        #[arg(long)]
        directory: Option<String>,
    },
    /// Certificates
    #[command(subcommand)]
    Certs(AcmeCertCmd),
    /// DNS-01 providers (JSON/YAML objects; secrets never shown)
    DnsProviders(Coll),
    /// Test a DNS provider's credentials
    TestProvider { id: String },
    /// Where a certificate is pushed after renewal
    #[command(subcommand)]
    Targets(TargetCmd),
}

#[derive(Debug, Subcommand)]
pub enum AcmeCertCmd {
    #[command(visible_alias = "ls")]
    List,
    Show {
        id: String,
    },
    /// Request a certificate
    Add {
        #[arg(long)]
        common_name: String,
        /// Extra names, comma-separated
        #[arg(long)]
        sans: Option<String>,
        /// dns-01 (default) or http-01
        #[arg(long, default_value = "dns-01")]
        challenge: String,
        /// DNS provider id (dns-01)
        #[arg(long)]
        provider: Option<i64>,
        #[arg(long)]
        no_auto_renew: bool,
        #[arg(long)]
        renew_days_before: Option<u32>,
    },
    /// Issue/renew now (waits for the CA)
    Renew {
        id: String,
    },
    /// Re-run the export targets
    Publish {
        id: String,
    },
    /// Download the certificate chain
    Pem {
        id: String,
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    /// Download the private key (needs settings:write)
    Key {
        id: String,
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum TargetCmd {
    /// A certificate's export targets
    #[command(visible_alias = "ls")]
    List { cert: String },
    /// Add a target: kind file|webhook|local-tls-store, config as JSON/YAML
    Add {
        cert: String,
        #[arg(long)]
        kind: String,
        /// Target config file (- for stdin), e.g. {"url": "https://…"}
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

const ACME_CERT_COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("NAME", "/common_name"),
    col("SANS", "/sans"),
    col("CHALLENGE", "/challenge_type"),
    col("STATUS", "/status"),
    col("EXPIRES", "/expires_at"),
    col("DAYS LEFT", "/days_until_expiry"),
    wide("AUTO-RENEW", "/auto_renew"),
    wide("LAST ERROR", "/last_renew_error"),
];

pub async fn acme(ctx: &mut Ctx, cmd: AcmeCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        AcmeCmd::Account { email, directory } => {
            let v = match email {
                Some(e) => {
                    let body = Fields::new()
                        .set("contact_email", e)
                        .opt("directory_url", directory)
                        .into_value();
                    client.put("/acme/account", &body).await?
                }
                None if directory.is_some() => {
                    return Err(CliError::Usage("--directory needs --email".into()).into());
                }
                None => client.get("/acme/account").await?,
            };
            ctx.detail(
                &v,
                &[
                    ("Email", "/contact_email"),
                    ("Directory", "/directory_url"),
                    ("Registered", "/registered"),
                ],
            )
        }
        AcmeCmd::Certs(c) => match c {
            AcmeCertCmd::List => {
                let v = client.get("/acme/certs").await?;
                ctx.list(&v, ACME_CERT_COLS)
            }
            AcmeCertCmd::Show { id } => ctx.raw(&client.get(&format!("/acme/certs/{id}")).await?),
            AcmeCertCmd::Add {
                common_name,
                sans,
                challenge,
                provider,
                no_auto_renew,
                renew_days_before,
            } => {
                if challenge != "http-01" && provider.is_none() {
                    return Err(CliError::Usage(
                        "dns-01 needs --provider <id> (see `aifw acme dns-providers`)".into(),
                    )
                    .into());
                }
                let sans: Vec<String> = sans
                    .as_deref()
                    .map(|s| {
                        s.split(',')
                            .map(str::trim)
                            .filter(|x| !x.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let body = Fields::new()
                    .set("common_name", common_name)
                    .set("sans", sans)
                    .set("challenge_type", challenge)
                    .opt("dns_provider_id", provider)
                    .set("auto_renew", !no_auto_renew)
                    .opt("renew_days_before_expiry", renew_days_before)
                    .into_value();
                let v = client.post("/acme/certs", &body).await?;
                if ctx.format().is_structured() {
                    return ctx.raw(&v);
                }
                ctx.io.println(&format!(
                    "Added certificate {} — run `aifw acme certs renew {}` to issue it",
                    v["id"], v["id"]
                ));
                Ok(())
            }
            AcmeCertCmd::Renew { id } => {
                let v = client
                    .request_with_timeout(
                        reqwest::Method::POST,
                        &format!("/acme/certs/{id}/renew"),
                        None,
                        ctx.slow_timeout(Duration::from_secs(600)),
                    )
                    .await?;
                ok_message(ctx, &v, "Renewed")
            }
            AcmeCertCmd::Publish { id } => {
                let v = client
                    .post_empty(&format!("/acme/certs/{id}/publish"))
                    .await?;
                ok_message(ctx, &v, "Published")
            }
            AcmeCertCmd::Pem { id, output_file } => {
                let b = client
                    .get_bytes(&format!("/acme/certs/{id}/cert.pem"))
                    .await?;
                save_pem(ctx, &b, output_file, false)
            }
            AcmeCertCmd::Key { id, output_file } => {
                let b = client
                    .get_bytes(&format!("/acme/certs/{id}/key.pem"))
                    .await?;
                save_pem(ctx, &b, output_file, true)
            }
            AcmeCertCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Delete ACME certificate {id}?"), yes)?;
                client.delete(&format!("/acme/certs/{id}")).await?;
                ctx.message(&Value::Null, &format!("Deleted certificate {id}"))
            }
        },
        AcmeCmd::DnsProviders(c) => {
            let r = Resource {
                path: "/acme/dns-providers".into(),
                what: "DNS provider",
                cols: vec![
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("KIND", "/kind"),
                    col("ZONE", "/zone"),
                    col("TOKEN", "/has_token"),
                    wide("SECRET", "/has_secret"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        AcmeCmd::TestProvider { id } => {
            let v = client
                .post_empty(&format!("/acme/dns-providers/{id}/test"))
                .await?;
            ok_message(ctx, &v, "Provider OK")
        }
        AcmeCmd::Targets(t) => match t {
            TargetCmd::List { cert } => {
                let v = client.get(&format!("/acme/certs/{cert}/targets")).await?;
                ctx.list(
                    &v,
                    &[
                        col("ID", "/id"),
                        col("KIND", "/kind"),
                        col("LAST RUN", "/last_run_at"),
                        col("OK", "/last_run_ok"),
                        wide("ERROR", "/last_run_error"),
                    ],
                )
            }
            TargetCmd::Add { cert, kind, file } => {
                let config = match file {
                    Some(f) => crate::cli::body::read(&mut ctx.io, &f)?,
                    None => Value::Null,
                };
                let v = client
                    .post(
                        &format!("/acme/certs/{cert}/targets"),
                        &json!({ "kind": kind, "config": config }),
                    )
                    .await?;
                ctx.message(&v, "Export target added")
            }
            TargetCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Delete export target {id}?"), yes)?;
                client.delete(&format!("/acme/export-targets/{id}")).await?;
                ctx.message(&Value::Null, "Export target deleted")
            }
        },
    }
}

// ------------------------------------------------------------------- DDNS

#[derive(Debug, Subcommand)]
pub enum DdnsCmd {
    /// DNS records kept up to date (JSON/YAML objects)
    Records(Coll),
    /// Push the current address for one record now
    Update { id: String },
    /// Polling and IP-echo settings
    Config {
        /// Replace the settings from a JSON/YAML file (- for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
}

pub async fn ddns(ctx: &mut Ctx, cmd: DdnsCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        DdnsCmd::Records(c) => {
            let r = Resource {
                path: "/ddns/records".into(),
                what: "DDNS record",
                cols: vec![
                    col("ID", "/id"),
                    col("HOSTNAME", "/hostname"),
                    col("TYPE", "/record_type"),
                    col("SOURCE", "/source"),
                    col("PROVIDER", "/provider_name"),
                    col("LAST IP", "/last_ip"),
                    col("STATUS", "/last_status"),
                    col("ENABLED", "/enabled"),
                    wide("LAST ERROR", "/last_error"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        DdnsCmd::Update { id } => {
            let v = client
                .post_empty(&format!("/ddns/records/{id}/update"))
                .await?;
            ok_message(ctx, &v, "Updated")
        }
        DdnsCmd::Config { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/ddns/config", &body).await?
                }
                None => client.get("/ddns/config").await?,
            };
            ctx.raw(&v)
        }
    }
}

// --------------------------------------------------------------------- CA

#[derive(Debug, Subcommand)]
pub enum CaCmd {
    /// CA details
    Show,
    /// Create the CA (REPLACES any existing CA and invalidates its certs)
    Init {
        #[arg(long)]
        common_name: Option<String>,
        #[arg(long)]
        organization: Option<String>,
        #[arg(long)]
        validity_days: Option<u32>,
        /// ec (default), rsa2048, rsa4096
        #[arg(long)]
        key_type: Option<String>,
        #[arg(short, long)]
        yes: bool,
    },
    /// The CA certificate (install it on clients)
    Pem {
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    /// Revocation list
    Crl,
    /// Issued certificates
    #[command(subcommand)]
    Certs(CaCertCmd),
}

#[derive(Debug, Subcommand)]
pub enum CaCertCmd {
    #[command(visible_alias = "ls")]
    List,
    Show {
        id: String,
    },
    /// Issue a certificate; writes NAME.crt / NAME.key (0600) in --out-dir
    Issue {
        /// server or client
        #[arg(long = "type", value_name = "TYPE")]
        cert_type: String,
        #[arg(long)]
        common_name: String,
        #[arg(long)]
        sans: Option<String>,
        #[arg(long)]
        validity_days: Option<u32>,
        #[arg(long)]
        key_type: Option<String>,
        /// Directory for the cert/key files (default: print JSON)
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Download a certificate
    Pem {
        id: String,
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    /// Download a private key (needs settings:write)
    Key {
        id: String,
        #[arg(short = 'O', long = "output-file")]
        output_file: Option<PathBuf>,
    },
    Revoke {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn ca(ctx: &mut Ctx, cmd: CaCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        CaCmd::Show => {
            let v = client.get("/ca").await?;
            ctx.detail(
                &v,
                &[
                    ("Initialized", "/initialized"),
                    ("Subject", "/subject"),
                    ("Algorithm", "/algorithm"),
                    ("Serial", "/serial"),
                    ("Not before", "/not_before"),
                    ("Not after", "/not_after"),
                    ("Fingerprint", "/fingerprint"),
                ],
            )
        }
        CaCmd::Init {
            common_name,
            organization,
            validity_days,
            key_type,
            yes,
        } => {
            let cur = client.get("/ca").await?;
            if cur["initialized"] == json!(true) {
                ctx.confirm(
                    "A CA already exists. Replace it (its certificates stop validating)?",
                    yes,
                )?;
            }
            let body = Fields::new()
                .opt("common_name", common_name)
                .opt("organization", organization)
                .opt("validity_days", validity_days)
                .opt("key_type", key_type)
                .into_value();
            let v = client.post("/ca", &body).await?;
            ctx.detail(
                &v,
                &[
                    ("Subject", "/subject"),
                    ("Algorithm", "/algorithm"),
                    ("Not after", "/not_after"),
                    ("Fingerprint", "/fingerprint"),
                ],
            )
        }
        CaCmd::Pem { output_file } => {
            let b = client.get_bytes("/ca/cert.pem").await?;
            save_pem(ctx, &b, output_file, false)
        }
        CaCmd::Crl => {
            let b = client.get_bytes("/ca/crl").await?;
            ctx.io.println(String::from_utf8_lossy(&b).trim_end());
            Ok(())
        }
        CaCmd::Certs(c) => match c {
            CaCertCmd::List => {
                let v = client.get("/ca/certs").await?;
                ctx.list(
                    &v,
                    &[
                        col("ID", "/id"),
                        col("TYPE", "/cert_type"),
                        col("NAME", "/common_name"),
                        col("SANS", "/sans"),
                        col("STATUS", "/status"),
                        col("EXPIRES", "/not_after"),
                        wide("SERIAL", "/serial"),
                    ],
                )
            }
            CaCertCmd::Show { id } => ctx.raw(&client.get(&format!("/ca/certs/{id}")).await?),
            CaCertCmd::Issue {
                cert_type,
                common_name,
                sans,
                validity_days,
                key_type,
                out_dir,
            } => {
                let sans: Option<Vec<String>> = sans.map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect()
                });
                let body = Fields::new()
                    .set("cert_type", cert_type)
                    .set("common_name", &common_name)
                    .opt("sans", sans)
                    .opt("validity_days", validity_days)
                    .opt("key_type", key_type)
                    .into_value();
                let v = client.post("/ca/certs", &body).await?;
                match out_dir {
                    Some(dir) => {
                        let safe: String = common_name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                                    c
                                } else {
                                    '_'
                                }
                            })
                            .collect();
                        let crt = dir.join(format!("{safe}.crt"));
                        let key = dir.join(format!("{safe}.key"));
                        crate::cli::config::write_atomic(
                            &crt,
                            v["certificate_pem"].as_str().unwrap_or_default().as_bytes(),
                            0o644,
                        )?;
                        crate::cli::config::write_atomic(
                            &key,
                            v["private_key_pem"].as_str().unwrap_or_default().as_bytes(),
                            0o600,
                        )?;
                        ctx.io.println(&format!(
                            "Issued {} → {} and {} (0600)",
                            v["id"],
                            crt.display(),
                            key.display()
                        ));
                        Ok(())
                    }
                    None => ctx.raw(&v),
                }
            }
            CaCertCmd::Pem { id, output_file } => {
                let b = client
                    .get_bytes(&format!("/ca/certs/{id}/cert.pem"))
                    .await?;
                save_pem(ctx, &b, output_file, false)
            }
            CaCertCmd::Key { id, output_file } => {
                let b = client.get_bytes(&format!("/ca/certs/{id}/key.pem")).await?;
                save_pem(ctx, &b, output_file, true)
            }
            CaCertCmd::Revoke { id, yes } => {
                ctx.confirm(&format!("Revoke certificate {id}?"), yes)?;
                let v = client.post_empty(&format!("/ca/certs/{id}/revoke")).await?;
                ctx.message(&v, "Revoked")
            }
            CaCertCmd::Remove { id, yes } => {
                ctx.confirm(&format!("Delete certificate {id}?"), yes)?;
                let v = client.delete(&format!("/ca/certs/{id}")).await?;
                ctx.message(&v, "Deleted")
            }
        },
    }
}
