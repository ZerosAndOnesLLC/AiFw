//! `aifw login`, `aifw logout`, `aifw whoami`.

use aifw_client::{Client, LoginOutcome, credential_from_token};
use clap::Args;
use serde_json::{Value, json};

use crate::cli::config::{ContextEntry, Credential, validate_context_name};
use crate::cli::connect::{self, LOCAL_TARGET};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, onbox, parse, prompt};

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// API URL (default: the selected context's URL, else this appliance)
    pub url: Option<String>,
    /// Username (prompted when omitted)
    #[arg(short, long)]
    pub username: Option<String>,
    /// Read the password from stdin instead of prompting
    #[arg(long, conflicts_with = "api_key_stdin")]
    pub password_stdin: bool,
    /// Authenticate with an API key read from stdin instead of a password
    #[arg(long)]
    pub api_key_stdin: bool,
    /// TOTP or recovery code (prompted when the account needs one)
    #[arg(long, value_name = "CODE")]
    pub totp: Option<String>,
    /// Trust and pin the certificate the server presents without asking
    /// (prefer --pin with a fingerprint you verified out of band)
    #[arg(long)]
    pub trust_cert: bool,
}

/// Context name derived from a URL: `local` for loopback, else the host.
fn name_for(url: &str) -> String {
    if onbox::is_loopback(url) {
        return LOCAL_TARGET.to_string();
    }
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_matches(['[', ']']).replace(':', "-"))
        })
        .unwrap_or_else(|| "default".into())
}

/// Decide the certificate pin for `url` (https only): an explicit `--pin`,
/// the context's existing pin, the on-box certificate, or trust-on-first-use
/// after showing the fingerprint.
async fn decide_pin(
    ctx: &mut Ctx,
    url: &str,
    existing: Option<&ContextEntry>,
    trust_cert: bool,
) -> anyhow::Result<Option<String>> {
    if !url.starts_with("https://") {
        return Ok(None);
    }
    if let Some(p) = ctx.g.pin.as_deref() {
        return Ok(Some(parse::fingerprint(p)?));
    }
    if let Some(e) = existing.filter(|e| e.url == url)
        && let Some(p) = &e.pin
    {
        return Ok(Some(p.clone()));
    }
    if onbox::is_loopback(url)
        && let Some(fp) = aifw_client::tls::fingerprint_pem_file(&ctx.onbox.cert)
    {
        return Ok(Some(fp));
    }
    let probe = Client::builder(url).accept_any_cert().build()?;
    let Some(fp) = probe.probe_fingerprint().await? else {
        return Err(anyhow::anyhow!("{url} did not present a certificate"));
    };
    let no_input = ctx.g.no_input;
    ctx.io.eprintln(&format!(
        "The server at {url} presented a certificate with SHA-256 fingerprint\n  {}",
        parse::fingerprint_display(&fp)
    ));
    if !prompt::confirm(
        &mut ctx.io,
        "Trust this certificate and pin it for this context?",
        trust_cert,
        no_input,
        "--pin <fingerprint> (or --trust-cert)",
    )? {
        return Err(CliError::Aborted(
            "certificate not trusted; verify the fingerprint on the appliance (Settings → TLS) and pass --pin".into(),
        )
        .into());
    }
    Ok(Some(fp))
}

pub async fn login(ctx: &mut Ctx, a: LoginArgs) -> anyhow::Result<()> {
    let cfg = ctx.store.load_config()?;
    let names = ctx.g.context_names();
    if names.len() > 1 {
        return Err(CliError::Usage("log in to one context at a time".into()).into());
    }
    let named = names.into_iter().next();
    let existing_name = named.clone().or_else(|| cfg.current.clone());
    let existing = existing_name.as_ref().and_then(|n| cfg.contexts.get(n));

    let url = match a.url.as_deref().or(ctx.g.url.as_deref()) {
        Some(u) => parse::api_url(u)?,
        None => existing
            .map(|e| e.url.clone())
            .unwrap_or_else(|| aifw_client::DEFAULT_LOCAL_URL.to_string()),
    };
    let name = named.unwrap_or_else(|| match existing {
        Some(e) if e.url == url => existing_name.clone().unwrap_or_else(|| name_for(&url)),
        _ => name_for(&url),
    });
    validate_context_name(&name)?;
    if name == LOCAL_TARGET && !onbox::is_loopback(&url) {
        return Err(CliError::Usage(
            "the context name `local` is reserved for this appliance; pick another --context"
                .into(),
        )
        .into());
    }
    let existing = cfg.contexts.get(&name).cloned();

    let pin = decide_pin(ctx, &url, existing.as_ref(), a.trust_cert).await?;
    let mut b = Client::builder(&url).label(&name);
    if let Some(p) = &pin {
        b = b.pin(p);
    }
    let client = b.build()?;
    let no_input = ctx.g.no_input;

    let cred = if a.api_key_stdin {
        let key = prompt::read_all(&mut ctx.io)?.trim().to_string();
        if key.is_empty() {
            return Err(CliError::Usage("no API key on stdin".into()).into());
        }
        client.set_auth(credential_from_token(&key)).await;
        Credential {
            api_key: Some(key),
            ..Default::default()
        }
    } else {
        let username = match a.username {
            Some(u) => u,
            None => prompt::line(&mut ctx.io, "Username: ", no_input, "username")?,
        };
        let password = if a.password_stdin {
            prompt::read_line_raw(&mut ctx.io)?
                .trim_end_matches(['\r', '\n'])
                .to_string()
        } else {
            prompt::secret(&mut ctx.io, "Password: ", no_input, "password")?
        };
        let tokens = match client.login(&username, &password).await? {
            LoginOutcome::Tokens(t) => t,
            LoginOutcome::TotpRequired => {
                let code = match a.totp {
                    Some(c) => c,
                    None => prompt::line(
                        &mut ctx.io,
                        "TOTP or recovery code: ",
                        no_input,
                        "TOTP code",
                    )?,
                };
                client.totp_login(&username, &password, &code).await?
            }
        };
        client
            .set_auth(aifw_client::Auth::Session(
                aifw_client::Session::from_tokens(&tokens),
            ))
            .await;
        Credential {
            access_token: Some(tokens.access_token),
            refresh_token: Some(tokens.refresh_token),
            access_expires_at: tokens.access_expires_at,
            username: Some(username),
            ..Default::default()
        }
    };

    // Prove the credential works before saving anything.
    let me = client.get("/auth/me").await?;
    let mut cred = cred;
    cred.username = me
        .get("username")
        .and_then(Value::as_str)
        .map(str::to_string);

    let mut cfg = ctx.store.load_config()?;
    let entry = cfg.contexts.entry(name.clone()).or_default();
    entry.url = url.clone();
    entry.pin = pin;
    cfg.current = Some(name.clone());
    ctx.store.save_config(&cfg)?;
    ctx.store.set_credential(&name, cred)?;

    let summary = json!({
        "context": name,
        "url": url,
        "username": me.get("username"),
        "role": me.get("role"),
    });
    if ctx.format().is_structured() {
        return ctx.raw(&summary);
    }
    ctx.io.println(&format!(
        "Logged in to {name} ({url}) as {} [{}]",
        me.get("username").and_then(Value::as_str).unwrap_or("?"),
        me.get("role").and_then(Value::as_str).unwrap_or("?"),
    ));
    Ok(())
}

pub async fn logout(ctx: &mut Ctx) -> anyhow::Result<()> {
    let target = ctx.target()?;
    let Some(name) = target.session_context.clone().or_else(|| {
        let cfg = ctx.store.load_config().ok()?;
        cfg.contexts
            .contains_key(&target.name)
            .then(|| target.name.clone())
    }) else {
        return Err(CliError::Usage(format!(
            "nothing stored for {}; pass --context to log out of a saved context",
            target.name
        ))
        .into());
    };
    if ctx.store.credential(&name)?.is_none() {
        ctx.io.eprintln(&format!("Not logged in to {name}."));
        return Ok(());
    }
    // Revoke server-side first (best effort: the appliance may be gone).
    let client = connect::client(&target, &ctx.store, None)?;
    if let Err(e) = client.logout().await {
        ctx.io
            .eprintln(&format!("warning: server-side logout failed: {e}"));
    }
    ctx.store.remove_credential(&name)?;
    ctx.message(&Value::Null, &format!("Logged out of {name}."))
}

pub async fn whoami(ctx: &mut Ctx) -> anyhow::Result<()> {
    let target = ctx.target()?;
    let client = connect::client(
        &target,
        &ctx.store,
        ctx.g.request_timeout.map(std::time::Duration::from_secs),
    )?;
    let mut me = client.get("/auth/me").await?;
    if let Some(obj) = me.as_object_mut() {
        obj.insert("context".into(), json!(target.name));
        obj.insert("url".into(), json!(target.url));
        obj.insert("auth".into(), json!(target.auth.kind()));
        obj.insert("auth_source".into(), json!(target.auth_source));
    }
    let wide = ctx.format() == crate::cli::Format::Wide;
    let mut fields = vec![
        ("Context", "/context"),
        ("URL", "/url"),
        ("User", "/username"),
        ("Role", "/role"),
        ("Auth", "/auth"),
        ("Credential", "/auth_source"),
        ("2FA", "/totp_enabled"),
    ];
    if wide {
        fields.push(("Permissions", "/permissions"));
    }
    ctx.detail(&me, &fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_names() {
        assert_eq!(name_for("https://127.0.0.1:8080"), "local");
        assert_eq!(name_for("https://fw1.example.com:8080"), "fw1.example.com");
        assert_eq!(name_for("https://10.0.0.1"), "10.0.0.1");
        assert_eq!(name_for("https://[fd00::1]:8080"), "fd00--1");
    }
}
