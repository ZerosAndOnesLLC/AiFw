//! `aifw context …` — manage saved appliances.

use aifw_client::Client;
use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::config::{ContextEntry, validate_context_name};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, parse, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum ContextCmd {
    /// List saved contexts (* marks the current one)
    #[command(visible_alias = "ls")]
    List,
    /// Make a context the default for later commands
    Use { name: String },
    /// Show one context (default: the current one)
    Show { name: Option<String> },
    /// Save a context without logging in (pair with `aifw login`, or set
    /// AIFW_TOKEN)
    Add {
        name: String,
        /// API URL, e.g. https://10.0.0.1:8080
        #[arg(long)]
        url: String,
        /// Certificate fingerprint to pin (SHA-256 hex)
        #[arg(long = "fingerprint", value_name = "SHA256")]
        fingerprint: Option<String>,
        /// Default output format for this context
        #[arg(long = "default-output", value_name = "FORMAT")]
        default_output: Option<crate::cli::Format>,
    },
    /// Delete a context and its stored credential
    #[command(visible_alias = "rm")]
    Remove {
        name: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Rename a context (its credential moves with it)
    Rename { old: String, new: String },
    /// Re-pin a context's certificate (after the appliance's cert changed).
    /// Without a fingerprint, shows the presented one and asks.
    SetPin {
        name: String,
        /// SHA-256 fingerprint to pin
        fingerprint: Option<String>,
        /// Trust the presented certificate without asking
        #[arg(long)]
        trust_cert: bool,
    },
}

fn format_name(f: crate::cli::Format) -> &'static str {
    match f {
        crate::cli::Format::Table => "table",
        crate::cli::Format::Wide => "wide",
        crate::cli::Format::Json => "json",
        crate::cli::Format::Yaml => "yaml",
    }
}

pub async fn run(ctx: &mut Ctx, cmd: ContextCmd) -> anyhow::Result<()> {
    match cmd {
        ContextCmd::List => list(ctx),
        ContextCmd::Use { name } => {
            let mut cfg = ctx.store.load_config()?;
            if !cfg.contexts.contains_key(&name) {
                return Err(CliError::Usage(format!("unknown context '{name}'")).into());
            }
            cfg.current = Some(name.clone());
            ctx.store.save_config(&cfg)?;
            ctx.message(&Value::Null, &format!("Now using context {name}."))
        }
        ContextCmd::Show { name } => {
            let cfg = ctx.store.load_config()?;
            let name = name
                .or(cfg.current.clone())
                .ok_or_else(|| CliError::Usage("no current context; name one".into()))?;
            let v = context_json(ctx, &name)?;
            ctx.detail(
                &v,
                &[
                    ("Name", "/name"),
                    ("URL", "/url"),
                    ("Pin", "/pin"),
                    ("Auth", "/auth"),
                    ("User", "/username"),
                    ("Output", "/output"),
                    ("Current", "/current"),
                ],
            )
        }
        ContextCmd::Add {
            name,
            url,
            fingerprint,
            default_output,
        } => {
            validate_context_name(&name)?;
            let mut cfg = ctx.store.load_config()?;
            if cfg.contexts.contains_key(&name) {
                return Err(CliError::Usage(format!("context '{name}' already exists")).into());
            }
            let pin = fingerprint.as_deref().map(parse::fingerprint).transpose()?;
            cfg.contexts.insert(
                name.clone(),
                ContextEntry {
                    url: parse::api_url(&url)?,
                    pin,
                    output: default_output.map(|f| format_name(f).to_string()),
                },
            );
            if cfg.current.is_none() {
                cfg.current = Some(name.clone());
            }
            ctx.store.save_config(&cfg)?;
            ctx.message(&Value::Null, &format!("Added context {name}."))
        }
        ContextCmd::Remove { name, yes } => {
            let mut cfg = ctx.store.load_config()?;
            if !cfg.contexts.contains_key(&name) {
                return Err(CliError::Usage(format!("unknown context '{name}'")).into());
            }
            ctx.confirm(
                &format!("Delete context {name} and its stored credential?"),
                yes,
            )?;
            cfg.contexts.remove(&name);
            if cfg.current.as_deref() == Some(name.as_str()) {
                cfg.current = None;
            }
            ctx.store.save_config(&cfg)?;
            ctx.store.remove_credential(&name)?;
            ctx.message(&Value::Null, &format!("Removed context {name}."))
        }
        ContextCmd::Rename { old, new } => {
            validate_context_name(&new)?;
            let mut cfg = ctx.store.load_config()?;
            if cfg.contexts.contains_key(&new) {
                return Err(CliError::Usage(format!("context '{new}' already exists")).into());
            }
            let entry = cfg
                .contexts
                .remove(&old)
                .ok_or_else(|| CliError::Usage(format!("unknown context '{old}'")))?;
            cfg.contexts.insert(new.clone(), entry);
            if cfg.current.as_deref() == Some(old.as_str()) {
                cfg.current = Some(new.clone());
            }
            ctx.store.save_config(&cfg)?;
            if let Some(c) = ctx.store.credential(&old)? {
                ctx.store.set_credential(&new, c)?;
                ctx.store.remove_credential(&old)?;
            }
            ctx.message(&Value::Null, &format!("Renamed context {old} to {new}."))
        }
        ContextCmd::SetPin {
            name,
            fingerprint,
            trust_cert,
        } => {
            let mut cfg = ctx.store.load_config()?;
            let url = cfg
                .contexts
                .get(&name)
                .map(|e| e.url.clone())
                .ok_or_else(|| CliError::Usage(format!("unknown context '{name}'")))?;
            let fp = match fingerprint {
                Some(f) => parse::fingerprint(&f)?,
                None => {
                    let probe = Client::builder(&url).accept_any_cert().build()?;
                    let fp = probe
                        .probe_fingerprint()
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("{url} did not present a certificate"))?;
                    ctx.io.eprintln(&format!(
                        "{url} presents SHA-256 fingerprint\n  {}",
                        parse::fingerprint_display(&fp)
                    ));
                    let no_input = ctx.g.no_input;
                    prompt::require(
                        &mut ctx.io,
                        "Pin this certificate?",
                        trust_cert,
                        no_input,
                        "the fingerprint (or --trust-cert)",
                    )?;
                    fp
                }
            };
            if let Some(e) = cfg.contexts.get_mut(&name) {
                e.pin = Some(fp);
            }
            ctx.store.save_config(&cfg)?;
            ctx.message(
                &Value::Null,
                &format!("Updated the certificate pin for {name}."),
            )
        }
    }
}

fn context_json(ctx: &Ctx, name: &str) -> anyhow::Result<Value> {
    let cfg = ctx.store.load_config()?;
    let e = cfg
        .contexts
        .get(name)
        .ok_or_else(|| CliError::Usage(format!("unknown context '{name}'")))?;
    let cred = ctx.store.credential(name)?;
    let auth = match &cred {
        Some(c) if c.api_key.is_some() => "api-key",
        Some(c) if c.refresh_token.is_some() => "session",
        Some(c) if c.access_token.is_some() => "bearer",
        _ => "none",
    };
    Ok(json!({
        "name": name,
        "url": e.url,
        "pin": e.pin,
        "output": e.output,
        "auth": auth,
        "username": cred.and_then(|c| c.username),
        "current": cfg.current.as_deref() == Some(name),
    }))
}

fn list(ctx: &mut Ctx) -> anyhow::Result<()> {
    let cfg = ctx.store.load_config()?;
    let mut rows = Vec::new();
    for name in cfg.contexts.keys() {
        let mut v = context_json(ctx, name)?;
        v["marker"] = json!(if v["current"] == json!(true) { "*" } else { "" });
        v["pin_short"] = json!(
            v["pin"]
                .as_str()
                .map(|p| format!("{}…", &p[..16.min(p.len())]))
        );
        rows.push(v);
    }
    let v = Value::Array(rows);
    if ctx.format().is_structured() {
        let clean: Vec<Value> = v
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let mut r = r.clone();
                if let Some(o) = r.as_object_mut() {
                    o.remove("marker");
                    o.remove("pin_short");
                }
                r
            })
            .collect();
        return ctx.raw(&Value::Array(clean));
    }
    if v.as_array().is_some_and(Vec::is_empty) {
        ctx.io
            .eprintln("No contexts. Add one with `aifw login <url>`.");
        return Ok(());
    }
    ctx.list(
        &v,
        &[
            col("CURRENT", "/marker"),
            col("NAME", "/name"),
            col("URL", "/url"),
            col("AUTH", "/auth"),
            col("USER", "/username"),
            col("PIN", "/pin_short"),
            wide("OUTPUT", "/output"),
        ],
    )
}
