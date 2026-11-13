//! Resolve which appliance to talk to and how to authenticate, then build
//! an [`aifw_client::Client`].
//!
//! Precedence: flags/env (`--url`, `--api-key`, `--pin`) > the selected
//! context (`--context`, `AIFW_CONTEXT`, `current` in config.toml) > the
//! on-box default (`https://127.0.0.1:8080`, pinned to the API's own
//! certificate, authenticated with the root CLI key).

use std::sync::Arc;
use std::time::Duration;

use aifw_client::{Auth, Client, Session, SessionStore, TokenPair, credential_from_token};

use super::config::{Credential, Store};
use super::exit::CliError;
use super::global::GlobalArgs;
use super::onbox::{self, OnBox};

/// Display name for the implicit on-box target.
pub const LOCAL_TARGET: &str = "local";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Normal WebPKI validation (or plain http).
    WebPki,
    Pin(String),
    /// Pin to the certificate in this file (on-box).
    PinFile(std::path::PathBuf),
}

/// Where a command goes and with which credential.
#[derive(Debug, Clone)]
pub struct Target {
    /// Context name, or [`LOCAL_TARGET`], or the URL when given ad hoc.
    pub name: String,
    pub url: String,
    pub trust: Trust,
    pub auth: Auth,
    /// Context whose credentials file receives refreshed sessions.
    pub session_context: Option<String>,
    /// Where the credential came from (for `whoami`).
    pub auth_source: String,
    /// Context default output format.
    pub output: Option<String>,
}

fn trust_for(url: &str, pin: Option<&str>, onbox: &OnBox) -> Trust {
    if let Some(p) = pin {
        return Trust::Pin(p.to_string());
    }
    if url.starts_with("https://") && onbox::is_loopback(url) {
        return Trust::PinFile(onbox.cert.clone());
    }
    Trust::WebPki
}

fn auth_from_credential(c: &Credential) -> Auth {
    if let Some(k) = c.api_key.as_deref() {
        return credential_from_token(k);
    }
    match (&c.access_token, &c.refresh_token) {
        (Some(a), Some(r)) => Auth::Session(Session::from_tokens(&TokenPair {
            access_token: a.clone(),
            refresh_token: r.clone(),
            access_expires_at: c.access_expires_at.clone(),
            refresh_expires_at: None,
        })),
        (Some(a), None) => Auth::Bearer(a.clone()),
        _ => Auth::None,
    }
}

/// Credential for the on-box API when nothing else was given: the root CLI
/// key (minted on demand when running as root), else the daemon key.
pub fn onbox_auth(onbox: &OnBox) -> (Auth, String) {
    if let Some(k) = onbox::read_key(&onbox.cli_key) {
        return (
            credential_from_token(&k),
            onbox.cli_key.display().to_string(),
        );
    }
    if onbox::is_root() && onbox.db.exists() {
        match crate::commands::local::provision_cli_key(onbox) {
            Ok(k) => {
                return (
                    credential_from_token(&k),
                    onbox.cli_key.display().to_string(),
                );
            }
            Err(e) => tracing::warn!(error = %e, "could not mint the on-box CLI key"),
        }
    }
    if let Some(k) = onbox::read_key(&onbox.daemon_key) {
        return (
            credential_from_token(&k),
            onbox.daemon_key.display().to_string(),
        );
    }
    (Auth::None, "none".into())
}

/// Resolve the target for one context name (`None` = the default).
pub fn resolve(
    g: &GlobalArgs,
    store: &Store,
    onbox: &OnBox,
    context: Option<&str>,
) -> anyhow::Result<Target> {
    let flag_auth = g
        .api_key
        .as_deref()
        .map(credential_from_token)
        .filter(|a| *a != Auth::None);

    // Ad-hoc URL (flag or AIFW_API_URL) wins over contexts.
    if let Some(url) = g.url.as_deref().filter(|u| !u.is_empty()) {
        let (auth, source) = match flag_auth {
            Some(a) => (a, "--api-key/AIFW_TOKEN".to_string()),
            None if onbox::is_loopback(url) => onbox_auth(onbox),
            None => (Auth::None, "none".into()),
        };
        return Ok(Target {
            name: url.to_string(),
            url: url.to_string(),
            trust: trust_for(url, g.pin.as_deref(), onbox),
            auth,
            session_context: None,
            auth_source: source,
            output: None,
        });
    }

    let cfg = store.load_config()?;
    let name = context.map(str::to_string).or_else(|| cfg.current.clone());
    if let Some(name) = name {
        let entry = cfg.contexts.get(&name).ok_or_else(|| {
            CliError::Usage(format!(
                "unknown context '{name}' (see `aifw context list`)"
            ))
        })?;
        let (auth, source, session_context) = match flag_auth {
            Some(a) => (a, "--api-key/AIFW_TOKEN".to_string(), None),
            None => match store.credential(&name)? {
                Some(c) => {
                    let a = auth_from_credential(&c);
                    let src = format!(
                        "{} ({})",
                        store.dir().join(super::config::CREDENTIALS_FILE).display(),
                        a.kind()
                    );
                    (a, src, Some(name.clone()))
                }
                None if onbox::is_loopback(&entry.url) => {
                    let (a, s) = onbox_auth(onbox);
                    (a, s, None)
                }
                None => (Auth::None, "none".into(), None),
            },
        };
        let pin = g.pin.as_deref().or(entry.pin.as_deref());
        return Ok(Target {
            trust: trust_for(&entry.url, pin, onbox),
            url: entry.url.clone(),
            name,
            auth,
            session_context,
            auth_source: source,
            output: entry.output.clone(),
        });
    }

    let url = aifw_client::DEFAULT_LOCAL_URL.to_string();
    let (auth, source) = match flag_auth {
        Some(a) => (a, "--api-key/AIFW_TOKEN".to_string()),
        None => onbox_auth(onbox),
    };
    Ok(Target {
        name: LOCAL_TARGET.into(),
        trust: trust_for(&url, g.pin.as_deref(), onbox),
        url,
        auth,
        session_context: None,
        auth_source: source,
        output: None,
    })
}

/// Persists rotated session tokens for a context.
struct ContextSessionStore {
    store: Store,
    context: String,
}

impl SessionStore for ContextSessionStore {
    fn save(&self, t: &TokenPair) -> Result<(), String> {
        let mut c = self
            .store
            .credential(&self.context)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        c.api_key = None;
        c.access_token = Some(t.access_token.clone());
        c.refresh_token = Some(t.refresh_token.clone());
        c.access_expires_at = t.access_expires_at.clone();
        self.store
            .set_credential(&self.context, c)
            .map_err(|e| e.to_string())
    }
}

/// Build a client for a resolved target.
pub fn client(target: &Target, store: &Store, timeout: Option<Duration>) -> anyhow::Result<Client> {
    let mut b = Client::builder(&target.url)
        .auth(target.auth.clone())
        .label(&target.name);
    b = match &target.trust {
        Trust::WebPki => b,
        Trust::Pin(p) => b.pin(p),
        Trust::PinFile(f) => b.pin_file(f),
    };
    if let Some(t) = timeout {
        b = b.timeout(t);
    }
    if let Some(ctx) = &target.session_context {
        b = b.session_store(Arc::new(ContextSessionStore {
            store: store.clone(),
            context: ctx.clone(),
        }));
    }
    Ok(b.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config::{Config, ContextEntry};

    fn setup(tag: &str) -> (Store, OnBox) {
        let dir = std::env::temp_dir().join(format!("aifw-cli-conn-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let onbox = OnBox {
            cert: dir.join("cert.pem"),
            cli_key: dir.join("cli.key"),
            daemon_key: dir.join("daemon.key"),
            db: dir.join("missing.db"),
        };
        (Store::new(dir.join("cfg")), onbox)
    }

    #[test]
    fn default_is_onbox_loopback() {
        let (store, onbox) = setup("default");
        let t = resolve(&GlobalArgs::default(), &store, &onbox, None).unwrap();
        assert_eq!(t.name, LOCAL_TARGET);
        assert_eq!(t.url, aifw_client::DEFAULT_LOCAL_URL);
        assert_eq!(t.trust, Trust::PinFile(onbox.cert.clone()));
        assert_eq!(t.auth, Auth::None);

        std::fs::create_dir_all(onbox.cli_key.parent().unwrap()).unwrap();
        std::fs::write(&onbox.daemon_key, "ab".repeat(32)).unwrap();
        let t = resolve(&GlobalArgs::default(), &store, &onbox, None).unwrap();
        assert!(matches!(t.auth, Auth::ApiKey(_)), "daemon key fallback");
        std::fs::write(&onbox.cli_key, "aifw_cli\n").unwrap();
        let t = resolve(&GlobalArgs::default(), &store, &onbox, None).unwrap();
        assert_eq!(t.auth, Auth::ApiKey("aifw_cli".into()), "cli.key preferred");
    }

    #[test]
    fn flags_override_everything() {
        let (store, onbox) = setup("flags");
        let g = GlobalArgs {
            url: Some("https://10.9.9.9:8080".into()),
            api_key: Some("aifw_flag".into()),
            pin: Some("cd".repeat(32)),
            ..Default::default()
        };
        let t = resolve(&g, &store, &onbox, None).unwrap();
        assert_eq!(t.url, "https://10.9.9.9:8080");
        assert_eq!(t.auth, Auth::ApiKey("aifw_flag".into()));
        assert_eq!(t.trust, Trust::Pin("cd".repeat(32)));
        // Remote URL with no pin uses WebPKI; no on-box key is sent remotely.
        let g = GlobalArgs {
            url: Some("https://fw.example.com".into()),
            ..Default::default()
        };
        let t = resolve(&g, &store, &onbox, None).unwrap();
        assert_eq!(t.trust, Trust::WebPki);
        assert_eq!(t.auth, Auth::None);
    }

    #[test]
    fn contexts_and_credentials() {
        let (store, onbox) = setup("ctx");
        let mut cfg = Config::default();
        cfg.contexts.insert(
            "a".into(),
            ContextEntry {
                url: "https://10.0.0.1:8080".into(),
                pin: Some("ef".repeat(32)),
                output: Some("json".into()),
            },
        );
        cfg.contexts.insert(
            "b".into(),
            ContextEntry {
                url: "http://10.0.0.2:8080".into(),
                pin: None,
                output: None,
            },
        );
        cfg.current = Some("a".into());
        store.save_config(&cfg).unwrap();
        store
            .set_credential(
                "a",
                Credential {
                    access_token: Some("at".into()),
                    refresh_token: Some("rt".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .set_credential(
                "b",
                Credential {
                    api_key: Some("aifw_b".into()),
                    ..Default::default()
                },
            )
            .unwrap();

        let t = resolve(&GlobalArgs::default(), &store, &onbox, None).unwrap();
        assert_eq!(t.name, "a");
        assert!(matches!(t.auth, Auth::Session(_)));
        assert_eq!(t.session_context.as_deref(), Some("a"));
        assert_eq!(t.trust, Trust::Pin("ef".repeat(32)));
        assert_eq!(t.output.as_deref(), Some("json"));

        let t = resolve(&GlobalArgs::default(), &store, &onbox, Some("b")).unwrap();
        assert_eq!(t.auth, Auth::ApiKey("aifw_b".into()));
        assert_eq!(t.trust, Trust::WebPki);

        let err = resolve(&GlobalArgs::default(), &store, &onbox, Some("zzz")).unwrap_err();
        assert_eq!(crate::cli::exit::code_for(&err), crate::cli::exit::USAGE);

        // --api-key beats the stored credential and is not persisted.
        let g = GlobalArgs {
            api_key: Some("aifw_override".into()),
            ..Default::default()
        };
        let t = resolve(&g, &store, &onbox, Some("a")).unwrap();
        assert_eq!(t.auth, Auth::ApiKey("aifw_override".into()));
        assert_eq!(t.session_context, None);
    }

    #[test]
    fn session_store_persists_rotation() {
        let (store, _) = setup("sess");
        store
            .set_credential(
                "a",
                Credential {
                    username: Some("admin".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        let s = ContextSessionStore {
            store: store.clone(),
            context: "a".into(),
        };
        s.save(&TokenPair {
            access_token: "a2".into(),
            refresh_token: "r2".into(),
            access_expires_at: None,
            refresh_expires_at: None,
        })
        .unwrap();
        let c = store.credential("a").unwrap().unwrap();
        assert_eq!(c.refresh_token.as_deref(), Some("r2"));
        assert_eq!(c.username.as_deref(), Some("admin"), "username kept");
    }
}
