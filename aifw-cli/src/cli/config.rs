//! Named contexts (`config.toml`) and their secrets (`credentials.toml`,
//! mode 0600) under the CLI config directory.
//!
//! ```toml
//! # config.toml
//! current = "fw1"
//! [contexts.fw1]
//! url = "https://10.0.0.1:8080"
//! pin = "ab12…"              # SHA-256 of the API's leaf certificate
//! ```
//! Secrets never go in `config.toml`, so it can be shared or committed.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "config.toml";
pub const CREDENTIALS_FILE: &str = "credentials.toml";

/// One saved appliance.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextEntry {
    pub url: String,
    /// Pinned SHA-256 leaf-certificate fingerprint (https only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// Default output format for this context (`table`, `json`, `yaml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, ContextEntry>,
}

/// Secret material for one context.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_expires_at: Option<String>,
    /// Username the session belongs to (display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

pub type Credentials = BTreeMap<String, Credential>;

/// Context names: letters, digits, `-`, `_`, `.` — they are TOML keys and
/// show up in tables.
pub fn validate_context_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(super::exit::CliError::Usage(format!(
            "invalid context name '{name}': use 1-64 letters, digits, '-', '_' or '.'"
        ))
        .into());
    }
    Ok(())
}

/// Default config directory: `$AIFW_CONFIG_DIR`, else `$XDG_CONFIG_HOME/aifw`,
/// else `$HOME/.config/aifw`.
pub fn default_config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("AIFW_CONFIG_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(x).join("aifw");
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/root"), PathBuf::from);
    home.join(".config").join("aifw")
}

/// The config directory and the two files in it.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load_config(&self) -> anyhow::Result<Config> {
        read_toml(&self.dir.join(CONFIG_FILE))
    }

    pub fn save_config(&self, cfg: &Config) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(cfg).context("serializing config")?;
        write_atomic(&self.dir.join(CONFIG_FILE), text.as_bytes(), 0o644)
    }

    pub fn load_credentials(&self) -> anyhow::Result<Credentials> {
        read_toml(&self.dir.join(CREDENTIALS_FILE))
    }

    pub fn save_credentials(&self, creds: &Credentials) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(creds).context("serializing credentials")?;
        write_atomic(&self.dir.join(CREDENTIALS_FILE), text.as_bytes(), 0o600)
    }

    pub fn credential(&self, context: &str) -> anyhow::Result<Option<Credential>> {
        Ok(self.load_credentials()?.remove(context))
    }

    pub fn set_credential(&self, context: &str, cred: Credential) -> anyhow::Result<()> {
        let mut all = self.load_credentials()?;
        all.insert(context.to_string(), cred);
        self.save_credentials(&all)
    }

    pub fn remove_credential(&self, context: &str) -> anyhow::Result<bool> {
        let mut all = self.load_credentials()?;
        let removed = all.remove(context).is_some();
        if removed {
            self.save_credentials(&all)?;
        }
        Ok(removed)
    }
}

fn read_toml<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> anyhow::Result<T> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash never leaves a half-written
/// file (a truncated credentials file would lose a rotated refresh token).
/// The directory is created 0700.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    // Unpredictable name + create_new (O_CREAT|O_EXCL): never opens an
    // existing file or a planted symlink.
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        uuid::Uuid::new_v4().simple()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // `mode` on open is masked by umask; set it explicitly.
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aifw-cli-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn missing_files_are_empty() {
        let s = Store::new(tmpdir("missing"));
        assert_eq!(s.load_config().unwrap(), Config::default());
        assert!(s.load_credentials().unwrap().is_empty());
    }

    #[test]
    fn round_trip_and_permissions() {
        let dir = tmpdir("rt");
        let s = Store::new(&dir);
        let mut cfg = Config::default();
        cfg.contexts.insert(
            "fw1".into(),
            ContextEntry {
                url: "https://10.0.0.1:8080".into(),
                pin: Some("ab".repeat(32)),
                output: None,
            },
        );
        cfg.current = Some("fw1".into());
        s.save_config(&cfg).unwrap();
        assert_eq!(s.load_config().unwrap(), cfg);

        s.set_credential(
            "fw1",
            Credential {
                api_key: Some("aifw_x".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            s.credential("fw1").unwrap().unwrap().api_key.as_deref(),
            Some("aifw_x")
        );
        let mode = std::fs::metadata(dir.join(CREDENTIALS_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "credentials must be owner-only");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(dmode & 0o777, 0o700);
        // Secrets never land in config.toml.
        let cfg_text = std::fs::read_to_string(dir.join(CONFIG_FILE)).unwrap();
        assert!(!cfg_text.contains("aifw_x"));

        assert!(s.remove_credential("fw1").unwrap());
        assert!(!s.remove_credential("fw1").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_reset() {
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CONFIG_FILE), "current = [").unwrap();
        assert!(Store::new(&dir).load_config().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn context_names() {
        for ok in ["fw1", "edge-01", "a.b_c"] {
            validate_context_name(ok).unwrap();
        }
        for bad in ["", "has space", "x/y", &"a".repeat(65)] {
            assert!(validate_context_name(bad).is_err(), "{bad}");
        }
    }
}
