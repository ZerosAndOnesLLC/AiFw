//! Paths and credentials available when the CLI runs on the appliance.

use std::path::{Path, PathBuf};

/// Files the CLI uses on the appliance. Overridable so tests (and odd
/// layouts) don't depend on `/usr/local/etc/aifw`.
#[derive(Debug, Clone)]
pub struct OnBox {
    /// The API's serving certificate — the loopback pin.
    pub cert: PathBuf,
    /// Root-only key the CLI mints for itself (`aifw local cli-key`).
    pub cli_key: PathBuf,
    /// The daemon loopback key (`system` role: cluster/HA only).
    pub daemon_key: PathBuf,
    /// The appliance database (needed to mint `cli_key`).
    pub db: PathBuf,
}

impl Default for OnBox {
    fn default() -> Self {
        Self {
            cert: PathBuf::from(aifw_client::tls::LOCAL_API_CERT_PATH),
            cli_key: PathBuf::from("/usr/local/etc/aifw/cli.key"),
            daemon_key: PathBuf::from("/usr/local/etc/aifw/daemon.key"),
            db: PathBuf::from("/var/db/aifw/aifw.db"),
        }
    }
}

/// Read a key file; `None` if missing, unreadable or empty.
pub fn read_key(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// True when `url` points at this machine.
pub fn is_loopback(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some_and(|h| matches!(h.as_str(), "127.0.0.1" | "localhost" | "::1" | "[::1]"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("https://127.0.0.1:8080"));
        assert!(is_loopback("http://localhost:18080/"));
        assert!(is_loopback("https://[::1]:8080"));
        assert!(!is_loopback("https://10.0.0.1:8080"));
        assert!(!is_loopback("garbage"));
    }

    #[test]
    fn key_files() {
        let p = std::env::temp_dir().join(format!("aifw-cli-key-{}", std::process::id()));
        assert_eq!(read_key(&p), None);
        std::fs::write(&p, "aifw_abc\n").unwrap();
        assert_eq!(read_key(&p).as_deref(), Some("aifw_abc"));
        std::fs::write(&p, "  \n").unwrap();
        assert_eq!(read_key(&p), None);
        let _ = std::fs::remove_file(&p);
    }
}
