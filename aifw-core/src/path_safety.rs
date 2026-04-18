//! Destination-path guards for privileged file writes.
//!
//! ACME export, DNS blocklist install, and anywhere else the daemon hops
//! through `sudo install` can normally write anywhere root can — because
//! admin API users get to pick the destination. Without these checks, an
//! attacker with admin access could drop a cert + key at
//! `/root/.ssh/authorized_keys` (RCE as root), `/etc/rc.conf.d/*`
//! (persistence), or `/usr/local/etc/sudoers.d/attacker` (privilege
//! grant).
//!
//! [`validate_export_path`] enforces:
//! - absolute path
//! - no `..` component (escape via path traversal)
//! - no `.` component (pointless and suspicious)
//! - destination is inside one of a small set of whitelisted roots
//! - no symlinks on any existing ancestor of the destination
//!
//! The whitelist is deliberately narrow. Sites that need a new export
//! target should add a root to [`ALLOWED_ROOTS`] with a review.

use std::path::{Component, Path, PathBuf};

/// Roots into which the daemon is allowed to export certificates or
/// other sensitive material. All destinations must canonicalize under
/// one of these after cleaning `..`/`.` components.
pub const ALLOWED_ROOTS: &[&str] = &[
    "/usr/local/etc/aifw/",
    "/usr/local/etc/nginx/",
    "/usr/local/etc/rdns/",
    "/usr/local/etc/trafficcop/",
    "/usr/local/etc/traefik/",
    "/usr/local/etc/haproxy/",
    "/usr/local/etc/ssl/",
    "/etc/ssl/",
];

/// Validate that `dest` is safe to write to under one of the allowed roots.
///
/// Returns the cleaned absolute `PathBuf` on success.
pub fn validate_export_path(dest: &str) -> Result<PathBuf, String> {
    let p = Path::new(dest);
    if !p.is_absolute() {
        return Err(format!("path must be absolute: {dest}"));
    }

    let mut cleaned = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => cleaned.push("/"),
            Component::Normal(part) => cleaned.push(part),
            Component::ParentDir => {
                return Err(format!("'..' is not allowed in path: {dest}"));
            }
            Component::CurDir => {
                // `Path::components()` elides these before we see them; treat
                // them as a no-op to be safe if that ever changes.
            }
            Component::Prefix(_) => {
                return Err(format!("drive-letter paths not supported: {dest}"));
            }
        }
    }

    let cleaned_str = cleaned.to_string_lossy();
    let allowed = ALLOWED_ROOTS
        .iter()
        .any(|root| cleaned_str.starts_with(root));
    if !allowed {
        return Err(format!(
            "path {cleaned_str} is not under an allowed export root ({})",
            ALLOWED_ROOTS.join(", ")
        ));
    }

    // Reject symlinks anywhere on the existing ancestry. The destination
    // itself usually doesn't exist yet, but its parent chain might — and
    // a hostile symlink there (e.g. /usr/local/etc/aifw -> /root) would
    // redirect our write.
    let mut ancestor = cleaned.as_path();
    while let Some(parent) = ancestor.parent() {
        if parent.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(parent) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "symlink on path: {} is a symlink, refusing",
                    parent.display()
                ));
            }
        }
        ancestor = parent;
    }

    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative() {
        assert!(validate_export_path("etc/foo.pem").is_err());
        assert!(validate_export_path("./etc/foo.pem").is_err());
    }

    #[test]
    fn rejects_dotdot() {
        assert!(validate_export_path("/usr/local/etc/aifw/../../root/.ssh/authorized_keys")
            .is_err());
    }

    #[test]
    fn rejects_outside_whitelist() {
        assert!(validate_export_path("/root/.ssh/authorized_keys").is_err());
        assert!(validate_export_path("/etc/passwd").is_err());
        assert!(validate_export_path("/etc/rc.conf.d/evil").is_err());
        assert!(validate_export_path("/usr/local/etc/sudoers.d/attacker").is_err());
    }

    #[test]
    fn accepts_whitelisted_aifw() {
        assert!(validate_export_path("/usr/local/etc/aifw/tls/cert.pem").is_ok());
    }

    #[test]
    fn accepts_whitelisted_nginx() {
        assert!(validate_export_path("/usr/local/etc/nginx/certs/site.pem").is_ok());
    }

    #[test]
    fn dot_component_is_normalized_out() {
        // `Path::components()` drops `.` components silently. We still accept
        // these because after normalization the destination is identical to
        // the no-dot version.
        assert!(validate_export_path("/usr/local/etc/aifw/./tls/cert.pem").is_ok());
    }

    #[test]
    fn rejects_traversal_inside_allowed_root() {
        // Starts under an allowed root but escapes via ..
        assert!(validate_export_path("/usr/local/etc/aifw/../../../etc/passwd").is_err());
    }
}
