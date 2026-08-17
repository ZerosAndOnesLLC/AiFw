//! Filesystem helpers for secret-bearing scratch files.
//!
//! Several code paths hand a secret (WireGuard private key / PSK, a config
//! under validation) to an external tool via a path in `/tmp`. Writing with
//! `fs::write` and then `chmod 600` leaves two holes (SEC-L5 #320, #67):
//! the file is world-readable for an instant, and a pre-planted symlink at
//! that path would be followed. [`write_private_new`] closes both by
//! creating with `O_CREAT | O_EXCL` and mode `0600` in one syscall — if
//! anything already exists at the path the call fails instead of
//! following it.

use std::path::Path;

use crate::error::{AifwError, Result};

/// Create `path` with mode 0600, failing if it already exists (so a
/// pre-planted file or symlink is never followed), and write `contents`.
///
/// On non-Unix targets the mode bits are not applied but the
/// create-new semantics still hold.
pub async fn write_private_new(path: impl AsRef<Path>, contents: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let path = path.as_ref();
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    tokio::fs::OpenOptions::mode(&mut opts, 0o600);
    let mut f = opts.open(path).await.map_err(|e| {
        AifwError::Io(std::io::Error::new(
            e.kind(),
            format!("create {}: {e}", path.display()),
        ))
    })?;
    f.write_all(contents).await?;
    f.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aifw-secure-fs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[tokio::test]
    async fn creates_with_0600_and_content() {
        let p = scratch("a.key");
        let _ = std::fs::remove_file(&p);
        write_private_new(&p, b"secret").await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode was {mode:o}");
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[tokio::test]
    async fn refuses_existing_path() {
        let p = scratch("b.key");
        std::fs::write(&p, b"planted").unwrap();
        let err = write_private_new(&p, b"secret").await.unwrap_err();
        assert!(err.to_string().contains("create"), "got: {err}");
        // Pre-existing content untouched.
        assert_eq!(std::fs::read(&p).unwrap(), b"planted");
        std::fs::remove_file(&p).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_symlink_at_path() {
        let target = scratch("c.target");
        let link = scratch("c.link");
        std::fs::write(&target, b"victim").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_private_new(&link, b"secret").await.is_err());
        // The symlink target must not have been overwritten.
        assert_eq!(std::fs::read(&target).unwrap(), b"victim");
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&target).unwrap();
    }
}
