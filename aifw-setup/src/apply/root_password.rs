//! Non-interactive root password (unattended seed).

/// Apply the setup configuration: write files, init DB, start services
/// Set the root password non-interactively (unattended seed, #533 Phase 2)
/// via `pw usermod root -h 0` reading the password on stdin — the same
/// mechanism the interactive wizard uses.
#[cfg(target_os = "freebsd")]
pub fn set_root_password_noninteractive(password: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if password.len() < 8 {
        return Err("root_password must be at least 8 characters".to_string());
    }
    let mut child = Command::new("/usr/sbin/pw")
        .args(["usermod", "root", "-h", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn pw: {e}"))?;
    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(password.as_bytes())
            .map_err(|e| format!("write pw stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("pw wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pw usermod root failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Non-FreeBSD stub so the unattended path compiles on dev hosts.
#[cfg(not(target_os = "freebsd"))]
pub fn set_root_password_noninteractive(_password: &str) -> Result<(), String> {
    Err("root password can only be set on FreeBSD".to_string())
}
