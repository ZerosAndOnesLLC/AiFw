//! Host-level steps: service user, devfs, TLS cert, sshd, directories, rc.conf helpers.

use crate::config::SetupConfig;
use crate::console;

/// Create the aifw service user and group if they don't exist
pub(super) fn create_service_user() -> Result<(), String> {
    #[cfg(target_os = "freebsd")]
    {
        // Check if user already exists
        let status = std::process::Command::new("pw")
            .args(["usershow", "aifw"])
            .output();
        if let Ok(out) = status {
            if out.status.success() {
                return Ok(()); // user exists
            }
        }
        // Create group
        run_best_effort("pw", &["groupadd", "aifw", "-g", "470"]);
        // Create user: no login shell, no home, system account
        let out = std::process::Command::new("pw")
            .args([
                "useradd",
                "aifw",
                "-u",
                "470",
                "-g",
                "aifw",
                "-d",
                "/nonexistent",
                "-s",
                "/usr/sbin/nologin",
                "-c",
                "AiFw Service Account",
            ])
            .output()
            .map_err(|e| format!("failed to create aifw user: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("already exists") {
                return Err(format!("pw useradd failed: {stderr}"));
            }
        }
    }
    Ok(())
}

/// Configure devfs rules so the aifw group can access /dev/pf and /dev/bpf*
pub(super) fn configure_devfs() -> Result<(), String> {
    #[cfg(target_os = "freebsd")]
    {
        // Write rules directly to /etc/devfs.rules (the canonical location)
        let devfs_rules_path = "/etc/devfs.rules";
        let existing = std::fs::read_to_string(devfs_rules_path).unwrap_or_default();
        if !existing.contains("aifw_devfs") {
            let mut content = existing;
            if !content.ends_with('\n') && !content.is_empty() {
                content.push('\n');
            }
            content.push_str("\n# AiFw device access rules\n");
            content.push_str("[aifw_devfs=10]\n");
            content.push_str("add path 'pf' mode 0660 group aifw\n");
            content.push_str("add path 'bpf*' mode 0660 group aifw\n");
            write_file(devfs_rules_path, &content)?;
        }

        // Enable the ruleset in rc.conf
        run_best_effort("sysrc", &["devfs_system_ruleset=aifw_devfs"]);

        // Apply immediately
        run_best_effort("service", &["devfs", "restart"]);
    }
    Ok(())
}

/// Generate a self-signed TLS cert for the API server
pub(super) fn generate_tls_cert() -> Result<(), String> {
    let cert_path = "/usr/local/etc/aifw/tls/cert.pem";
    let key_path = "/usr/local/etc/aifw/tls/key.pem";

    if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
        return Ok(());
    }

    std::fs::create_dir_all("/usr/local/etc/aifw/tls")
        .map_err(|e| format!("failed to create tls dir: {e}"))?;

    // Generate using openssl CLI (available on FreeBSD base)
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=AiFw Firewall/O=AiFw",
        ])
        .status()
        .map_err(|e| format!("openssl failed: {e}"))?;

    if !status.success() {
        return Err("openssl cert generation failed".to_string());
    }

    // Set permissions: aifw group can read
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        warn_on_err(
            "chmod jwt key to 0640",
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o640)),
        );
        run_best_effort("chown", &["root:aifw", key_path]);
        run_best_effort("chown", &["root:aifw", cert_path]);
    }

    Ok(())
}

/// Configure SSH: authorized_keys, sshd_config, enable sshd
pub(super) fn configure_ssh(config: &SetupConfig) -> Result<(), String> {
    use crate::config::SshAuthMethod;

    // Write authorized_keys if we have keys
    if !config.ssh_authorized_keys.is_empty() {
        let ssh_dir = "/root/.ssh";
        std::fs::create_dir_all(ssh_dir).map_err(|e| format!("failed to create {ssh_dir}: {e}"))?;

        let keys_content = config.ssh_authorized_keys.join("\n") + "\n";
        std::fs::write(format!("{ssh_dir}/authorized_keys"), &keys_content)
            .map_err(|e| format!("failed to write authorized_keys: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            warn_on_err(
                "chmod ssh dir to 0700",
                std::fs::set_permissions(ssh_dir, std::fs::Permissions::from_mode(0o700)),
            );
            warn_on_err(
                "chmod authorized_keys to 0600",
                std::fs::set_permissions(
                    format!("{ssh_dir}/authorized_keys"),
                    std::fs::Permissions::from_mode(0o600),
                ),
            );
        }
    }

    // Configure sshd_config
    let sshd_config = match config.ssh_auth_method {
        SshAuthMethod::KeyOnly => {
            "# AiFw SSH configuration — key authentication only\n\
             PermitRootLogin prohibit-password\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             AuthorizedKeysFile .ssh/authorized_keys\n\
             X11Forwarding no\n\
             PrintMotd yes\n\
             Subsystem sftp /usr/libexec/sftp-server\n"
        }
        SshAuthMethod::Password => {
            "# AiFw SSH configuration — password authentication (not recommended)\n\
             PermitRootLogin yes\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication yes\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             AuthorizedKeysFile .ssh/authorized_keys\n\
             X11Forwarding no\n\
             PrintMotd yes\n\
             Subsystem sftp /usr/libexec/sftp-server\n"
        }
    };

    #[cfg(target_os = "freebsd")]
    {
        std::fs::write("/etc/ssh/sshd_config", sshd_config)
            .map_err(|e| format!("failed to write sshd_config: {e}"))?;

        // Enable sshd at boot
        run_best_effort("sysrc", &["sshd_enable=YES"]);

        // Restart sshd to apply config
        run_best_effort("service", &["sshd", "restart"]);
    }

    #[cfg(not(target_os = "freebsd"))]
    {
        // Not fallible: consumes the built string to suppress the unused
        // warning on non-FreeBSD dev builds.
        let _ = sshd_config;
    }

    Ok(())
}

pub(super) fn create_dirs(config: &SetupConfig) -> Result<(), String> {
    for dir in [&config.config_dir, "/var/db/aifw", "/var/log/aifw"] {
        std::fs::create_dir_all(dir).map_err(|e| format!("failed to create {dir}: {e}"))?;
    }

    // Set ownership: config dir readable by aifw, db/log owned by aifw
    #[cfg(target_os = "freebsd")]
    {
        // Config dir: root owns, aifw group can read
        run_best_effort("chown", &["root:aifw", &config.config_dir]);
        run_best_effort("chmod", &["750", &config.config_dir]);
        // DB dir: aifw owns (API needs write access)
        run_best_effort("chown", &["-R", "aifw:aifw", "/var/db/aifw"]);
        run_best_effort("chmod", &["750", "/var/db/aifw"]);
        // Log dir: aifw owns
        run_best_effort("chown", &["-R", "aifw:aifw", "/var/log/aifw"]);
        run_best_effort("chmod", &["750", "/var/log/aifw"]);
    }

    Ok(())
}

pub(super) fn write_file(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("failed to write {path}: {e}"))
}

/// Run a best-effort setup command, printing a visible warning on spawn
/// failure or non-zero exit instead of silently swallowing it (QUAL-H1 #421).
/// First-boot steps intentionally continue past individual failures — the
/// operator sees the warning in the wizard output and can fix up afterwards.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) fn run_best_effort(cmd: &str, args: &[&str]) {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => console::warn(&format!(
            "{cmd} {} exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => console::warn(&format!("failed to run {cmd} {}: {e}", args.join(" "))),
    }
}

/// Print a fallible best-effort step's failure instead of dropping it
/// (QUAL-H1 #421). Pass an empty `desc` when the error already carries
/// full context.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub(super) fn warn_on_err<T, E: std::fmt::Display>(desc: &str, res: Result<T, E>) {
    if let Err(e) = res {
        if desc.is_empty() {
            console::warn(&format!("{e}"));
        } else {
            console::warn(&format!("{desc}: {e}"));
        }
    }
}

/// Write a single sysrc key=value pair (FreeBSD only).
#[cfg(target_os = "freebsd")]
pub(super) fn run_sysrc(key: &str, value: &str) -> Result<(), String> {
    let out = std::process::Command::new("sysrc")
        .arg(format!("{key}={value}"))
        .output()
        .map_err(|e| format!("sysrc {key}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sysrc {key}={value} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Append a value to a sysrc list key (space-separated, FreeBSD only).
#[cfg(target_os = "freebsd")]
pub(super) fn run_sysrc_append(key: &str, value: &str) -> Result<(), String> {
    let existing = std::process::Command::new("sysrc")
        .arg("-n")
        .arg(key)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let combined = if existing.is_empty() {
        value.to_string()
    } else {
        format!("{existing} {value}")
    };
    run_sysrc(key, &combined)
}

/// Single-quote-wrap a string for safe inclusion in /etc/rc.conf values, which
/// are sourced by /bin/sh at boot. Returns the value wrapped in single quotes
/// with any inner single quotes escaped as `'\''`. Caller embeds the result
/// directly into the larger value string.
#[cfg(target_os = "freebsd")]
pub(super) fn shell_quote_for_rcconf(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub(super) fn write_config_file(config: &SetupConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config).map_err(|e| format!("serialize error: {e}"))?;
    write_file(&format!("{}/aifw.conf", config.config_dir), &json)
}
