//! Narrow-privilege wrappers around helper scripts under
//! `/usr/local/libexec/aifw-sudo-*`. Each helper enforces an internal
//! allowlist of valid arguments — paths, services, interface names — so
//! a compromise of the `aifw` user can't pivot to root via a broad
//! NOPASSWD grant on something like `tee`, `cp`, or `chmod`.
//!
//! Background: GHSA-mjqh-2vx8-7hq7 follow-up #204. Pre-fix sudoers gave
//! `aifw` full-arg NOPASSWD on a dozen utilities — `sudo cp /etc/master.passwd /tmp/x`
//! was a one-liner to root. Each call site that genuinely needs root is
//! migrated through here so the broad grant can be dropped.

use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const SUDO: &str = "/usr/local/bin/sudo";

/// Detect when sudo refused the narrow-helper invocation because the
/// caller (aifw user) hasn't been granted that path in sudoers. This
/// happens during in-place upgrades from a pre-#204 appliance — the
/// helpers exist on disk (`ensure_libexec_scripts()` self-installs them
/// from the embedded copies) but the sudoers file is still the broad-
/// only legacy version. The wrappers below fall back to direct sudo of
/// the underlying binary using the broad grant that those legacy
/// sudoers files have always granted.
///
/// FreeBSD sudo emits one of these stderr strings on refusal:
///   - "sudo: a password is required"
///   - "Sorry, user aifw is not allowed to execute ..."
///
/// "command not found" is also a fallback trigger: sudo reports a helper
/// that is missing *or non-executable* with that message. ISO images
/// before v5.97.6 shipped eight helpers mode 644 (#469), which bricked
/// the in-app updater at the tar-extract step even though the broad
/// compat grant for the underlying binary was still in sudoers.
fn sudo_refused(stderr: &str) -> bool {
    stderr.contains("password is required")
        || stderr.contains("is not allowed to")
        || stderr.contains("command not found")
}

/// Run a command via sudo, preferring the narrow helper path; if sudo
/// refuses the narrow path (operator hasn't yet refreshed sudoers to
/// include the new helper grants), fall back to the direct broad-grant
/// invocation. Returns whichever `Output` was actually produced.
async fn sudo_with_fallback(
    narrow_args: &[&str],
    fallback_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let narrow = Command::new(SUDO).args(narrow_args).output().await?;
    if narrow.status.success() {
        return Ok(narrow);
    }
    let stderr = String::from_utf8_lossy(&narrow.stderr);
    if sudo_refused(&stderr) {
        tracing::debug!(
            "narrow helper {:?} refused by sudo (no grant); falling back to broad path",
            narrow_args.first().copied().unwrap_or("?")
        );
        return Command::new(SUDO).args(fallback_args).output().await;
    }
    Ok(narrow)
}

const HELPER_WRITE: &str = "/usr/local/libexec/aifw-sudo-write";
const HELPER_WG: &str = "/usr/local/libexec/aifw-sudo-wg";
const HELPER_FREEBSD_UPDATE: &str = "/usr/local/libexec/aifw-sudo-freebsd-update";
const HELPER_PKG: &str = "/usr/local/libexec/aifw-sudo-pkg";
const HELPER_SERVICE: &str = "/usr/local/libexec/aifw-sudo-service";
const HELPER_CHOWN: &str = "/usr/local/libexec/aifw-sudo-chown";
const HELPER_IFCONFIG: &str = "/usr/local/libexec/aifw-sudo-ifconfig";
const HELPER_INSTALL: &str = "/usr/local/libexec/aifw-sudo-install";
const HELPER_SYSRC: &str = "/usr/local/libexec/aifw-sudo-sysrc";
const HELPER_DHCLIENT: &str = "/usr/local/libexec/aifw-sudo-dhclient";
const HELPER_ROUTE: &str = "/usr/local/libexec/aifw-sudo-route";
const HELPER_PKILL: &str = "/usr/local/libexec/aifw-sudo-pkill";
const HELPER_RM: &str = "/usr/local/libexec/aifw-sudo-rm";
const HELPER_MKDIR: &str = "/usr/local/libexec/aifw-sudo-mkdir";
const HELPER_CP: &str = "/usr/local/libexec/aifw-sudo-cp";
const HELPER_TAR: &str = "/usr/local/libexec/aifw-sudo-tar";
const HELPER_TCPDUMP: &str = "/usr/local/libexec/aifw-sudo-tcpdump";

/// Atomically write `contents` to `path`, as root, via the
/// `aifw-sudo-write` helper script.
///
/// The helper enforces a closed allowlist of paths — see the script at
/// `freebsd/overlay/usr/local/libexec/aifw-sudo-write`. Adding a new
/// write target requires editing the script, not just the call site.
pub async fn write_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-utf8 path"))?;

    // Narrow path: pipe contents into `aifw-sudo-write <path>`.
    let output = run_with_stdin_pipe(&[HELPER_WRITE, path_str], contents).await?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if sudo_refused(&stderr) {
        // Fallback: pipe into `sudo /usr/bin/tee <path>` (broad legacy
        // grant). tee writes both to file and stdout, so /dev/null it.
        tracing::debug!("aifw-sudo-write refused; falling back to sudo tee");
        let output = run_with_stdin_pipe(&["/usr/bin/tee", path_str], contents).await?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "sudo tee fallback failed (exit {}): {}",
            output.status,
            stderr.trim()
        )));
    }
    Err(std::io::Error::other(format!(
        "aifw-sudo-write failed (exit {}): {}",
        output.status,
        stderr.trim()
    )))
}

/// Spawn `sudo <args>`, pipe `data` to stdin, collect output. Helper for
/// the write_file fallback (both narrow + broad paths consume stdin).
async fn run_with_stdin_pipe(args: &[&str], data: &[u8]) -> std::io::Result<std::process::Output> {
    let mut child = Command::new(SUDO)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data).await?;
        stdin.shutdown().await?;
        drop(stdin);
    }
    child.wait_with_output().await
}

/// Run `wg <subcommand> <iface> [args...]` as root via the
/// `aifw-sudo-wg` helper.
///
/// The helper restricts `subcommand` to `set` / `show` and `iface` to
/// `wg<N>` patterns; remaining args are passed through. Returns the raw
/// `Output` so callers can inspect stdout (e.g. `wg show … dump`) and
/// surface `stderr` themselves on failure.
pub async fn wg(
    subcommand: &str,
    iface: &str,
    extra_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_WG, subcommand, iface];
    narrow.extend_from_slice(extra_args);
    let mut fallback: Vec<&str> = vec!["/usr/bin/wg", subcommand, iface];
    fallback.extend_from_slice(extra_args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `freebsd-update <action> [args...]` as root via the
/// `aifw-sudo-freebsd-update` helper.
///
/// The helper restricts `action` to `updatesready` / `fetch` / `install`
/// and validates the small set of allowed args per action (currently
/// just `--not-running-from-cron` for `fetch`). Returns the raw
/// `Output` so callers can branch on `status.success()` and surface
/// `stderr`/`stdout` themselves.
pub async fn freebsd_update(
    action: &str,
    extra_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_FREEBSD_UPDATE, action];
    narrow.extend_from_slice(extra_args);
    let mut fallback: Vec<&str> = vec!["/usr/sbin/freebsd-update", action];
    fallback.extend_from_slice(extra_args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `pkg <action> [args...]` as root via the `aifw-sudo-pkg` helper.
///
/// The helper restricts `action` to `update` / `install` / `upgrade`
/// and validates each form (`install -y <pkg>...` requires alnum/dot/
/// underscore/plus/hyphen-only package names; `upgrade` must be `-y`
/// or `-n`). Other subcommands and arbitrary flags are denied.
pub async fn pkg(action: &str, extra_args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_PKG, action];
    narrow.extend_from_slice(extra_args);
    let mut fallback: Vec<&str> = vec!["/usr/sbin/pkg", action];
    fallback.extend_from_slice(extra_args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `service <name> <action>` as root via the `aifw-sudo-service`
/// helper.
///
/// The helper restricts both the service name (closed allowlist of
/// AiFw-managed services + `unbound`/`sshd`) and the action verb
/// (`start` / `stop` / `restart` / `reload` / `status`, plus the
/// `one*` force variants). Adding a new managed service requires
/// updating the helper script's case block.
pub async fn service(name: &str, action: &str) -> std::io::Result<std::process::Output> {
    sudo_with_fallback(
        &[HELPER_SERVICE, name, action],
        &["/usr/sbin/service", name, action],
    )
    .await
}

/// Recursively change ownership of `path` to `owner_group` (e.g.
/// `"aifw:aifw"`), as root, via the `aifw-sudo-chown` helper.
///
/// The helper enforces closed allowlists for both `owner_group` and
/// `path`. Only the `-R` form is exposed; adding a new managed
/// directory requires editing the helper script.
pub async fn chown_r(owner_group: &str, path: &str) -> std::io::Result<std::process::Output> {
    sudo_with_fallback(
        &[HELPER_CHOWN, "-R", owner_group, path],
        &["/usr/sbin/chown", "-R", owner_group, path],
    )
    .await
}

/// Run `ifconfig <iface> <action> [args...]` as root via the
/// `aifw-sudo-ifconfig` helper.
///
/// The helper validates the iface name (alnum/dot/underscore, ≤16
/// chars, no flag-shape) and constrains `action` to a closed set:
/// `up`/`down`/`delete`/`destroy`/`create` (no-arg), `mtu`/`fib`
/// (numeric arg), `inet` (1–2 args), `inet6` (one arg), `description`
/// (≤128 chars), and `vlan <id> vlandev <parent>`.
pub async fn ifconfig(
    iface: &str,
    action: &str,
    extra_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_IFCONFIG, iface, action];
    narrow.extend_from_slice(extra_args);
    // Direct ifconfig argv order is `<iface> <action> [args...]` — same shape.
    let mut fallback: Vec<&str> = vec!["/sbin/ifconfig", iface, action];
    fallback.extend_from_slice(extra_args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `install -m MODE [-o OWNER] [-g GROUP] SRC DEST` as root via the
/// `aifw-sudo-install` helper.
///
/// The helper enforces closed allowlists for SRC (must be under
/// `/tmp/` or `/usr/share/zoneinfo/`), DEST (specific files +
/// AiFw-managed prefixes), MODE (`0440`/`0600`/`0644`/`0755`), and
/// OWNER/GROUP (root, aifw, rdns, unbound, nginx, www / wheel, aifw,
/// rdns, unbound, nginx, www). Pass `None` for any unwanted field.
/// Set or unset an `/etc/rc.conf` variable as root via the
/// `aifw-sudo-sysrc` helper.
///
/// The helper restricts which rcvars `aifw` may touch (AiFw service
/// `*_enable` rcvars, `ifconfig_*`, `vlans_*`, `hostname`,
/// `defaultrouter`, etc.) and rejects keys with shell metacharacters.
/// Pass `["KEY=VALUE"]` to set, `["-x", "KEY"]` to unset, `["-n",
/// "KEY"]` to read (though reads don't actually need root).
pub async fn sysrc(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_SYSRC];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/usr/sbin/sysrc"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `install [-m MODE] [-o OWNER] [-g GROUP] SRC DEST` as root via the
/// `aifw-sudo-install` narrow helper, falling back to sudo'ing
/// `/usr/bin/install` with the same argv if sudo refuses the helper (no
/// grant). Pass `None` to omit a flag.
pub async fn install(
    mode: Option<&str>,
    owner: Option<&str>,
    group: Option<&str>,
    src: &str,
    dest: &str,
) -> std::io::Result<std::process::Output> {
    let build = |first: &'static str| {
        let mut a: Vec<String> = vec![first.to_string()];
        if let Some(m) = mode {
            a.push("-m".into());
            a.push(m.into());
        }
        if let Some(o) = owner {
            a.push("-o".into());
            a.push(o.into());
        }
        if let Some(g) = group {
            a.push("-g".into());
            a.push(g.into());
        }
        a.push(src.into());
        a.push(dest.into());
        a
    };
    let narrow = build(HELPER_INSTALL);
    let fallback = build("/usr/bin/install");
    let narrow_refs: Vec<&str> = narrow.iter().map(String::as_str).collect();
    let fallback_refs: Vec<&str> = fallback.iter().map(String::as_str).collect();
    sudo_with_fallback(&narrow_refs, &fallback_refs).await
}

/// Run `dhclient <iface>` (or `dhclient -k <iface>` to release) as root via
/// the `aifw-sudo-dhclient` helper. The helper rejects `-sf`/`-cf`/`-pf`
/// (script-exec primitives) and validates the iface name.
pub async fn dhclient(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_DHCLIENT];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/sbin/dhclient"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `route <action> <dest> [<gw>] [-fib <N>]` as root via the
/// `aifw-sudo-route` helper. Restricted to add/delete on `default` or a
/// CIDR with a valid IP gateway.
pub async fn route(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_ROUTE];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/sbin/route"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run `pkill -f "dhclient <iface>"` as root via the `aifw-sudo-pkill`
/// helper. Only the dhclient pattern is accepted.
pub async fn pkill_dhclient(iface: &str) -> std::io::Result<std::process::Output> {
    let pattern = format!("dhclient {iface}");
    sudo_with_fallback(
        &[HELPER_PKILL, "-f", &pattern],
        &["/usr/bin/pkill", "-f", &pattern],
    )
    .await
}

/// Remove a single allowlisted path as root via `aifw-sudo-rm`.
pub async fn rm(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_RM];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/bin/rm"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Create a directory under an allowlisted prefix as root via `aifw-sudo-mkdir`.
pub async fn mkdir(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_MKDIR];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/bin/mkdir"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Copy a file or directory between allowlisted paths as root via `aifw-sudo-cp`.
pub async fn cp(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_CP];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/bin/cp"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Extract a tarball into an allowlisted directory via `aifw-sudo-tar`.
/// The helper hard-rejects `--use-compress-program`, `--checkpoint-action`,
/// `--to-command`, `-I` and other script-exec primitives. Fallback uses
/// the broad pre-#204 `/usr/bin/tar` grant when the narrow helper isn't
/// yet permitted by sudoers.
pub async fn tar(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_TAR];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/usr/bin/tar"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}

/// Run tcpdump via `aifw-sudo-tcpdump`. The helper rejects `-z` (postrotate
/// exec), `-w` (arbitrary write), and `-G/-W` (output rotation). Only
/// reading allowlisted pcap files or live-capturing `pflog0` is allowed.
pub async fn tcpdump(args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut narrow: Vec<&str> = vec![HELPER_TCPDUMP];
    narrow.extend_from_slice(args);
    let mut fallback: Vec<&str> = vec!["/usr/sbin/tcpdump"];
    fallback.extend_from_slice(args);
    sudo_with_fallback(&narrow, &fallback).await
}
