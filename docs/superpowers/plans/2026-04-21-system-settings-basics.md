# System Settings Basics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add baseline OPNsense/pfSense-style "System" configuration to the AiFw web UI — hostname, domain, timezone, login banner / MOTD, console, SSH access — plus a live System Info dashboard. Also removes the AiFw version string from `/etc/motd` on fresh installs and upgrades.

**Architecture:** Four layers matching existing AiFw patterns. (1) sqlite KV table `system_config` for persistence, mirroring the `dhcp_config` pattern at `aifw-api/src/dhcp.rs:338`. (2) `aifw-core/src/system_apply.rs` with `#[cfg(target_os)]` split: Linux/WSL = no-op, FreeBSD = writes to `/etc/*` and `/boot/loader.conf` via managed blocks. (3) New `aifw-api/src/system.rs` module mounted at `/api/v1/system/*`, gated by `SettingsRead` / `SettingsWrite`. (4) Four new cards on `/settings?cat=system` plus a new `/system/info` dashboard page.

**Tech Stack:** Rust + Axum (API), sqlx + SQLite (persistence), Next.js 15 + Tailwind 4 (UI), tokio (async + process spawning).

---

## Deviation from spec

The spec (`docs/superpowers/specs/2026-04-21-system-settings-basics-design.md`) stated persistence would extend `SystemConfig` in `aifw-core/src/config.rs` and write to `config.json`. On implementation review, `FirewallConfig` is in practice only used as a backup import/export artifact (see `aifw-api/src/backup.rs:721,1491,1968`) — there is no runtime load-from-JSON path. Each subsystem (DHCP, reverse-proxy, time, IDS) persists its own config to a sqlite KV table. This plan follows that existing pattern: new `system_config` KV table as source of truth, with `/etc/*` files as the applied projection. The `SystemConfig` struct is still extended (so backup export/import carries the new fields), but it is not the runtime state. This matches the rest of the codebase and simplifies testing (no filesystem dependency for round-trip tests).

---

## File structure

**New files:**

- `aifw-core/src/system_apply.rs` — apply layer (Linux no-op, FreeBSD /etc writes)
- `aifw-core/src/system_apply_helpers.rs` — pure string/validation helpers (unit-testable on any OS)
- `aifw-api/src/system.rs` — API module with route handlers, KV load/save, validation
- `aifw-ui/src/app/system/info/page.tsx` — live System Info dashboard
- `freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh` — idempotent MOTD version-stripper
- `aifw-core/tests/system_apply_helpers.rs` — unit tests for managed-block rewriting and validators

**Modified files:**

- `aifw-core/src/config.rs` — extend `SystemConfig` + add `ConsoleConfig`, `SshAccessConfig`, `ConsoleKind`
- `aifw-core/src/lib.rs` — add `pub mod system_apply; pub mod system_apply_helpers;`
- `aifw-api/src/main.rs` — add `mod system;` and mount routes
- `aifw-api/src/lib.rs` (if present) — expose `system` module
- `aifw-ui/src/app/settings/page.tsx` — four new cards in the `System` category
- `aifw-ui/src/components/Sidebar.tsx` — add System Info link
- `freebsd/build-iso.sh` — drop version line from MOTD template
- `freebsd/deploy.sh` — call `aifw-motd-cleanup.sh`
- `aifw-core/src/updater.rs` — call `aifw-motd-cleanup.sh` in `download_and_install()`
- `Cargo.toml` — version bump
- `aifw-ui/package.json` — matching version bump

---

## Task 1: Extend `SystemConfig` struct

**Files:**
- Modify: `aifw-core/src/config.rs` (insert after `SystemConfig` at line 146)

- [ ] **Step 1: Write the failing test** in `aifw-core/src/tests.rs` (append at end of file)

```rust
#[test]
fn system_config_defaults_for_new_fields() {
    let c = crate::SystemConfig::default();
    assert_eq!(c.domain, "");
    assert_eq!(c.timezone, "UTC");
    assert_eq!(c.login_banner, "");
    assert_eq!(c.motd, "");
    assert_eq!(c.console.kind, crate::ConsoleKind::Video);
    assert_eq!(c.console.baud, 115200);
    assert!(c.ssh.enabled);
    assert_eq!(c.ssh.port, 22);
    assert!(!c.ssh.password_auth);
    assert!(!c.ssh.permit_root_login);
}

#[test]
fn old_config_json_loads_with_defaults() {
    // JSON from before the new fields existed — must still deserialize.
    let legacy = r#"{
        "schema_version": 1,
        "system": {
            "hostname": "test",
            "dns_servers": ["1.1.1.1"],
            "wan_interface": "em0",
            "lan_interface": null,
            "lan_ip": null,
            "api_listen": "0.0.0.0",
            "api_port": 8080,
            "ui_enabled": true
        },
        "auth": { "access_token_expiry_mins": 60, "refresh_token_expiry_days": 7, "require_totp": false, "require_totp_for_oauth": false, "auto_create_oauth_users": false }
    }"#;
    let c = crate::FirewallConfig::from_json(legacy).expect("legacy JSON must load");
    assert_eq!(c.system.hostname, "test");
    assert_eq!(c.system.domain, ""); // default
    assert_eq!(c.system.timezone, "UTC"); // default
    assert_eq!(c.system.ssh.port, 22); // default
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --package aifw-core system_config_defaults_for_new_fields old_config_json_loads_with_defaults`
Expected: compile error — types `ConsoleKind`, fields `domain`, etc. don't exist yet.

- [ ] **Step 3: Add new types and extend `SystemConfig`** — in `aifw-core/src/config.rs`, replace the block at lines 145–170 with:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub hostname: String,
    pub dns_servers: Vec<String>,
    pub wan_interface: String,
    pub lan_interface: Option<String>,
    pub lan_ip: Option<String>,
    pub api_listen: String,
    pub api_port: u16,
    pub ui_enabled: bool,

    #[serde(default)]
    pub domain: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub login_banner: String,
    #[serde(default)]
    pub motd: String,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[serde(default)]
    pub ssh: SshAccessConfig,
}

fn default_timezone() -> String { "UTC".to_string() }

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "aifw".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            wan_interface: "em0".to_string(),
            lan_interface: None,
            lan_ip: None,
            api_listen: "0.0.0.0".to_string(),
            api_port: 8080,
            ui_enabled: true,
            domain: String::new(),
            timezone: default_timezone(),
            login_banner: String::new(),
            motd: String::new(),
            console: ConsoleConfig::default(),
            ssh: SshAccessConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleKind {
    #[default]
    Video,
    Serial,
    Dual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub kind: ConsoleKind,
    #[serde(default = "default_baud")]
    pub baud: u32,
}

fn default_baud() -> u32 { 115200 }

impl Default for ConsoleConfig {
    fn default() -> Self { Self { kind: ConsoleKind::default(), baud: default_baud() } }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshAccessConfig {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub permit_root_login: bool,
}

impl Default for SshAccessConfig {
    fn default() -> Self {
        Self { enabled: true, port: 22, password_auth: false, permit_root_login: false }
    }
}
```

- [ ] **Step 4: Re-export new types** — in `aifw-core/src/lib.rs`, find the `pub use` line that re-exports `SystemConfig` and extend it:

```rust
pub use config::{
    FirewallConfig, SystemConfig, AuthConfig,
    ConsoleConfig, ConsoleKind, SshAccessConfig, // add these
    /* any other existing re-exports on this line — preserve them */
};
```

(If the file uses multiple `pub use config::X;` lines, add one per new type in the same style.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --package aifw-core system_config_defaults_for_new_fields old_config_json_loads_with_defaults`
Expected: PASS for both.

- [ ] **Step 6: Run full cargo check**

Run: `cargo check --workspace`
Expected: no errors, no warnings. If any existing test constructs `SystemConfig { ... }` with all fields listed out, it will fail to compile — update those tests to use `..SystemConfig::default()` spread.

- [ ] **Step 7: Commit**

```bash
git add aifw-core/src/config.rs aifw-core/src/lib.rs aifw-core/src/tests.rs
git commit -m "core: extend SystemConfig with domain/timezone/banner/console/ssh"
```

---

## Task 2: Pure helpers — validation + managed-block rewrite

**Files:**
- Create: `aifw-core/src/system_apply_helpers.rs`
- Create: `aifw-core/tests/system_apply_helpers.rs`
- Modify: `aifw-core/src/lib.rs` — add `pub mod system_apply_helpers;`

These helpers are pure (string-in / string-out) so they unit-test cleanly on Linux.

- [ ] **Step 1: Write the failing tests** in `aifw-core/tests/system_apply_helpers.rs`

```rust
use aifw_core::system_apply_helpers::{
    replace_managed_block, validate_hostname, validate_domain, validate_ssh_port,
    validate_baud,
};

#[test]
fn replace_managed_block_inserts_when_absent() {
    let original = "line1\nline2\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    assert!(out.contains("# BEGIN AiFw console"));
    assert!(out.contains("console=\"comconsole\""));
    assert!(out.contains("# END AiFw console"));
    assert!(out.starts_with("line1\nline2\n"));
}

#[test]
fn replace_managed_block_overwrites_existing() {
    let original = "keepme\n# BEGIN AiFw console\nconsole=\"vidconsole\"\n# END AiFw console\ntail\n";
    let out = replace_managed_block(original, "AiFw console", "console=\"comconsole\"\n");
    assert!(out.contains("console=\"comconsole\""));
    assert!(!out.contains("console=\"vidconsole\""));
    assert!(out.contains("keepme"));
    assert!(out.contains("tail"));
    // No duplicated markers
    assert_eq!(out.matches("# BEGIN AiFw console").count(), 1);
    assert_eq!(out.matches("# END AiFw console").count(), 1);
}

#[test]
fn replace_managed_block_idempotent() {
    let original = "x\n";
    let once = replace_managed_block(original, "AiFw console", "a=1\n");
    let twice = replace_managed_block(&once, "AiFw console", "a=1\n");
    assert_eq!(once, twice);
}

#[test]
fn validate_hostname_accepts_rfc1123_label() {
    assert!(validate_hostname("router").is_ok());
    assert!(validate_hostname("aifw-01").is_ok());
    assert!(validate_hostname("a").is_ok());
}

#[test]
fn validate_hostname_rejects_dots_and_empty_and_long() {
    assert!(validate_hostname("").is_err());
    assert!(validate_hostname("host.domain").is_err()); // dots → use domain field
    assert!(validate_hostname("-leading").is_err());
    assert!(validate_hostname(&"a".repeat(64)).is_err()); // > 63
    assert!(validate_hostname("has space").is_err());
}

#[test]
fn validate_domain_allows_empty() {
    assert!(validate_domain("").is_ok());
}

#[test]
fn validate_domain_rejects_leading_dot_and_spaces() {
    assert!(validate_domain("home.lan").is_ok());
    assert!(validate_domain(".badlead").is_err());
    assert!(validate_domain("has space.com").is_err());
}

#[test]
fn validate_ssh_port_range() {
    assert!(validate_ssh_port(22).is_ok());
    assert!(validate_ssh_port(65535).is_ok());
    assert!(validate_ssh_port(1).is_ok());
    assert!(validate_ssh_port(0).is_err());
}

#[test]
fn validate_baud_allowed_set() {
    for b in [9600, 19200, 38400, 57600, 115200] {
        assert!(validate_baud(b).is_ok(), "baud {} should be allowed", b);
    }
    assert!(validate_baud(1).is_err());
    assert!(validate_baud(250000).is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail (compile error)**

Run: `cargo test --package aifw-core --test system_apply_helpers`
Expected: compile error — module doesn't exist.

- [ ] **Step 3: Create the helpers module** — write `aifw-core/src/system_apply_helpers.rs`:

```rust
//! Pure helpers for system_apply — string-in/string-out so they
//! unit-test on any host OS.

/// Replace (or insert) a block of content between
/// `# BEGIN <marker>` and `# END <marker>` lines.
///
/// If the markers exist anywhere in `content`, the block between them
/// is replaced. Otherwise a new block is appended at the end.
/// `new_block` should end with a trailing newline if it contains lines.
pub fn replace_managed_block(content: &str, marker: &str, new_block: &str) -> String {
    let begin = format!("# BEGIN {}", marker);
    let end = format!("# END {}", marker);

    if let (Some(b), Some(e)) = (content.find(&begin), content.find(&end)) {
        if b < e {
            let end_line_end = content[e..].find('\n').map(|n| e + n + 1).unwrap_or(content.len());
            let before = &content[..b];
            let after = &content[end_line_end..];
            let mut out = String::with_capacity(content.len() + new_block.len());
            out.push_str(before);
            out.push_str(&begin);
            out.push('\n');
            out.push_str(new_block);
            if !new_block.ends_with('\n') { out.push('\n'); }
            out.push_str(&end);
            out.push('\n');
            out.push_str(after);
            return out;
        }
    }

    // No markers yet — append.
    let mut out = String::with_capacity(content.len() + new_block.len() + begin.len() + end.len() + 8);
    out.push_str(content);
    if !content.is_empty() && !content.ends_with('\n') { out.push('\n'); }
    out.push_str(&begin);
    out.push('\n');
    out.push_str(new_block);
    if !new_block.ends_with('\n') { out.push('\n'); }
    out.push_str(&end);
    out.push('\n');
    out
}

pub fn validate_hostname(s: &str) -> Result<(), String> {
    if s.is_empty() { return Err("hostname must not be empty".into()); }
    if s.len() > 63 { return Err("hostname must be ≤ 63 characters (RFC 1123)".into()); }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err("hostname must start with a letter or digit".into());
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("hostname contains invalid character: {:?}", b as char));
        }
    }
    Ok(())
}

pub fn validate_domain(s: &str) -> Result<(), String> {
    if s.is_empty() { return Ok(()); }
    if s.starts_with('.') || s.ends_with('.') {
        return Err("domain must not start or end with a dot".into());
    }
    for b in s.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            return Err(format!("domain contains invalid character: {:?}", b as char));
        }
    }
    Ok(())
}

pub fn validate_ssh_port(port: u16) -> Result<(), String> {
    if port == 0 { return Err("ssh port must be 1–65535".into()); }
    Ok(())
}

pub fn validate_baud(baud: u32) -> Result<(), String> {
    match baud {
        9600 | 19200 | 38400 | 57600 | 115200 => Ok(()),
        _ => Err("baud must be one of 9600, 19200, 38400, 57600, 115200".into()),
    }
}
```

- [ ] **Step 4: Add module to `aifw-core/src/lib.rs`**

Add `pub mod system_apply_helpers;` near the other `pub mod` declarations.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --package aifw-core --test system_apply_helpers`
Expected: all 9 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add aifw-core/src/system_apply_helpers.rs aifw-core/src/lib.rs aifw-core/tests/system_apply_helpers.rs
git commit -m "core: add system_apply pure helpers (block rewrite, validators)"
```

---

## Task 3: `system_apply` module skeleton (Linux no-ops)

**Files:**
- Create: `aifw-core/src/system_apply.rs`
- Modify: `aifw-core/src/lib.rs` — add `pub mod system_apply;`

- [ ] **Step 1: Write the failing test** in a new file `aifw-core/tests/system_apply_linux.rs`

```rust
#![cfg(not(target_os = "freebsd"))]

use aifw_core::system_apply::{
    apply_general, apply_banner, apply_console, apply_ssh, collect_info,
    GeneralInput, BannerInput, ConsoleInput, SshInput, ApplyReport,
};

#[tokio::test]
async fn linux_apply_general_is_noop_ok() {
    let r: ApplyReport = apply_general(&GeneralInput {
        hostname: "testhost".into(),
        domain: "example.com".into(),
        timezone: "UTC".into(),
    }).await;
    assert!(r.ok);
    assert!(!r.requires_reboot);
    assert!(r.requires_service_restart.is_none());
}

#[tokio::test]
async fn linux_apply_console_reports_requires_reboot() {
    let r = apply_console(&ConsoleInput { kind: "serial".into(), baud: 115200 }).await;
    assert!(r.ok);
    assert!(r.requires_reboot);
}

#[tokio::test]
async fn linux_apply_ssh_reports_sshd_restart() {
    let r = apply_ssh(&SshInput { enabled: true, port: 22, password_auth: false, permit_root_login: false }).await;
    assert!(r.ok);
    assert_eq!(r.requires_service_restart.as_deref(), Some("sshd"));
}

#[tokio::test]
async fn linux_apply_banner_is_noop_ok() {
    let r = apply_banner(&BannerInput { login_banner: "hi".into(), motd: "there".into() }).await;
    assert!(r.ok);
}

#[tokio::test]
async fn linux_collect_info_returns_stub() {
    let info = collect_info().await;
    assert!(!info.os_version.is_empty());
    assert!(info.cpu_count >= 1);
    assert!(info.mem_total_bytes > 0);
}
```

- [ ] **Step 2: Run tests to verify they fail (compile error)**

Run: `cargo test --package aifw-core --test system_apply_linux`
Expected: compile error — module doesn't exist.

- [ ] **Step 3: Create `aifw-core/src/system_apply.rs`** with Linux implementations and FreeBSD stubs that compile but error out (the FreeBSD bodies will be filled in Tasks 5–9):

```rust
//! Apply-layer for System settings.
//!
//! Linux/WSL build: every apply is a no-op that returns OK, matching
//! the `PfMock` philosophy. FreeBSD build: writes to /etc/* and
//! /boot/loader.conf and runs service/sysrc commands.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub ok: bool,
    pub requires_reboot: bool,
    pub requires_service_restart: Option<String>,
    pub warning: Option<String>,
}

impl ApplyReport {
    pub fn ok() -> Self { Self { ok: true, requires_reboot: false, requires_service_restart: None, warning: None } }
    pub fn ok_requires_reboot() -> Self { Self { ok: true, requires_reboot: true, requires_service_restart: None, warning: None } }
    pub fn ok_requires_restart(service: &str) -> Self { Self { ok: true, requires_reboot: false, requires_service_restart: Some(service.to_string()), warning: None } }
    pub fn warn(msg: impl Into<String>) -> Self { Self { ok: true, requires_reboot: false, requires_service_restart: None, warning: Some(msg.into()) } }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeneralInput { pub hostname: String, pub domain: String, pub timezone: String }

#[derive(Debug, Clone, Deserialize)]
pub struct BannerInput { pub login_banner: String, pub motd: String }

#[derive(Debug, Clone, Deserialize)]
pub struct ConsoleInput { pub kind: String, pub baud: u32 }

#[derive(Debug, Clone, Deserialize)]
pub struct SshInput {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub permit_root_login: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub domain: String,
    pub os_version: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load_avg: [f64; 3],
    pub cpu_model: String,
    pub cpu_count: u32,
    pub cpu_usage_pct: f32,
    pub mem_total_bytes: u64,
    pub mem_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub temperatures_c: Vec<CpuTemp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuTemp { pub core: u32, pub celsius: f32 }

// ----- Linux/WSL (dev): no-op apply, stub info -----

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_general(_i: &GeneralInput) -> ApplyReport { ApplyReport::ok() }

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_banner(_i: &BannerInput) -> ApplyReport { ApplyReport::ok() }

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport { ApplyReport::ok_requires_reboot() }

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport { ApplyReport::ok_requires_restart("sshd") }

#[cfg(not(target_os = "freebsd"))]
pub async fn collect_info() -> SystemInfo {
    // Minimal plausible stub for UI development.
    SystemInfo {
        hostname: hostname_stub(),
        domain: String::new(),
        os_version: format!("{} (dev)", std::env::consts::OS),
        kernel: "dev-kernel".into(),
        uptime_secs: 0,
        load_avg: [0.0, 0.0, 0.0],
        cpu_model: "dev-cpu".into(),
        cpu_count: num_cpus_stub(),
        cpu_usage_pct: 0.0,
        mem_total_bytes: 8 * 1024 * 1024 * 1024,
        mem_used_bytes: 0,
        disk_total_bytes: 100 * 1024 * 1024 * 1024,
        disk_used_bytes: 0,
        temperatures_c: Vec::new(),
    }
}

#[cfg(not(target_os = "freebsd"))]
fn hostname_stub() -> String {
    std::env::var("HOSTNAME").ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "dev".to_string())
}

#[cfg(not(target_os = "freebsd"))]
fn num_cpus_stub() -> u32 {
    std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1)
}

#[cfg(not(target_os = "freebsd"))]
pub async fn motd_user_edited_marker_set() -> bool { false }

// ----- FreeBSD: real apply (bodies filled in Tasks 5–9) -----

#[cfg(target_os = "freebsd")]
mod freebsd_impl;

#[cfg(target_os = "freebsd")]
pub use freebsd_impl::{
    apply_general, apply_banner, apply_console, apply_ssh, collect_info,
    motd_user_edited_marker_set,
};
```

Also create an empty `aifw-core/src/freebsd_impl.rs` so the cfg-gated `mod` compiles on non-FreeBSD **only because it's gated out**. Actually it won't be referenced on Linux. But we still need it to exist for `cargo check --target x86_64-unknown-freebsd`. For this task, leave a stub:

Create `aifw-core/src/freebsd_impl.rs`:

```rust
//! FreeBSD apply implementations — filled in Tasks 5–9.
#![cfg(target_os = "freebsd")]

use super::{ApplyReport, GeneralInput, BannerInput, ConsoleInput, SshInput, SystemInfo};

pub async fn apply_general(_i: &GeneralInput) -> ApplyReport { ApplyReport::ok() }
pub async fn apply_banner(_i: &BannerInput) -> ApplyReport { ApplyReport::ok() }
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport { ApplyReport::ok_requires_reboot() }
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport { ApplyReport::ok_requires_restart("sshd") }
pub async fn collect_info() -> SystemInfo { SystemInfo::default() }
pub async fn motd_user_edited_marker_set() -> bool { false }
```

Note: the `mod freebsd_impl;` in `system_apply.rs` refers to a sibling file in the same module tree — adjust the path. Since `system_apply.rs` is a file (not a `system_apply/` directory), `mod freebsd_impl;` looks for `aifw-core/src/system_apply/freebsd_impl.rs`. Convert `system_apply` to a module directory:

- Move `aifw-core/src/system_apply.rs` to `aifw-core/src/system_apply/mod.rs`
- Create `aifw-core/src/system_apply/freebsd_impl.rs` with the stub body above.

- [ ] **Step 4: Register module in `aifw-core/src/lib.rs`**

Add `pub mod system_apply;` in the `pub mod` section.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --package aifw-core --test system_apply_linux`
Expected: all 5 tests PASS.

- [ ] **Step 6: Run full workspace check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 7: Commit**

```bash
git add aifw-core/src/system_apply/ aifw-core/src/lib.rs aifw-core/tests/system_apply_linux.rs
git commit -m "core: add system_apply skeleton with Linux no-op impls"
```

---

## Task 4: `system_config` KV storage + `aifw-api/src/system.rs` skeleton

**Files:**
- Create: `aifw-api/src/system.rs`
- Modify: `aifw-api/src/main.rs` — add `mod system;` and mount routes

This task sets up the sqlite KV table, the load/save helpers, the API module with empty handlers, and wires routes. No apply calls yet — those come in Tasks 5–9.

- [ ] **Step 1: Write the failing test** at `aifw-api/tests/system_endpoints.rs` (new file)

```rust
//! Integration tests for /api/v1/system/*. Uses in-memory sqlite +
//! the Linux no-op system_apply layer, so these run identically on
//! Linux dev boxes and FreeBSD CI.

mod common;
use common::{auth_header_admin, test_server};
use axum::http::StatusCode;

#[tokio::test]
async fn get_general_returns_defaults() {
    let ts = test_server().await;
    let r = ts.get("/api/v1/system/general").add_header("authorization", auth_header_admin(&ts).await).await;
    r.assert_status_ok();
    let body: serde_json::Value = r.json();
    assert_eq!(body["timezone"], "UTC");
    // hostname + domain default to empty string in the KV table
    assert!(body["hostname"].is_string());
    assert!(body["domain"].is_string());
}

#[tokio::test]
async fn put_general_round_trips() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/general")
        .add_header("authorization", h.clone())
        .json(&serde_json::json!({ "hostname": "myfw", "domain": "home.lan", "timezone": "America/Chicago" }))
        .await;
    r.assert_status_ok();
    let body: serde_json::Value = r.json();
    assert_eq!(body["ok"], true);

    let r2 = ts.get("/api/v1/system/general").add_header("authorization", h).await;
    let back: serde_json::Value = r2.json();
    assert_eq!(back["hostname"], "myfw");
    assert_eq!(back["domain"], "home.lan");
    assert_eq!(back["timezone"], "America/Chicago");
}

#[tokio::test]
async fn put_general_rejects_invalid_hostname() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/general")
        .add_header("authorization", h)
        .json(&serde_json::json!({ "hostname": "has.dot", "domain": "", "timezone": "UTC" }))
        .await;
    r.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_general_requires_auth() {
    let ts = test_server().await;
    let r = ts.get("/api/v1/system/general").await;
    r.assert_status(StatusCode::UNAUTHORIZED);
}
```

You will need a `common.rs` test helper. Check whether `aifw-api/tests/common.rs` already exists:

```bash
ls aifw-api/tests/
```

If `common.rs` does not exist, create one based on the pattern in the existing `aifw-api/src/tests` module. The helper should:
- Spin up `axum_test::TestServer` via `create_app_state_in_memory`
- Provide `auth_header_admin(&ts)` that registers an admin user and returns a `Bearer <jwt>` string

(If a similar helper already exists, use it — adjust the test imports accordingly.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: compile error / test failures — module + routes don't exist.

- [ ] **Step 3: Create `aifw-api/src/system.rs`** with table migration, KV helpers, route handlers for `/general` only, and skeletons for the others:

```rust
//! System settings API — KV-backed persistence + apply hooks.

use crate::AppState;
use aifw_core::system_apply::{apply_general, ApplyReport, GeneralInput};
use aifw_core::system_apply_helpers::{validate_domain, validate_hostname};
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    ).execute(pool).await?;
    Ok(())
}

async fn get_kv(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value FROM system_config WHERE key = ?1")
        .bind(key).fetch_optional(pool).await.ok().flatten().map(|(v,)| v)
}

async fn set_kv(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

// ---------- General (hostname, domain, timezone) ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralDto {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
}

pub async fn get_general(State(state): State<AppState>) -> Result<Json<GeneralDto>, StatusCode> {
    let hostname = get_kv(&state.pool, "hostname").await.unwrap_or_default();
    let domain = get_kv(&state.pool, "domain").await.unwrap_or_default();
    let timezone = get_kv(&state.pool, "timezone").await.unwrap_or_else(|| "UTC".to_string());
    Ok(Json(GeneralDto { hostname, domain, timezone }))
}

pub async fn put_general(
    State(state): State<AppState>,
    Json(req): Json<GeneralDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    validate_hostname(&req.hostname).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_domain(&req.domain).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if req.timezone.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "timezone must not be empty".into()));
    }

    set_kv(&state.pool, "hostname", &req.hostname).await;
    set_kv(&state.pool, "domain", &req.domain).await;
    set_kv(&state.pool, "timezone", &req.timezone).await;

    let report = apply_general(&GeneralInput {
        hostname: req.hostname,
        domain: req.domain,
        timezone: req.timezone,
    }).await;
    Ok(Json(report))
}

// ---------- Banner / SSH / Console / Info — stubs (filled in Tasks 6–9) ----------
// Keeping them here so `main.rs` can wire the routes in one place.

pub async fn get_banner() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_banner() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_ssh() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_ssh() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_console() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_console() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_info() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn list_timezones() -> Result<Json<Vec<String>>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
```

- [ ] **Step 4: Register module and mount routes in `aifw-api/src/main.rs`**

Add near other `mod` declarations (~line 20):

```rust
mod system;
```

Find `build_router()` and locate the block where other route groups are registered (near the `settings_read` / `settings_write` groups — search for `Permission::SettingsRead`). Add two new route groups:

```rust
// system:read (under SettingsRead permission)
let system_read = Router::new()
    .route("/api/v1/system/general", get(system::get_general))
    .route("/api/v1/system/banner", get(system::get_banner))
    .route("/api/v1/system/ssh", get(system::get_ssh))
    .route("/api/v1/system/console", get(system::get_console))
    .route("/api/v1/system/info", get(system::get_info))
    .route("/api/v1/system/timezones", get(system::list_timezones))
    .layer(middleware::from_fn(perm_check!(Permission::SettingsRead)));

// system:write (under SettingsWrite permission)
let system_write = Router::new()
    .route("/api/v1/system/general", put(system::put_general))
    .route("/api/v1/system/banner", put(system::put_banner))
    .route("/api/v1/system/ssh", put(system::put_ssh))
    .route("/api/v1/system/console", put(system::put_console))
    .layer(middleware::from_fn(perm_check!(Permission::SettingsWrite)));
```

Then merge these into the overall protected router alongside the other groups. Search for the final `.merge(...)` chain and add `.merge(system_read).merge(system_write)`.

Also find the startup code that runs migrations for other subsystems (search for `dhcp::migrate` or `reverse_proxy::migrate`) and add:

```rust
system::migrate(&pool).await.expect("system_config migrate");
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: all 4 tests PASS.

- [ ] **Step 6: Run full workspace check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 7: Commit**

```bash
git add aifw-api/src/system.rs aifw-api/src/main.rs aifw-api/tests/
git commit -m "api: scaffold /api/v1/system/* with general GET/PUT + KV store"
```

---

## Task 5: FreeBSD `apply_general` — hostname, domain, timezone

**Files:**
- Modify: `aifw-core/src/system_apply/freebsd_impl.rs`

FreeBSD-only code; compiles but is not run by CI's Linux `cargo test`. Verified via manual smoke on the test VM at the end of the plan.

- [ ] **Step 1: Implement `apply_general` on FreeBSD** — replace the stub in `aifw-core/src/system_apply/freebsd_impl.rs` for that function:

```rust
pub async fn apply_general(i: &GeneralInput) -> ApplyReport {
    let mut warnings: Vec<String> = Vec::new();

    // --- hostname: sysrc + live ---
    if let Err(e) = run("sysrc", &[&format!("hostname={}", i.hostname)]).await {
        warnings.push(format!("sysrc hostname failed: {}", e));
    }
    if let Err(e) = run("hostname", &[&i.hostname]).await {
        warnings.push(format!("live hostname failed: {}", e));
    }

    // --- /etc/hosts loopback line ---
    if let Err(e) = update_hosts_loopback(&i.hostname, &i.domain).await {
        warnings.push(format!("/etc/hosts update failed: {}", e));
    }

    // --- domain: resolv.conf search line ---
    if let Err(e) = update_resolv_conf_search(&i.domain).await {
        warnings.push(format!("resolv.conf update failed: {}", e));
    }

    // --- timezone: /etc/localtime + /var/db/zoneinfo ---
    let zoneinfo = format!("/usr/share/zoneinfo/{}", i.timezone);
    if !tokio::fs::try_exists(&zoneinfo).await.unwrap_or(false) {
        warnings.push(format!("timezone {} not found in /usr/share/zoneinfo", i.timezone));
    } else {
        if let Err(e) = tokio::fs::copy(&zoneinfo, "/etc/localtime").await {
            warnings.push(format!("/etc/localtime copy failed: {}", e));
        }
        let _ = atomic_write("/var/db/zoneinfo", i.timezone.as_bytes(), 0o644).await;
    }

    if warnings.is_empty() {
        ApplyReport::ok()
    } else {
        let mut r = ApplyReport::ok();
        r.warning = Some(warnings.join("; "));
        r
    }
}

async fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = tokio::process::Command::new(cmd).args(args).output().await
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(())
}

async fn atomic_write(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = format!("{}.aifw.tmp", path);
    tokio::fs::write(&tmp, data).await.map_err(|e| e.to_string())?;
    let perms = std::fs::Permissions::from_mode(mode);
    tokio::fs::set_permissions(&tmp, perms).await.map_err(|e| e.to_string())?;
    tokio::fs::rename(&tmp, path).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn update_hosts_loopback(hostname: &str, domain: &str) -> Result<(), String> {
    let existing = tokio::fs::read_to_string("/etc/hosts").await.unwrap_or_default();
    let fqdn = if domain.is_empty() { hostname.to_string() } else { format!("{}.{} {}", hostname, domain, hostname) };
    let want_line = format!("127.0.1.1\t{}", fqdn);
    let mut out = String::with_capacity(existing.len() + want_line.len() + 1);
    let mut replaced = false;
    for line in existing.lines() {
        if line.starts_with("127.0.1.1") {
            out.push_str(&want_line);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&want_line);
        out.push('\n');
    }
    atomic_write("/etc/hosts", out.as_bytes(), 0o644).await
}

async fn update_resolv_conf_search(domain: &str) -> Result<(), String> {
    let existing = tokio::fs::read_to_string("/etc/resolv.conf").await.unwrap_or_default();
    let mut out = String::with_capacity(existing.len() + 32);
    let mut wrote_search = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("search ") || trimmed.starts_with("domain ") {
            if !domain.is_empty() && !wrote_search {
                out.push_str(&format!("search {}\n", domain));
                wrote_search = true;
            }
            // else: drop this line
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !domain.is_empty() && !wrote_search {
        // Prepend search line
        let body = out;
        out = format!("search {}\n{}", domain, body);
    }
    atomic_write("/etc/resolv.conf", out.as_bytes(), 0o644).await
}
```

- [ ] **Step 2: Verify compiles (with FreeBSD target check)**

Cross-compile check is impractical from a Linux dev box. Instead run:

```bash
cargo check --workspace
```

This will compile the Linux path unchanged. The FreeBSD path gets exercised via test-VM deploy at Task 14.

- [ ] **Step 3: Commit**

```bash
git add aifw-core/src/system_apply/freebsd_impl.rs
git commit -m "core: implement apply_general on FreeBSD (hostname, domain, timezone)"
```

---

## Task 6: Banner — API + FreeBSD apply + marker file

**Files:**
- Modify: `aifw-api/src/system.rs`
- Modify: `aifw-core/src/system_apply/freebsd_impl.rs`

- [ ] **Step 1: Add test cases** — append to `aifw-api/tests/system_endpoints.rs`:

```rust
#[tokio::test]
async fn banner_round_trip() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/banner")
        .add_header("authorization", h.clone())
        .json(&serde_json::json!({ "login_banner": "Authorized only", "motd": "Welcome" }))
        .await;
    r.assert_status_ok();
    let back: serde_json::Value = ts.get("/api/v1/system/banner").add_header("authorization", h).await.json();
    assert_eq!(back["login_banner"], "Authorized only");
    assert_eq!(back["motd"], "Welcome");
}

#[tokio::test]
async fn banner_rejects_oversize() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let big = "x".repeat(9 * 1024);
    let r = ts.put("/api/v1/system/banner")
        .add_header("authorization", h)
        .json(&serde_json::json!({ "login_banner": big, "motd": "" }))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
```

- [ ] **Step 2: Replace the banner stubs in `aifw-api/src/system.rs`:**

```rust
use aifw_core::system_apply::{apply_banner, BannerInput};

#[derive(Debug, Serialize, Deserialize)]
pub struct BannerDto { pub login_banner: String, pub motd: String }

pub async fn get_banner(State(state): State<AppState>) -> Result<Json<BannerDto>, StatusCode> {
    let login_banner = get_kv(&state.pool, "login_banner").await.unwrap_or_default();
    let motd = get_kv(&state.pool, "motd").await.unwrap_or_default();
    Ok(Json(BannerDto { login_banner, motd }))
}

pub async fn put_banner(
    State(state): State<AppState>,
    Json(req): Json<BannerDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    const MAX: usize = 8 * 1024;
    if req.login_banner.len() > MAX || req.motd.len() > MAX {
        return Err((StatusCode::BAD_REQUEST, "banner/motd must be ≤ 8 KiB".into()));
    }
    set_kv(&state.pool, "login_banner", &req.login_banner).await;
    set_kv(&state.pool, "motd", &req.motd).await;
    let report = apply_banner(&BannerInput { login_banner: req.login_banner, motd: req.motd }).await;
    Ok(Json(report))
}
```

Remove the stub `get_banner` / `put_banner` declarations that returned `NOT_IMPLEMENTED`.

- [ ] **Step 3: Implement `apply_banner` on FreeBSD** — in `aifw-core/src/system_apply/freebsd_impl.rs`, replace the stub:

```rust
pub async fn apply_banner(i: &BannerInput) -> ApplyReport {
    let mut warnings = Vec::new();

    if let Err(e) = atomic_write("/etc/issue", i.login_banner.as_bytes(), 0o644).await {
        warnings.push(format!("/etc/issue write failed: {}", e));
    }
    if let Err(e) = atomic_write("/etc/motd.template", i.motd.as_bytes(), 0o644).await {
        warnings.push(format!("/etc/motd.template write failed: {}", e));
    }
    // Mark user-edited so updater leaves MOTD alone.
    let _ = tokio::fs::create_dir_all("/var/db/aifw").await;
    let _ = atomic_write("/var/db/aifw/motd.user-edited", b"1\n", 0o644).await;

    if warnings.is_empty() { ApplyReport::ok() } else {
        let mut r = ApplyReport::ok();
        r.warning = Some(warnings.join("; "));
        r
    }
}

pub async fn motd_user_edited_marker_set() -> bool {
    tokio::fs::try_exists("/var/db/aifw/motd.user-edited").await.unwrap_or(false)
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: all banner tests + previous general tests PASS.

- [ ] **Step 5: cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 6: Commit**

```bash
git add aifw-api/src/system.rs aifw-core/src/system_apply/freebsd_impl.rs aifw-api/tests/system_endpoints.rs
git commit -m "api: banner GET/PUT + FreeBSD apply + user-edited marker"
```

---

## Task 7: SSH — API + FreeBSD apply (sshd_config block + sysrc)

**Files:**
- Modify: `aifw-api/src/system.rs`
- Modify: `aifw-core/src/system_apply/freebsd_impl.rs`

- [ ] **Step 1: Add test cases** — append to `aifw-api/tests/system_endpoints.rs`:

```rust
#[tokio::test]
async fn ssh_defaults_on_fresh_install() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let body: serde_json::Value = ts.get("/api/v1/system/ssh").add_header("authorization", h).await.json();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["port"], 22);
    assert_eq!(body["password_auth"], false);
    assert_eq!(body["permit_root_login"], false);
}

#[tokio::test]
async fn ssh_put_rejects_port_zero() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/ssh")
        .add_header("authorization", h)
        .json(&serde_json::json!({ "enabled": true, "port": 0, "password_auth": false, "permit_root_login": false }))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ssh_put_round_trips_and_reports_restart() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/ssh")
        .add_header("authorization", h.clone())
        .json(&serde_json::json!({ "enabled": true, "port": 2222, "password_auth": false, "permit_root_login": false }))
        .await;
    r.assert_status_ok();
    let body: serde_json::Value = r.json();
    assert_eq!(body["requires_service_restart"], "sshd");

    let back: serde_json::Value = ts.get("/api/v1/system/ssh").add_header("authorization", h).await.json();
    assert_eq!(back["port"], 2222);
}
```

- [ ] **Step 2: Replace SSH stubs in `aifw-api/src/system.rs`:**

```rust
use aifw_core::system_apply::{apply_ssh, SshInput};
use aifw_core::system_apply_helpers::validate_ssh_port;

#[derive(Debug, Serialize, Deserialize)]
pub struct SshDto {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub permit_root_login: bool,
}

pub async fn get_ssh(State(state): State<AppState>) -> Result<Json<SshDto>, StatusCode> {
    let enabled = get_kv(&state.pool, "ssh_enabled").await.map(|v| v == "true").unwrap_or(true);
    let port = get_kv(&state.pool, "ssh_port").await.and_then(|v| v.parse().ok()).unwrap_or(22);
    let password_auth = get_kv(&state.pool, "ssh_password_auth").await.map(|v| v == "true").unwrap_or(false);
    let permit_root_login = get_kv(&state.pool, "ssh_permit_root_login").await.map(|v| v == "true").unwrap_or(false);
    Ok(Json(SshDto { enabled, port, password_auth, permit_root_login }))
}

pub async fn put_ssh(
    State(state): State<AppState>,
    Json(req): Json<SshDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    validate_ssh_port(req.port).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    set_kv(&state.pool, "ssh_enabled", if req.enabled { "true" } else { "false" }).await;
    set_kv(&state.pool, "ssh_port", &req.port.to_string()).await;
    set_kv(&state.pool, "ssh_password_auth", if req.password_auth { "true" } else { "false" }).await;
    set_kv(&state.pool, "ssh_permit_root_login", if req.permit_root_login { "true" } else { "false" }).await;

    let report = apply_ssh(&SshInput {
        enabled: req.enabled,
        port: req.port,
        password_auth: req.password_auth,
        permit_root_login: req.permit_root_login,
    }).await;
    Ok(Json(report))
}
```

- [ ] **Step 3: Implement `apply_ssh` on FreeBSD** — replace the stub in `aifw-core/src/system_apply/freebsd_impl.rs`:

```rust
use aifw_core::system_apply_helpers::replace_managed_block;

pub async fn apply_ssh(i: &SshInput) -> ApplyReport {
    let mut warnings = Vec::new();

    // --- sshd_enable ---
    if let Err(e) = run("sysrc", &[&format!("sshd_enable={}", if i.enabled { "YES" } else { "NO" })]).await {
        warnings.push(format!("sysrc sshd_enable failed: {}", e));
    }

    // --- managed block in /etc/ssh/sshd_config ---
    let path = "/etc/ssh/sshd_config";
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let block = format!(
        "Port {}\nPasswordAuthentication {}\nPermitRootLogin {}\n",
        i.port,
        if i.password_auth { "yes" } else { "no" },
        if i.permit_root_login { "yes" } else { "no" },
    );
    let updated = replace_managed_block(&existing, "AiFw", &block);
    if let Err(e) = atomic_write(path, updated.as_bytes(), 0o600).await {
        warnings.push(format!("sshd_config write failed: {}", e));
    }

    // --- service action ---
    let service_action = if i.enabled { "start" } else { "stop" };
    if let Err(e) = run("service", &["sshd", service_action]).await {
        warnings.push(format!("service sshd {} failed: {}", service_action, e));
    }
    if i.enabled {
        let _ = run("service", &["sshd", "reload"]).await;
    }

    let mut r = ApplyReport::ok_requires_restart("sshd");
    if !warnings.is_empty() { r.warning = Some(warnings.join("; ")); }
    r
}
```

Note: `replace_managed_block` is in `aifw-core::system_apply_helpers`. Since `freebsd_impl.rs` is inside `aifw-core`, use `crate::system_apply_helpers::replace_managed_block`.

- [ ] **Step 4: Run tests**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: all SSH tests PASS.

- [ ] **Step 5: cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 6: Commit**

```bash
git add aifw-api/src/system.rs aifw-core/src/system_apply/freebsd_impl.rs aifw-api/tests/system_endpoints.rs
git commit -m "api: SSH access GET/PUT + FreeBSD apply via managed sshd_config block"
```

---

## Task 8: Console — API + FreeBSD apply (loader.conf block)

**Files:**
- Modify: `aifw-api/src/system.rs`
- Modify: `aifw-core/src/system_apply/freebsd_impl.rs`

- [ ] **Step 1: Add test cases** — append to `aifw-api/tests/system_endpoints.rs`:

```rust
#[tokio::test]
async fn console_defaults_and_round_trip() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let body: serde_json::Value = ts.get("/api/v1/system/console").add_header("authorization", h.clone()).await.json();
    assert_eq!(body["kind"], "video");
    assert_eq!(body["baud"], 115200);

    let r = ts.put("/api/v1/system/console")
        .add_header("authorization", h.clone())
        .json(&serde_json::json!({ "kind": "serial", "baud": 115200 }))
        .await;
    r.assert_status_ok();
    let report: serde_json::Value = r.json();
    assert_eq!(report["requires_reboot"], true);

    let back: serde_json::Value = ts.get("/api/v1/system/console").add_header("authorization", h).await.json();
    assert_eq!(back["kind"], "serial");
}

#[tokio::test]
async fn console_rejects_bad_baud() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/console")
        .add_header("authorization", h)
        .json(&serde_json::json!({ "kind": "video", "baud": 4242 }))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn console_rejects_bad_kind() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let r = ts.put("/api/v1/system/console")
        .add_header("authorization", h)
        .json(&serde_json::json!({ "kind": "braille", "baud": 115200 }))
        .await;
    r.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
```

- [ ] **Step 2: Replace console stubs in `aifw-api/src/system.rs`:**

```rust
use aifw_core::system_apply::{apply_console, ConsoleInput};
use aifw_core::system_apply_helpers::validate_baud;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsoleDto { pub kind: String, pub baud: u32 }

pub async fn get_console(State(state): State<AppState>) -> Result<Json<ConsoleDto>, StatusCode> {
    let kind = get_kv(&state.pool, "console_kind").await.unwrap_or_else(|| "video".to_string());
    let baud = get_kv(&state.pool, "console_baud").await.and_then(|v| v.parse().ok()).unwrap_or(115200);
    Ok(Json(ConsoleDto { kind, baud }))
}

pub async fn put_console(
    State(state): State<AppState>,
    Json(req): Json<ConsoleDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    match req.kind.as_str() {
        "video" | "serial" | "dual" => {}
        _ => return Err((StatusCode::BAD_REQUEST, "kind must be one of: video, serial, dual".into())),
    }
    validate_baud(req.baud).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    set_kv(&state.pool, "console_kind", &req.kind).await;
    set_kv(&state.pool, "console_baud", &req.baud.to_string()).await;

    let report = apply_console(&ConsoleInput { kind: req.kind, baud: req.baud }).await;
    Ok(Json(report))
}
```

- [ ] **Step 3: Implement `apply_console` on FreeBSD** — replace the stub:

```rust
pub async fn apply_console(i: &ConsoleInput) -> ApplyReport {
    let path = "/boot/loader.conf";
    let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();

    let console_val = match i.kind.as_str() {
        "serial" => "comconsole",
        "dual" => "comconsole vidconsole",
        _ => "vidconsole",
    };
    let block = format!(
        "console=\"{}\"\ncomconsole_speed=\"{}\"\n",
        console_val, i.baud,
    );
    let updated = crate::system_apply_helpers::replace_managed_block(&existing, "AiFw console", &block);

    let mut r = ApplyReport::ok_requires_reboot();
    if let Err(e) = atomic_write(path, updated.as_bytes(), 0o644).await {
        r.warning = Some(format!("loader.conf write failed: {}", e));
    }
    r
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: all console tests PASS.

- [ ] **Step 5: cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 6: Commit**

```bash
git add aifw-api/src/system.rs aifw-core/src/system_apply/freebsd_impl.rs aifw-api/tests/system_endpoints.rs
git commit -m "api: console GET/PUT + FreeBSD apply via managed loader.conf block"
```

---

## Task 9: System info + timezone list

**Files:**
- Modify: `aifw-api/src/system.rs`
- Modify: `aifw-core/src/system_apply/freebsd_impl.rs`

- [ ] **Step 1: Add test cases** — append to `aifw-api/tests/system_endpoints.rs`:

```rust
#[tokio::test]
async fn info_returns_shape() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let body: serde_json::Value = ts.get("/api/v1/system/info").add_header("authorization", h).await.json();
    assert!(body["os_version"].is_string());
    assert!(body["cpu_count"].as_u64().unwrap() >= 1);
    assert!(body["mem_total_bytes"].as_u64().unwrap() > 0);
    assert!(body["load_avg"].is_array());
    assert_eq!(body["load_avg"].as_array().unwrap().len(), 3);
    assert!(body["temperatures_c"].is_array());
}

#[tokio::test]
async fn timezones_non_empty_includes_utc() {
    let ts = test_server().await;
    let h = auth_header_admin(&ts).await;
    let body: Vec<String> = ts.get("/api/v1/system/timezones").add_header("authorization", h).await.json();
    assert!(!body.is_empty());
    assert!(body.iter().any(|z| z == "UTC"));
}
```

- [ ] **Step 2: Replace info + timezones stubs in `aifw-api/src/system.rs`:**

```rust
use aifw_core::system_apply::{collect_info, SystemInfo};

pub async fn get_info() -> Result<Json<SystemInfo>, StatusCode> {
    Ok(Json(collect_info().await))
}

pub async fn list_timezones() -> Result<Json<Vec<String>>, StatusCode> {
    Ok(Json(enumerate_timezones()))
}

#[cfg(target_os = "freebsd")]
fn enumerate_timezones() -> Vec<String> {
    use std::path::PathBuf;
    fn walk(base: &std::path::Path, prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(base) else { return };
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') { continue; }
            // Skip non-zone files
            if ["posix", "right", "Etc"].contains(&name.as_str()) && prefix.is_empty() {
                // keep Etc for UTC
                if name != "Etc" { continue; }
            }
            let joined = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
            let ft = match e.file_type() { Ok(t) => t, Err(_) => continue };
            if ft.is_dir() {
                walk(&path, &joined, out);
            } else if ft.is_file() {
                out.push(joined);
            }
        }
    }
    let mut out = Vec::new();
    walk(&PathBuf::from("/usr/share/zoneinfo"), "", &mut out);
    if !out.iter().any(|z| z == "UTC") { out.push("UTC".to_string()); }
    out.sort();
    out.dedup();
    out
}

#[cfg(not(target_os = "freebsd"))]
fn enumerate_timezones() -> Vec<String> {
    // Fixed short list for Linux dev so the UI has something to render.
    ["UTC", "America/Chicago", "America/Los_Angeles", "America/New_York",
     "Europe/London", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"]
        .iter().map(|s| s.to_string()).collect()
}
```

- [ ] **Step 3: Implement `collect_info` on FreeBSD** — replace the stub:

```rust
pub async fn collect_info() -> SystemInfo {
    let hostname = read_sysctl_str("kern.hostname").unwrap_or_default();
    let os_release = run_stdout("uname", &["-sr"]).await.unwrap_or_default();
    let kernel = run_stdout("uname", &["-v"]).await.unwrap_or_default();
    let cpu_model = read_sysctl_str("hw.model").unwrap_or_default();
    let cpu_count: u32 = read_sysctl_int("hw.ncpu").unwrap_or(1);
    let mem_total: u64 = read_sysctl_int("hw.physmem").unwrap_or(0);
    let uptime_secs = uptime_from_boottime().unwrap_or(0);
    let load_avg = read_loadavg().unwrap_or([0.0, 0.0, 0.0]);
    let domain = tokio::fs::read_to_string("/etc/resolv.conf").await.ok()
        .and_then(|s| s.lines()
            .find_map(|l| l.strip_prefix("search ").or_else(|| l.strip_prefix("domain ")))
            .map(|v| v.split_whitespace().next().unwrap_or("").to_string()))
        .unwrap_or_default();

    // Disk: statfs / via `df -k /`
    let (disk_total, disk_used) = df_root().await.unwrap_or((0, 0));
    // Mem used: hw.physmem - (free * pagesize). Keep simple via sysctl.
    let (mem_used, _) = mem_used_bytes().unwrap_or((0, 0));
    let temperatures_c = read_cpu_temps(cpu_count);

    SystemInfo {
        hostname, domain,
        os_version: os_release.trim().to_string(),
        kernel: kernel.trim().to_string(),
        uptime_secs,
        load_avg,
        cpu_model, cpu_count,
        cpu_usage_pct: 0.0, // best-effort; skip dual-sample for v1
        mem_total_bytes: mem_total,
        mem_used_bytes: mem_used,
        disk_total_bytes: disk_total,
        disk_used_bytes: disk_used,
        temperatures_c,
    }
}

async fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let out = tokio::process::Command::new(cmd).args(args).output().await.ok()?;
    if !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_sysctl_str(name: &str) -> Option<String> {
    let out = std::process::Command::new("sysctl").args(["-n", name]).output().ok()?;
    if !out.status.success() { return None; }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn read_sysctl_int<T: std::str::FromStr>(name: &str) -> Option<T> {
    read_sysctl_str(name)?.parse().ok()
}

fn uptime_from_boottime() -> Option<u64> {
    // `sysctl -n kern.boottime` → "{ sec = 1234567890, usec = 0 } ..."
    let s = read_sysctl_str("kern.boottime")?;
    let sec: u64 = s.split("sec = ").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(sec))
}

fn read_loadavg() -> Option<[f64; 3]> {
    // `sysctl -n vm.loadavg` → "{ 0.05 0.10 0.08 }"
    let s = read_sysctl_str("vm.loadavg")?;
    let nums: Vec<f64> = s.split_whitespace()
        .filter_map(|w| w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.').parse().ok())
        .collect();
    if nums.len() >= 3 { Some([nums[0], nums[1], nums[2]]) } else { None }
}

async fn df_root() -> Option<(u64, u64)> {
    // `df -k /` → "Filesystem  1K-blocks  Used  Avail  Capacity  Mounted on"
    let out = run_stdout("df", &["-k", "/"]).await?;
    let line = out.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 4 { return None; }
    let total: u64 = cols[1].parse().ok()?;
    let used: u64 = cols[2].parse().ok()?;
    Some((total * 1024, used * 1024))
}

fn mem_used_bytes() -> Option<(u64, u64)> {
    let page_size: u64 = read_sysctl_int("hw.pagesize").unwrap_or(4096);
    let total: u64 = read_sysctl_int("hw.physmem")?;
    let free: u64 = read_sysctl_int("vm.stats.vm.v_free_count")?;
    Some((total.saturating_sub(free * page_size), total))
}

fn read_cpu_temps(n: u32) -> Vec<CpuTemp> {
    let mut out = Vec::new();
    for core in 0..n {
        let name = format!("dev.cpu.{}.temperature", core);
        let Some(raw) = read_sysctl_str(&name) else { continue };
        // FreeBSD reports "38.0C"
        let celsius: f32 = raw.trim_end_matches('C').parse().unwrap_or(0.0);
        out.push(CpuTemp { core, celsius });
    }
    out
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test --package aifw-api --test system_endpoints`
Expected: all info + timezone tests PASS.

- [ ] **Step 5: cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 6: Commit**

```bash
git add aifw-api/src/system.rs aifw-core/src/system_apply/freebsd_impl.rs aifw-api/tests/system_endpoints.rs
git commit -m "api: /system/info + /system/timezones with FreeBSD sysctl collection"
```

---

## Task 10: UI — four new cards under `/settings?cat=system`

**Files:**
- Modify: `aifw-ui/src/app/settings/page.tsx`

Add four cards to the existing `System` category. Reading the existing patterns at lines 14, 1905, 1963 of `page.tsx`, each card follows this shape:
- `<section className={sectionCls}>` wrapper
- `<FeedbackBanner feedback={...} />`
- fields via `inputCls` / `labelCls`
- Save button via `saveBtnCls`

- [ ] **Step 1: Update `CATEGORIES` entry** — in `aifw-ui/src/app/settings/page.tsx` line 14, replace:

```typescript
{ key: "system",  label: "System",          sections: ["System Actions", "pf State Table"] },
```

with:

```typescript
{ key: "system",  label: "System",          sections: ["General", "Login Banner & MOTD", "SSH Access", "Console", "System Actions", "pf State Table"] },
```

- [ ] **Step 2: Add state + load effect for the new cards** — inside `SettingsPage` (near the other `useState` blocks around line 55–90):

```typescript
// --- System General ---
const [sysHostname, setSysHostname] = useState("");
const [sysDomain, setSysDomain] = useState("");
const [sysTimezone, setSysTimezone] = useState("UTC");
const [timezoneList, setTimezoneList] = useState<string[]>([]);
const [generalFeedback, setGeneralFeedback] = useState<SectionFeedback | null>(null);
const [generalSaving, setGeneralSaving] = useState(false);

// --- System Banner ---
const [loginBanner, setLoginBanner] = useState("");
const [motdBody, setMotdBody] = useState("");
const [bannerFeedback, setBannerFeedback] = useState<SectionFeedback | null>(null);
const [bannerSaving, setBannerSaving] = useState(false);

// --- System SSH ---
const [sshEnabled, setSshEnabled] = useState(true);
const [sshPort, setSshPort] = useState(22);
const [sshPasswordAuth, setSshPasswordAuth] = useState(false);
const [sshPermitRoot, setSshPermitRoot] = useState(false);
const [sshFeedback, setSshFeedback] = useState<SectionFeedback | null>(null);
const [sshSaving, setSshSaving] = useState(false);

// --- System Console ---
const [consoleKind, setConsoleKind] = useState<"video" | "serial" | "dual">("video");
const [consoleBaud, setConsoleBaud] = useState(115200);
const [consoleFeedback, setConsoleFeedback] = useState<SectionFeedback | null>(null);
const [consoleSaving, setConsoleSaving] = useState(false);
const [consoleConfirm, setConsoleConfirm] = useState(false);
```

- [ ] **Step 3: Add data fetch** — find the existing `useEffect` that loads all settings on mount (search for the first `useEffect(` in the file, around line 250–400) and add these fetches alongside:

```typescript
// General
authFetch("/api/v1/system/general").then(r => r.json()).then(d => {
  setSysHostname(d.hostname || "");
  setSysDomain(d.domain || "");
  setSysTimezone(d.timezone || "UTC");
}).catch(() => {});

authFetch("/api/v1/system/timezones").then(r => r.json()).then(setTimezoneList).catch(() => setTimezoneList(["UTC"]));

authFetch("/api/v1/system/banner").then(r => r.json()).then(d => {
  setLoginBanner(d.login_banner || "");
  setMotdBody(d.motd || "");
}).catch(() => {});

authFetch("/api/v1/system/ssh").then(r => r.json()).then(d => {
  setSshEnabled(d.enabled); setSshPort(d.port);
  setSshPasswordAuth(d.password_auth); setSshPermitRoot(d.permit_root_login);
}).catch(() => {});

authFetch("/api/v1/system/console").then(r => r.json()).then(d => {
  setConsoleKind(d.kind); setConsoleBaud(d.baud);
}).catch(() => {});
```

- [ ] **Step 4: Add save handlers** — just below the other save handlers (search for `const savePf`):

```typescript
const saveGeneral = async () => {
  setGeneralSaving(true); setGeneralFeedback(null);
  try {
    const r = await authFetch("/api/v1/system/general", {
      method: "PUT",
      body: JSON.stringify({ hostname: sysHostname, domain: sysDomain, timezone: sysTimezone }),
    });
    if (!r.ok) throw new Error(await r.text());
    const res = await r.json();
    const msg = res.warning ? `Saved (warning: ${res.warning})` : "Saved.";
    setGeneralFeedback({ type: res.warning ? "error" : "success", message: msg });
  } catch (e) { setGeneralFeedback({ type: "error", message: String(e) }); }
  finally { setGeneralSaving(false); }
};

const saveBanner = async () => {
  setBannerSaving(true); setBannerFeedback(null);
  try {
    const r = await authFetch("/api/v1/system/banner", {
      method: "PUT",
      body: JSON.stringify({ login_banner: loginBanner, motd: motdBody }),
    });
    if (!r.ok) throw new Error(await r.text());
    setBannerFeedback({ type: "success", message: "Saved." });
  } catch (e) { setBannerFeedback({ type: "error", message: String(e) }); }
  finally { setBannerSaving(false); }
};

const saveSsh = async () => {
  setSshSaving(true); setSshFeedback(null);
  try {
    const r = await authFetch("/api/v1/system/ssh", {
      method: "PUT",
      body: JSON.stringify({ enabled: sshEnabled, port: sshPort, password_auth: sshPasswordAuth, permit_root_login: sshPermitRoot }),
    });
    if (!r.ok) throw new Error(await r.text());
    const res = await r.json();
    setSshFeedback({ type: "success", message: `Saved. sshd reloading${sshPort !== 22 ? ` — reconnect on port ${sshPort}` : ""}.` });
  } catch (e) { setSshFeedback({ type: "error", message: String(e) }); }
  finally { setSshSaving(false); }
};

const saveConsole = async () => {
  setConsoleSaving(true); setConsoleFeedback(null);
  try {
    const r = await authFetch("/api/v1/system/console", {
      method: "PUT",
      body: JSON.stringify({ kind: consoleKind, baud: consoleBaud }),
    });
    if (!r.ok) throw new Error(await r.text());
    setConsoleFeedback({ type: "success", message: "Saved. Reboot required. Verify console access before rebooting." });
    setConsoleConfirm(false);
  } catch (e) { setConsoleFeedback({ type: "error", message: String(e) }); }
  finally { setConsoleSaving(false); }
};
```

- [ ] **Step 5: Insert the four new `<section>` cards** — in the JSX return, immediately before the existing `<section>` for `"pf State Table"` (search for `inCategory("pf State Table")`, around line 1905), insert these four cards:

```tsx
{/* General */}
<section className={`${sectionCls} ${inCategory("General") ? "" : "hidden"}`}>
  <div className="flex items-center justify-between mb-4">
    <h2 className="font-medium">General</h2>
    <a href="/system/info" className="text-xs text-[var(--accent)] hover:underline">View live system info →</a>
  </div>
  <FeedbackBanner feedback={generalFeedback} />
  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
    <div>
      <label className={labelCls}>Hostname</label>
      <input className={inputCls} value={sysHostname} onChange={e => setSysHostname(e.target.value)} />
    </div>
    <div>
      <label className={labelCls}>Domain</label>
      <input className={inputCls} value={sysDomain} onChange={e => setSysDomain(e.target.value)} placeholder="home.lan" />
    </div>
    <div>
      <label className={labelCls}>Timezone</label>
      <input
        list="tz-list"
        className={inputCls}
        value={sysTimezone}
        onChange={e => setSysTimezone(e.target.value)}
      />
      <datalist id="tz-list">
        {timezoneList.map(tz => <option key={tz} value={tz} />)}
      </datalist>
    </div>
  </div>
  <div className="flex justify-end mt-4">
    <button onClick={saveGeneral} disabled={generalSaving} className={saveBtnCls}>
      {generalSaving ? "Saving…" : "Save"}
    </button>
  </div>
</section>

{/* Login Banner & MOTD */}
<section className={`${sectionCls} ${inCategory("Login Banner & MOTD") ? "" : "hidden"}`}>
  <h2 className="font-medium mb-4">Login Banner & MOTD</h2>
  <FeedbackBanner feedback={bannerFeedback} />
  <p className="text-xs text-[var(--text-muted)] mb-3">
    Banner shows before login (SSH / console). MOTD shows after login.
  </p>
  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
    <div>
      <label className={labelCls}>Login Banner (/etc/issue)</label>
      <textarea className={`${inputCls} font-mono`} rows={8} value={loginBanner} onChange={e => setLoginBanner(e.target.value)} />
    </div>
    <div>
      <label className={labelCls}>MOTD (/etc/motd.template)</label>
      <textarea className={`${inputCls} font-mono`} rows={8} value={motdBody} onChange={e => setMotdBody(e.target.value)} />
    </div>
  </div>
  <div className="flex justify-end mt-4">
    <button onClick={saveBanner} disabled={bannerSaving} className={saveBtnCls}>
      {bannerSaving ? "Saving…" : "Save"}
    </button>
  </div>
</section>

{/* SSH Access */}
<section className={`${sectionCls} ${inCategory("SSH Access") ? "" : "hidden"}`}>
  <h2 className="font-medium mb-4">SSH Access</h2>
  <FeedbackBanner feedback={sshFeedback} />
  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={sshEnabled} onChange={e => setSshEnabled(e.target.checked)} />
      <span>SSH enabled</span>
    </label>
    <div>
      <label className={labelCls}>Port {sshPort !== 22 && <span className="text-yellow-400">(non-default)</span>}</label>
      <input type="number" min={1} max={65535} className={inputCls} value={sshPort} onChange={e => setSshPort(Number(e.target.value) || 22)} />
    </div>
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={sshPasswordAuth} onChange={e => setSshPasswordAuth(e.target.checked)} />
      <span>Password authentication (insecure)</span>
    </label>
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={sshPermitRoot} onChange={e => setSshPermitRoot(e.target.checked)} />
      <span>Permit root login</span>
    </label>
  </div>
  <div className="flex justify-end mt-4">
    <button onClick={saveSsh} disabled={sshSaving} className={saveBtnCls}>
      {sshSaving ? "Saving…" : "Save"}
    </button>
  </div>
</section>

{/* Console */}
<section className={`${sectionCls} ${inCategory("Console") ? "" : "hidden"}`}>
  <h2 className="font-medium mb-4">Console</h2>
  <FeedbackBanner feedback={consoleFeedback} />
  <p className="text-xs text-yellow-300 mb-3">
    Changing the console requires a reboot and can break console access if misconfigured.
    Verify you have access on the selected device before rebooting.
  </p>
  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
    <div>
      <label className={labelCls}>Console</label>
      <div className="flex gap-4 mt-1">
        {(["video","serial","dual"] as const).map(k => (
          <label key={k} className="flex items-center gap-2">
            <input type="radio" checked={consoleKind === k} onChange={() => setConsoleKind(k)} />
            <span>{k}</span>
          </label>
        ))}
      </div>
    </div>
    <div>
      <label className={labelCls}>Baud</label>
      <select className={inputCls} value={consoleBaud} onChange={e => setConsoleBaud(Number(e.target.value))}>
        {[9600,19200,38400,57600,115200].map(b => <option key={b} value={b}>{b}</option>)}
      </select>
    </div>
  </div>
  <div className="flex justify-end mt-4 gap-2">
    {!consoleConfirm ? (
      <button onClick={() => setConsoleConfirm(true)} className={saveBtnCls}>Apply</button>
    ) : (
      <>
        <button onClick={() => setConsoleConfirm(false)} className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]">Cancel</button>
        <button onClick={saveConsole} disabled={consoleSaving} className="px-4 py-2 text-sm font-medium rounded-md bg-orange-600 hover:bg-orange-700 text-white">
          {consoleSaving ? "Saving…" : "Confirm & Save"}
        </button>
      </>
    )}
  </div>
</section>
```

- [ ] **Step 6: Build the UI**

Run: `cd aifw-ui && npm run build && cd ..`
Expected: compiles cleanly, static export succeeds.

- [ ] **Step 7: Run lint**

Run: `cd aifw-ui && npm run lint && cd ..`
Expected: zero errors.

- [ ] **Step 8: Commit**

```bash
git add aifw-ui/src/app/settings/page.tsx
git commit -m "ui: add System cards for General, Banner & MOTD, SSH, Console"
```

---

## Task 11: UI — `/system/info` dashboard page + sidebar link

**Files:**
- Create: `aifw-ui/src/app/system/info/page.tsx`
- Modify: `aifw-ui/src/components/Sidebar.tsx`

- [ ] **Step 1: Create `aifw-ui/src/app/system/info/page.tsx`:**

```tsx
"use client";

import { useState, useEffect } from "react";

interface SysInfo {
  hostname: string; domain: string;
  os_version: string; kernel: string;
  uptime_secs: number;
  load_avg: [number, number, number];
  cpu_model: string; cpu_count: number; cpu_usage_pct: number;
  mem_total_bytes: number; mem_used_bytes: number;
  disk_total_bytes: number; disk_used_bytes: number;
  temperatures_c: { core: number; celsius: number }[];
}

function authFetch(url: string): Promise<Response> {
  const token = typeof window !== "undefined" ? (localStorage.getItem("aifw_token") || "") : "";
  return fetch(url, { headers: { Authorization: `Bearer ${token}` } });
}

function fmtDuration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtBytes(b: number): string {
  const units = ["B","KB","MB","GB","TB"];
  let v = b; let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

export default function SystemInfoPage() {
  const [info, setInfo] = useState<SysInfo | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      if (document.visibilityState !== "visible") return;
      try {
        const r = await authFetch("/api/v1/system/info");
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (!cancelled) { setInfo(d); setErr(null); }
      } catch (e) {
        if (!cancelled) setErr(String(e));
      }
    }
    tick();
    const id = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (err) return <div className="p-6 text-red-400">Failed: {err}</div>;
  if (!info) return <div className="p-6 text-[var(--text-muted)]">Loading…</div>;

  const memPct = info.mem_total_bytes ? (info.mem_used_bytes / info.mem_total_bytes) * 100 : 0;
  const diskPct = info.disk_total_bytes ? (info.disk_used_bytes / info.disk_total_bytes) * 100 : 0;

  const tileCls = "bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4";
  const labelCls = "text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1";
  const barCls = "h-2 bg-[var(--bg-input)] rounded mt-2 overflow-hidden";

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-bold">System Info</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className={tileCls}>
          <div className={labelCls}>Identity</div>
          <div className="text-lg font-medium">{info.hostname || "(none)"}<span className="text-[var(--text-muted)]">{info.domain ? `.${info.domain}` : ""}</span></div>
          <div className="text-xs text-[var(--text-muted)] mt-1">{info.os_version}</div>
          <div className="text-xs text-[var(--text-muted)]">{info.kernel}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Uptime</div>
          <div className="text-2xl font-semibold">{fmtDuration(info.uptime_secs)}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Load avg (1 / 5 / 15 m)</div>
          <div className="text-lg font-mono">{info.load_avg.map(n => n.toFixed(2)).join(" / ")}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>CPU</div>
          <div className="text-sm">{info.cpu_model}</div>
          <div className="text-xs text-[var(--text-muted)] mt-1">{info.cpu_count} cores</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Memory</div>
          <div className="text-sm">{fmtBytes(info.mem_used_bytes)} / {fmtBytes(info.mem_total_bytes)}</div>
          <div className={barCls}><div style={{ width: `${memPct}%` }} className="h-full bg-[var(--accent)]" /></div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Root disk</div>
          <div className="text-sm">{fmtBytes(info.disk_used_bytes)} / {fmtBytes(info.disk_total_bytes)}</div>
          <div className={barCls}><div style={{ width: `${diskPct}%` }} className="h-full bg-[var(--accent)]" /></div>
        </div>
        {info.temperatures_c.length > 0 && (
          <div className={`${tileCls} md:col-span-2 lg:col-span-3`}>
            <div className={labelCls}>CPU Temperatures</div>
            <div className="grid grid-cols-4 md:grid-cols-8 gap-2 mt-2">
              {info.temperatures_c.map(t => (
                <div key={t.core} className="text-sm text-center">
                  <div className="text-xs text-[var(--text-muted)]">Core {t.core}</div>
                  <div className="font-mono">{t.celsius.toFixed(1)}°C</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Add sidebar link** — in `aifw-ui/src/components/Sidebar.tsx`, find the existing System-group entries (search for `label: "Settings"` or for the existing link ordering around lines 140–150). Immediately after the entry that leads to `/settings?cat=system` (or next to it), add:

```typescript
{ label: "System Info", href: "/system/info", icon: /* use whichever icon component pattern the sidebar uses — match neighboring entries */ },
```

The exact object shape must match the existing entries in that file (some codebases use `label`/`href`, others use `name`/`path`). Copy the pattern of a neighboring entry (e.g., the Users or Updates entry at lines 136–137) and substitute the label / href.

- [ ] **Step 3: Build the UI**

Run: `cd aifw-ui && npm run build && cd ..`
Expected: succeeds. The new page appears at `aifw-ui/out/system/info/index.html`.

- [ ] **Step 4: Run lint**

Run: `cd aifw-ui && npm run lint && cd ..`
Expected: zero errors.

- [ ] **Step 5: Commit**

```bash
git add aifw-ui/src/app/system/info/page.tsx aifw-ui/src/components/Sidebar.tsx
git commit -m "ui: add /system/info live dashboard + sidebar link"
```

---

## Task 12: Remove version from fresh-install MOTD

**Files:**
- Modify: `freebsd/build-iso.sh`

- [ ] **Step 1: Edit `freebsd/build-iso.sh`** — find the MOTD heredoc at lines 244–257 and change:

```sh
# MOTD
cat > "$STAGEDIR/etc/motd.template" <<MOTD

  AiFw ${VERSION} — AI-Powered Firewall for FreeBSD

  Commands:
    aifw-console        Launch the management menu
```

to:

```sh
# MOTD — version intentionally omitted; lives in /usr/local/share/aifw/version
cat > "$STAGEDIR/etc/motd.template" <<MOTD

  Commands:
    aifw-console        Launch the management menu
```

Keep the rest of the heredoc (Commands / Web UI lines) unchanged.

- [ ] **Step 2: Verify the file still parses**

Run: `bash -n freebsd/build-iso.sh`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
git add freebsd/build-iso.sh
git commit -m "installer: drop AiFw version line from MOTD template"
```

---

## Task 13: MOTD cleanup helper + wire into deploy.sh and updater.rs

**Files:**
- Create: `freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh`
- Modify: `freebsd/deploy.sh`
- Modify: `aifw-core/src/updater.rs`

- [ ] **Step 1: Create the helper script** at `freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh`:

```sh
#!/bin/sh
# aifw-motd-cleanup.sh — idempotent MOTD version stripper.
#
# Removes any "AiFw <version> — AI-Powered ..." line from /etc/motd.template.
# Skips if the admin has customized MOTD via the UI (marker file present).

set -eu

MARKER="/var/db/aifw/motd.user-edited"
TEMPLATE="/etc/motd.template"

if [ -f "$MARKER" ]; then
    # Admin has customized MOTD — leave it alone.
    exit 0
fi

if [ ! -f "$TEMPLATE" ]; then
    exit 0
fi

# POSIX sed in place: FreeBSD requires `-i ''`, GNU sed accepts `-i`.
# Detect and branch.
if sed --version >/dev/null 2>&1; then
    SED_INPLACE="sed -i"
else
    SED_INPLACE="sed -i ''"
fi

# Strip version line and an immediately-following blank line if that leaves one.
# Matches: optional leading whitespace + "AiFw <number> — " + "AI-Powered"
$SED_INPLACE -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' "$TEMPLATE"
exit 0
```

- [ ] **Step 2: Make it executable and add a test** — create `freebsd/tests/motd-cleanup.sh`:

```sh
#!/bin/sh
# Test harness for aifw-motd-cleanup.sh. Runs on the dev host.
set -eu

SCRIPT="$(dirname "$0")/../overlay/usr/local/libexec/aifw-motd-cleanup.sh"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Swap paths by running the script in a sandboxed env via sed-substitution.
# Simpler approach: run the core sed command directly against a fixture.
FIXTURE="$TMPDIR/motd"

# 1. With version line → stripped
cat > "$FIXTURE" <<EOF

  AiFw 5.71.9 — AI-Powered Firewall for FreeBSD

  Commands: do stuff
EOF

if sed --version >/dev/null 2>&1; then
    sed -i -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' "$FIXTURE"
else
    sed -i '' -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' "$FIXTURE"
fi

grep -q "AiFw" "$FIXTURE" && { echo "FAIL: version line not removed"; exit 1; }
grep -q "Commands: do stuff" "$FIXTURE" || { echo "FAIL: kept content was removed"; exit 1; }

# 2. Without version line → idempotent
cat > "$FIXTURE" <<EOF

  Commands: do stuff
EOF

ORIG=$(cat "$FIXTURE")
if sed --version >/dev/null 2>&1; then
    sed -i -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' "$FIXTURE"
else
    sed -i '' -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' "$FIXTURE"
fi
NEW=$(cat "$FIXTURE")
[ "$ORIG" = "$NEW" ] || { echo "FAIL: idempotent case modified content"; exit 1; }

echo "OK"
```

Make both executable:

```bash
chmod +x freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh freebsd/tests/motd-cleanup.sh
```

- [ ] **Step 3: Run the test**

Run: `sh freebsd/tests/motd-cleanup.sh`
Expected: output `OK`, exit 0.

- [ ] **Step 4: Wire into `freebsd/deploy.sh`** — find the section that copies binaries to `/usr/local/sbin/` and restarts services. After the copy step and before `service aifw restart` (or the equivalent final restart), add:

```sh
# Strip stale AiFw version from MOTD template (idempotent; respects user customizations).
if [ -x /usr/local/libexec/aifw-motd-cleanup.sh ]; then
    /usr/local/libexec/aifw-motd-cleanup.sh || true
fi
```

(Use `|| true` so a cleanup failure never aborts the deploy.)

- [ ] **Step 5: Wire into `aifw-core/src/updater.rs`** — find `download_and_install()` at line 144. After the tarball is extracted and binaries moved into place but before `restart_services()` is called, add:

```rust
// Strip stale AiFw version from MOTD template. Idempotent and respects
// the marker file that `apply_banner` sets when the admin edits MOTD.
#[cfg(target_os = "freebsd")]
{
    let _ = tokio::process::Command::new("/usr/local/libexec/aifw-motd-cleanup.sh")
        .output().await;
}
```

- [ ] **Step 6: cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 7: Commit**

```bash
git add freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh freebsd/tests/motd-cleanup.sh freebsd/deploy.sh aifw-core/src/updater.rs
git commit -m "updater: strip AiFw version from MOTD on deploy + in-place update"
```

---

## Task 14: Final verification + version bump

- [ ] **Step 1: Full workspace test**

Run: `cargo test --workspace`
Expected: all tests pass. Tally any new failures and fix before proceeding.

- [ ] **Step 2: Full cargo check with zero warnings**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 3: Build the UI**

Run: `cd aifw-ui && npm run build && cd ..`
Expected: static export succeeds; no warnings.

- [ ] **Step 4: Bump versions** — per `CLAUDE.md`, this is a **minor** bump (feature addition). Read the current version in `Cargo.toml` at `[workspace.package] version`, e.g. `5.71.9`. Bump to `5.72.0`.

Edit `Cargo.toml` (root) — the `version = "..."` line under `[workspace.package]`. Edit `aifw-ui/package.json` — the `"version": "..."` field to match.

- [ ] **Step 5: Final cargo check**

Run: `cargo check --workspace`
Expected: zero warnings.

- [ ] **Step 6: Final commit**

```bash
git add Cargo.toml aifw-ui/package.json
git commit -m "release: bump to 5.72.0 — system settings basics + MOTD cleanup"
```

- [ ] **Step 7: Manual smoke on test VM** (per `CLAUDE.md`'s deploy workflow)

```bash
ssh root@172.29.69.159 "cd /root/AiFw && git pull && sh freebsd/deploy.sh"
```

Then in a browser at `http://172.29.69.159:8080/` (or https on the configured port), verify:

- `/settings?cat=system` shows all four new cards (General, Banner & MOTD, SSH Access, Console)
- Editing hostname saves; `ssh root@<vm>` shows the new hostname in the prompt within a few seconds
- Editing MOTD and logging back in shows the new MOTD; MOTD no longer shows the `AiFw <version>` line
- `/system/info` loads and shows live uptime, load, memory, disk
- `cat /etc/motd.template` shows the user's edited content; `/var/db/aifw/motd.user-edited` exists
- On a fresh install (if available), `/etc/motd.template` has no `AiFw <version>` line

If any smoke check fails, open an issue / add a follow-up task rather than trying to fix it in this PR.

---

## Self-review checklist

Before declaring the plan complete, verify:

- [ ] Every spec section has a matching task
  - Section 1 (Data model) → Task 1
  - Section 2 (API) → Tasks 4, 6, 7, 8, 9
  - Section 3 (FreeBSD apply) → Tasks 5, 6, 7, 8, 9
  - Section 4 (UI) → Tasks 10, 11
  - Section 5 (MOTD cleanup) → Tasks 12, 13
  - Section 6 (Tests) → test steps embedded in each task
- [ ] No placeholders ("TBD", "similar to", etc.) — scanned, none present
- [ ] Type consistency — `ApplyReport`, `SystemInfo`, `GeneralInput`/`BannerInput`/`ConsoleInput`/`SshInput` used consistently across Tasks 3–9; DTOs (`GeneralDto` etc.) used consistently in Task 4–9; UI state names consistent across Tasks 10–11
- [ ] KV keys used in API match KV keys read by the API (`hostname`, `domain`, `timezone`, `login_banner`, `motd`, `ssh_enabled`, `ssh_port`, `ssh_password_auth`, `ssh_permit_root_login`, `console_kind`, `console_baud`)
