# System Settings — OPNsense/pfSense Parity (Basics)

**Date:** 2026-04-21
**Status:** Draft — awaiting user review
**Scope:** Add core "System" settings to the AiFw web UI that OPNsense/pfSense users expect (hostname, domain, timezone, login banner/MOTD, console, SSH), plus a read-only System Info dashboard. Also removes the AiFw version string from `/etc/motd` on both fresh installs and upgrades.

## Motivation

The `System` category in `aifw-ui/src/app/settings/page.tsx` currently exposes only two cards: `System Actions` (reboot button) and `pf State Table`. Baseline system configuration that every competing firewall UI exposes — hostname, domain, timezone, login banner, SSH access, console selection, system info — is either set only in the first-boot wizard (`aifw-setup`), or not configurable at all. Users who want to change hostname after first boot, switch from video to serial console, tighten SSH, or see live system info currently have to shell in.

Separately, the MOTD template baked by `freebsd/build-iso.sh` embeds the AiFw version at install time and the updater never touches it, so upgraded appliances show a permanently stale version in their MOTD. The version belongs on the About page and in `/usr/local/share/aifw/version`; it should not be in MOTD.

## Non-goals

- Gateway / static route / interface editing (already live under `/multi-wan` and `/interfaces`)
- DNS resolver configuration (already live under `/dns` and `Settings → DNS`)
- NTP configuration (already live under `/time`)
- User / API-key management (already live under `/users`)
- Sysctl / loader.conf tunables beyond the console-related ones (deferred; first-boot wizard already writes tuning files)
- Backup / update / plugin flows (already live under `/backup`, `/updates`, `/plugins`)
- Kernel-level firewall tuning beyond the existing `pf State Table` card

## Architecture Overview

Four layers, mirroring the existing engine pattern described in `CLAUDE.md`:

1. **Config model** — extend the existing `SystemConfig` struct in `aifw-core/src/config.rs`. Persistence is the existing JSON config file (`FirewallConfig::to_json` / `from_json`); no new sqlite table.
2. **Apply layer** — new `aifw-core/src/system_apply.rs` module with `#[cfg(target_os)]`-gated implementations. On Linux/WSL it's a no-op (mirroring `PfMock`). On FreeBSD it writes the right `/etc/*` and `/boot/loader.conf` files and triggers service actions.
3. **API** — new `aifw-api/src/system.rs` module mounted under `/api/v1/system/*`, admin-gated.
4. **UI** — new cards under `/settings?cat=system` plus a new top-level `/system/info` dashboard page.

## Data Model

### Extended `SystemConfig` (aifw-core/src/config.rs)

All new fields use `#[serde(default)]` so existing `config.json` files continue to load unchanged.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    // --- existing ---
    pub hostname: String,
    pub dns_servers: Vec<String>,
    pub wan_interface: String,
    pub lan_interface: Option<String>,
    pub lan_ip: Option<String>,
    pub api_listen: String,
    pub api_port: u16,
    pub ui_enabled: bool,

    // --- new ---
    #[serde(default)]
    pub domain: String,              // e.g. "home.lan"; empty = no search domain
    #[serde(default = "default_timezone")]
    pub timezone: String,            // IANA, default "UTC"
    #[serde(default)]
    pub login_banner: String,        // /etc/issue — shown before login
    #[serde(default)]
    pub motd: String,                // /etc/motd.template — shown after login
    #[serde(default)]
    pub console: ConsoleConfig,
    #[serde(default)]
    pub ssh: SshAccessConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub kind: ConsoleKind,
    #[serde(default = "default_baud")]
    pub baud: u32,                   // 9600 | 19200 | 38400 | 57600 | 115200
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleKind {
    #[default] Video,
    Serial,
    Dual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn default_timezone() -> String { "UTC".to_string() }
fn default_baud() -> u32 { 115200 }
```

Validation rules, enforced in the API handlers:

- `hostname` — RFC 1123 label (`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`), no dots (domain goes in `domain`)
- `domain` — empty string allowed, otherwise a DNS name
- `timezone` — must exist as `/usr/share/zoneinfo/<tz>` on FreeBSD; on Linux dev we accept any non-empty string but the apply path no-ops
- `ssh.port` — 1..=65535, must not equal the API port (`SystemConfig::api_port`)
- `ssh.enabled=false` + the current admin authed over SSH — not our problem to solve (this is a UI-driven change; admin is responsible)
- `console.baud` — one of the five speeds above
- `login_banner` / `motd` — max 8 KiB each

## API Surface

New routes under `/api/v1/system/*`, all admin-gated via the existing `require_admin` middleware. Implementation in `aifw-api/src/system.rs`, mounted from `build_router()` in `aifw-api/src/main.rs`.

| Method | Path | Body / query | Response |
|--------|------|--------------|----------|
| GET | `/system/general` | — | `{ hostname, domain, timezone }` |
| PUT | `/system/general` | `{ hostname, domain, timezone }` | `ApplyResult` |
| GET | `/system/banner` | — | `{ login_banner, motd }` |
| PUT | `/system/banner` | `{ login_banner, motd }` | `ApplyResult` |
| GET | `/system/console` | — | `{ kind, baud }` |
| PUT | `/system/console` | `{ kind, baud }` | `ApplyResult { requires_reboot: true, ... }` |
| GET | `/system/ssh` | — | `{ enabled, port, password_auth, permit_root_login }` |
| PUT | `/system/ssh` | `{ enabled, port, password_auth, permit_root_login }` | `ApplyResult { requires_service_restart: Some("sshd"), ... }` |
| GET | `/system/info` | — | `SystemInfo` (see below) |
| GET | `/system/timezones` | — | `Vec<String>` of IANA zones |

```rust
#[derive(Serialize)]
pub struct ApplyResult {
    pub ok: bool,
    pub requires_reboot: bool,
    pub requires_service_restart: Option<String>,
    pub warning: Option<String>,     // e.g. "SSH port changed to 2222 — reconnect on new port"
}

#[derive(Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub domain: String,
    pub os_version: String,          // `uname -sr`
    pub kernel: String,              // `uname -v`
    pub uptime_secs: u64,
    pub load_avg: [f64; 3],          // 1/5/15m
    pub cpu_model: String,
    pub cpu_count: u32,
    pub cpu_usage_pct: f32,          // rolling 5s
    pub mem_total_bytes: u64,
    pub mem_used_bytes: u64,
    pub disk_total_bytes: u64,       // `/` mount
    pub disk_used_bytes: u64,
    pub temperatures_c: Vec<CpuTemp>,  // may be empty
}

pub struct CpuTemp { pub core: u32, pub celsius: f32 }
```

`GET /system/timezones` reads `/usr/share/zoneinfo` on FreeBSD; on Linux dev it returns a hardcoded list of common zones (cached at startup). Result is static for the process lifetime, so it can be cached in `AppState`.

PUT handlers (`general`, `banner`, `console`, `ssh`):
1. Parse + validate request body. Return `400` on invalid input.
2. Mutate `FirewallConfig.system` in memory, write config.json via existing `to_json` path.
3. Call the corresponding `system_apply::apply_*` function.
4. Return `ApplyResult` reflecting what the apply layer reported.

On validation error the config is not mutated. On apply-layer failure the config **is** already persisted — we treat apply as best-effort and surface the error in `ApplyResult.warning`. (Alternative: transactional apply-before-persist. Rejected as overkill; admin can re-submit. Calling this out explicitly.)

## Apply Layer (`aifw-core/src/system_apply.rs`)

Module shape:

```rust
// Linux/WSL build — everything is a no-op returning a neutral ApplyResult.
#[cfg(not(target_os = "freebsd"))]
mod imp {
    pub fn apply_general(...) -> ApplyReport { ApplyReport::ok() }
    pub fn apply_banner(...) -> ApplyReport { ApplyReport::ok() }
    pub fn apply_console(...) -> ApplyReport { ApplyReport::ok_requires_reboot() }
    pub fn apply_ssh(...) -> ApplyReport { ApplyReport::ok_requires_service_restart("sshd") }
}

#[cfg(target_os = "freebsd")]
mod imp {
    // real implementations below
}

pub use imp::*;
```

`ApplyReport` is the internal type mapped 1:1 to the API's `ApplyResult`.

### FreeBSD apply — per field

| Field | Action |
|-------|--------|
| `hostname` | `sysrc hostname=<new>`; `hostname <new>` (live); rewrite `/etc/hosts` line for `127.0.1.1` |
| `domain` | rewrite the `search` line in `/etc/resolv.conf` (preserving nameserver lines); `sysrc hostname=<host>.<domain>` when domain set |
| `timezone` | copy `/usr/share/zoneinfo/<tz>` to `/etc/localtime`; write `<tz>` to `/var/db/zoneinfo`; no service action — running processes pick it up lazily, which is acceptable |
| `login_banner` | write to `/etc/issue` (mode 0644) |
| `motd` | write to `/etc/motd.template` (mode 0644); create `/var/db/aifw/motd.user-edited` marker so the updater stops managing it |
| `console.kind` + `console.baud` | rewrite managed block in `/boot/loader.conf` between `# BEGIN AiFw console / # END AiFw console` markers. Emits `console="vidconsole"` / `"comconsole"` / `"comconsole vidconsole"` plus `comconsole_speed="<baud>"` |
| `ssh.enabled` | `sysrc sshd_enable=YES|NO`; `service sshd start\|stop` |
| `ssh.port` / `password_auth` / `permit_root_login` | rewrite managed block in `/etc/ssh/sshd_config` between `# BEGIN AiFw / # END AiFw` markers; `service sshd reload` |

Managed-block rewriting is the key pattern — every file we touch that might have user edits gets a clearly delimited "AiFw-owned" block. Outside the markers the user's edits survive untouched.

All file writes are atomic (write to `<path>.tmp`, `fsync`, `rename`). All service actions use `/usr/sbin/service`. The existing sudoers setup (referenced at `aifw-setup/src/apply.rs:94`) already permits these.

### Failure handling

- File write failure → `ApplyReport::error(message)`, returned through the API as `ApplyResult.warning` (HTTP 200 — the config persisted). Admin sees a yellow banner in the UI.
- Service reload failure → same pattern.
- Invalid timezone on FreeBSD (file missing) is rejected at validation time by probing `/usr/share/zoneinfo/<tz>` existence, not at apply time.

### System info collection (FreeBSD)

`system_apply::collect_info()` returns `SystemInfo`:

- `uname -sr`, `uname -v` for OS / kernel
- `sysctl kern.boottime` → uptime
- `sysctl vm.loadavg` → load
- `sysctl hw.model`, `hw.ncpu` → CPU
- `sysctl kern.cp_time` sampled twice 500 ms apart → CPU %
- `sysctl hw.physmem`, `vm.stats.vm.v_free_count` etc. → memory
- `statfs("/")` → disk
- `sysctl dev.cpu.<N>.temperature` for each core → temps (silently empty if unavailable)

Linux dev returns a plausible stub with `uname` and `/proc` where possible so the UI has something to render.

## UI

### Existing page extension — `aifw-ui/src/app/settings/page.tsx`

Four new cards added to the `System` category (the `CATEGORIES` entry at `page.tsx:14`). Order of cards in the category, top to bottom:

1. **General** — hostname, domain, timezone
   - Fields: `<input>` hostname, `<input>` domain, searchable dropdown timezone (populated from `GET /system/timezones`; default-selected is the current value)
   - Save button posts to `PUT /system/general`, uses `FeedbackBanner` for result
2. **Login Banner & MOTD**
   - Two `<textarea>` (monospace), each with a live rendered preview panel to the right
   - Save posts to `PUT /system/banner`
   - Helper text: "Banner shows before login (SSH / console). MOTD shows after login."
3. **SSH Access**
   - Toggle: enabled
   - Number: port (warning pill if `!= 22`)
   - Toggle: password authentication (default off — key-based only)
   - Toggle: permit root login (default off)
   - Save posts to `PUT /system/ssh`. If port changed, UI shows: "SSH port changed to `<n>`. Reconnect your SSH sessions on the new port."
4. **Console**
   - Radio: Video / Serial / Dual
   - Select: baud (9600 / 19200 / 38400 / 57600 / **115200** default)
   - Save posts to `PUT /system/console`. On success shows an orange banner: "Console settings changed. **Reboot required** — and verify you have console access on the selected device before rebooting."
   - Double-confirmation: the Save button requires two clicks ("Apply" → "Confirm") like the existing `SystemActions` reboot flow at `page.tsx:2003`

Existing `System Actions` and `pf State Table` cards stay at the bottom, in that order.

Each new card gets a `CATEGORIES.sections` entry so the category sidebar filter at `page.tsx:13-20` keeps working.

### New page — `/system/info`

File: `aifw-ui/src/app/system/info/page.tsx`.

Layout: responsive grid of tiles; auto-refreshes every 5 seconds via `setInterval` on a `GET /system/info` fetch (suspended while the page is not visible, via `document.visibilityState`).

Tiles:

- **Identity** — hostname, domain, OS version, kernel
- **Uptime** — pretty-printed duration, plus boot time
- **Load** — 1 / 5 / 15-minute
- **CPU** — model, core count, usage %
- **Memory** — used / total, bar
- **Root disk** — used / total, bar
- **Temperatures** — per-core C, only if the array is non-empty

Sidebar: add `System Info` entry under the `System` group in `aifw-ui/src/components/Sidebar.tsx:140`. The System category's header in `/settings?cat=system` also gets a "View live system info →" link to this page.

### Sidebar ordering

No reshuffle of unrelated nav. The only sidebar change is the new `System Info` entry.

## MOTD Version Cleanup

Two changes, described in full so the plan can implement them verbatim.

### 1. Remove version from fresh-install MOTD template

`freebsd/build-iso.sh:244-257` currently writes:

```
  AiFw ${VERSION} — AI-Powered Firewall for FreeBSD

  Commands:
    aifw-console        Launch the management menu
    ...
```

Change: drop the first line (and the blank line before/after it). The baked MOTD template becomes just the commands + URL block. Version continues to live in `/usr/local/share/aifw/version` (unchanged at `build-iso.sh:241`) and on the About page in the UI.

### 2. Strip version from MOTD on update

The update paths are two:

- `freebsd/deploy.sh` — manual test-VM deploys
- `aifw-core/src/updater.rs::download_and_install()` (line 144) — in-place updates triggered by `POST /api/v1/updates/aifw/install`

Both get a new idempotent step after the new binaries are in place and before services restart:

```
if [ -f /var/db/aifw/motd.user-edited ]; then
    # Admin has customized MOTD via the UI — don't touch it.
    exit 0
fi

if [ -f /etc/motd.template ]; then
    # Remove any "AiFw <version> — ..." line and its surrounding blank line.
    sed -i '' -E '/^[[:space:]]*AiFw [0-9][0-9.]+[[:space:]]*[—-][[:space:]]*AI-Powered/d' /etc/motd.template
fi
```

Behavior:

- Fresh install: nothing to strip (build-iso no longer bakes the version).
- Old install being upgraded: version line gets removed once, then the `sed` is a no-op on subsequent upgrades.
- Admin has edited MOTD via the new `PUT /system/banner` endpoint (marker file present): updater leaves MOTD alone completely.

The marker file `/var/db/aifw/motd.user-edited` is created by `system_apply::apply_banner` on FreeBSD (see apply layer above).

The same logic lives in one shell snippet shared between `deploy.sh` and the API updater — implementation detail for the plan is whether to extract it to `freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh` and call it from both, or inline it in both. The plan should pick the extract-to-helper path; it's one small file and it removes duplication.

## Testing

Following the existing pattern (in-memory SQLite + `PfMock`, `axum_test::TestServer`):

- **`aifw-core/tests/system_config.rs`**
  - `SystemConfig::default()` produces the documented defaults
  - Loading an old `config.json` (without the new fields) succeeds and fills defaults
  - Roundtrip serialize → deserialize preserves values
- **`aifw-api/tests/system_endpoints.rs`**
  - `GET /system/general` unauthenticated → 401
  - `GET /system/general` non-admin → 403
  - `PUT /system/general` admin → 200, `GET` reflects the change
  - `PUT /system/general` with bad hostname (`"foo.bar"`, contains dot) → 400
  - `PUT /system/ssh` with port = api_port → 400
  - `PUT /system/ssh` with port ∈ [1, 65535] → 200
  - `PUT /system/console` → `ApplyResult.requires_reboot == true`
  - `GET /system/timezones` → non-empty list, includes `"UTC"` and `"America/Chicago"`
  - `GET /system/info` admin → shape check (fields present, reasonable ranges)
- **`aifw-core/tests/system_apply.rs`** (Linux)
  - `apply_general` / `apply_banner` / `apply_console` / `apply_ssh` on Linux return `ok_*()` variants and touch no filesystem paths
- **MOTD cleanup script**
  - `freebsd/tests/motd-cleanup.sh` (or equivalent bats-style shell test): given a file with the version line, the script removes exactly that line; given a file without it, the script is a no-op; given the marker file, the script exits 0 without touching anything.
- **FreeBSD apply path** — not exercised by unit tests (needs a real FreeBSD VM). Covered by a manual smoke run on the test VM (`root@172.29.69.159`) after merge, per the existing deploy workflow documented in `CLAUDE.md`.
- **UI** — manual smoke. No Playwright in the repo.

`cargo check` must pass with zero warnings. `cargo test` must pass. `npm run build` must succeed (static export).

## File-level Impact Summary

New files:

- `aifw-core/src/system_apply.rs`
- `aifw-api/src/system.rs`
- `aifw-ui/src/app/system/info/page.tsx`
- `freebsd/overlay/usr/local/libexec/aifw-motd-cleanup.sh`
- `aifw-core/tests/system_config.rs`
- `aifw-core/tests/system_apply.rs`
- `aifw-api/tests/system_endpoints.rs`

Modified files:

- `aifw-core/src/config.rs` — extend `SystemConfig`, add `ConsoleConfig`, `SshAccessConfig`, `ConsoleKind`
- `aifw-core/src/lib.rs` — `pub mod system_apply;`
- `aifw-api/src/main.rs` — mount `/system/*` routes in `build_router()`
- `aifw-api/src/lib.rs` — `pub mod system;`
- `aifw-ui/src/app/settings/page.tsx` — four new cards under `System` category; update `CATEGORIES` entry
- `aifw-ui/src/components/Sidebar.tsx` — add `System Info` link
- `freebsd/build-iso.sh` — drop version line from MOTD template (line ~246)
- `freebsd/deploy.sh` — call `aifw-motd-cleanup.sh` after copying new binaries
- `aifw-core/src/updater.rs` — call `aifw-motd-cleanup.sh` from `download_and_install()` after the new binaries are moved into place, before `restart_services()`
- `Cargo.toml` version bump (patch)
- `aifw-ui/package.json` version bump (same patch)

## Open Questions / Deferred

- Full sysctl / tunables editor (OPNsense's System → Settings → Tunables) — deferred. Existing first-boot wizard writes a tuning file; exposing a UI editor is a separate feature.
- Serial console connection test (round-trip "are you actually receiving bytes on ttyu0?") before applying — deferred. The double-confirm + reboot-required banner is the mitigation for v1.
- `GET /system/info` rate limiting — the 5 s auto-refresh is cheap (a few sysctls) but multiple open tabs will compound. Deferred until it shows up as a problem.
