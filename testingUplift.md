# AiFw Full End-to-End Testing Uplift

## Purpose

This document reviews AiFw's current testing and deployment harness and proposes a full end-to-end (E2E) framework that provisions the shipped appliance artifact in Proxmox, tests the running VM and network data plane, gathers diagnostics, and reliably tears down all test resources.

The target definition of done is:

> From one command, the framework creates an isolated appliance environment from the shipped artifact, verifies both control-plane behavior and real forwarded traffic, records actionable evidence, and leaves no Proxmox resources behind—even when setup or testing fails.

## Current state

AiFw currently has a strong base of Rust unit and in-process integration tests, but it does not have an appliance-level E2E framework.

Existing coverage includes:

- Approximately 688 Rust test attributes across the workspace.
- API integration tests using in-memory SQLite, `PfMock`, and `axum_test::TestServer`.
- Linux CI running formatting, Clippy, and workspace Rust tests.
- UI CI running lint and static-export builds.
- FreeBSD CI compiling binaries and producing ISO, IMG, and update artifacts.
- A manual deployment script targeting a persistent FreeBSD test VM.
- `scripts/ha-verify.sh`, which verifies two already-running HA nodes over SSH.
- `aifw-setup --config <json>`, which supports unattended appliance configuration.

Important gaps remain:

- No shipped ISO or IMG is booted before publication.
- No Proxmox provisioning, resource allocation, ownership tagging, or teardown exists.
- No tracked UI or browser test suite exists.
- No real FreeBSD `pf`, service, networking, TLS, IDS, DNS, or DHCP behavior is exercised in CI.
- No real packets are routed through an AiFw appliance under test.
- No reboot, failure-recovery, installation, update, or rollback suite exists at VM level.
- UI lint is currently non-blocking.
- No stale-resource janitor protects the Proxmox environment after interrupted jobs.

The current suite therefore proves substantial application logic, but not that the released appliance boots and works as an integrated firewall.

## Main release risk

The ISO workflow builds and releases artifacts without a deployed-VM validation gate between those stages. A packaging, boot, first-boot, service, permission, interface-driver, or live-`pf` regression can pass current CI and be published.

The complete E2E framework should test the exact immutable artifact intended for release, rather than rebuilding or deploying source independently after the artifact has been produced.

## Proposed architecture

```text
Build immutable artifact
        |
Create per-run credentials and network allocation
        |
Provision Proxmox VM(s) and helper clients
        |
Boot and perform unattended setup
        |
SSH -> services -> TLS -> authenticated API readiness
        |
System + API + browser + real traffic tests
        |
Reboot / failure / recovery tests
        |
Collect diagnostics and browser traces
        |
Always destroy VMs, disks, seed media, and allocations
```

The orchestrator should expose one supported lifecycle command:

```sh
scripts/e2e run \
  --artifact output/aifw-5.99.6-amd64.img.xz \
  --suite pr
```

It should own provisioning, readiness, testing, artifact collection, and cleanup. Individual tests should never be responsible for creating or destroying shared Proxmox infrastructure.

## Proxmox lab topology

A useful firewall E2E test requires more than an AiFw VM:

```text
                         Proxmox API
                              ^
                       E2E runner/control
                              |
WAN origin/test server -- WAN network -- AiFw VM -- LAN network -- client VM
                                                  |
                                            Playwright/API/
                                            DNS/DHCP/traffic
```

Recommended guests:

- **AiFw appliance:** 2-4 vCPU, 4 GB RAM, two VirtIO NICs.
- **LAN client:** small Linux cloud-init VM for DHCP, DNS, browser, API, and traffic tests.
- **WAN origin:** small Linux VM serving HTTP, HTTPS, DNS, TCP, UDP, and `iperf3` endpoints.
- **HA expansion:** a second AiFw VM plus a dedicated pfsync network and CARP VIP.

Use fixed lab bridges or VLAN-aware bridges with a unique VLAN/subnet allocation per run. Avoid dynamically creating permanent Proxmox bridges.

Every resource should be tagged or described with:

- `aifw-e2e`
- Run UUID
- Commit SHA
- Expiration timestamp
- CI job URL

Use a dedicated Proxmox resource pool and storage scope for E2E workloads.

## Appliance bootstrap

### Seed-media first boot

The existing `aifw-setup --config <json>` path is a strong foundation. The harness needs a reliable method to provide that configuration and ephemeral SSH access to a pristine appliance.

Attach a small read-only ISO labeled `AIFW_SEED` containing:

- `setup.json`
- An ephemeral SSH public key
- Run identifier
- Optional suite-specific settings

`aifw_firstboot` should detect this medium and invoke:

```sh
aifw-setup --config /mnt/aifw-seed/setup.json
```

On success, first boot should disable itself and invalidate or eject the seed. On failure, it should emit a clear serial-console error and must not report readiness.

### Credential handling

The setup JSON expects an already-Argon2-hashed admin password. The harness should:

1. Generate a random per-run admin password.
2. Generate its compatible Argon2 hash.
3. Generate a per-run SSH keypair.
4. Inject only the hash and public key into the seed.
5. Keep the plaintext password and private key in protected job runtime state.
6. Remove credentials from logs, request dumps, browser traces, and uploaded artifacts.

No long-lived appliance credential should be stored in the repository or Proxmox configuration.

### Unattended ISO installation

The current disk installer is interactive. Release-level installation testing requires an explicit automation interface such as:

```sh
aifw-install \
  --disk vtbd0 \
  --filesystem zfs \
  --config /mnt/aifw-seed/setup.json \
  --yes \
  --poweroff
```

The installer must still:

- Validate the exact target disk.
- Reject missing, ambiguous, mounted, or unsafe targets.
- Require `--yes` for destructive unattended use.
- Return meaningful non-zero exit statuses.
- Write machine-readable progress and failure information to the serial console.

## Artifact test lanes

### IMG lane: pull requests and main

The generated IMG is a writable, bootable UFS image and is the preferred frequent-test artifact.

The harness should:

1. Verify its checksum.
2. Decompress it into a run-specific staging area.
3. Import it into the E2E Proxmox storage.
4. Attach the imported disk, seed ISO, and two network adapters.
5. Boot it and wait for complete application readiness.

This lane validates packaging, first boot, setup, services, UI, API, live firewall state, and traffic behavior with relatively low provisioning overhead.

### ISO installer lane: nightly and release candidate

The harness should:

1. Create an empty target disk.
2. Attach and boot the exact ISO.
3. Attach the automation seed.
4. Run the unattended installer.
5. Shut down and detach the ISO and seed as appropriate.
6. Boot from the installed disk.
7. Run the full functional suite.

Test UFS and ZFS as separate jobs. Test BIOS and UEFI at least nightly, with the release matrix covering all supported combinations.

### Optional update fast lane

A golden installed template may be cloned and updated with the current update tarball for rapid update testing. This is useful supplemental coverage, but it must never replace testing of the exact IMG and ISO artifacts.

## Readiness contract

Readiness must be layered. A successful ping or open TCP port is insufficient.

Recommended progression:

1. Proxmox reports VM running.
2. Serial console reaches the expected boot phase.
3. Expected network address is reachable.
4. SSH succeeds with the ephemeral key.
5. Core services report healthy through `service ... onestatus`.
6. TLS handshake succeeds with the expected test trust policy.
7. Login returns valid tokens.
8. Authenticated `/api/v1/status` succeeds and reports `pf_running`.
9. Expected version and UI assets are served.
10. No panic, migration failure, crash loop, or watchdog restart loop is present.

A small unauthenticated `/healthz` endpoint containing no sensitive state would simplify transport-level readiness. Authenticated readiness should still verify the complete application.

## Test suites

### Boot and packaging

- Artifact checksum is correct.
- Embedded version matches the requested build.
- BIOS and UEFI boot as expected.
- Every manifest-listed binary exists and is executable.
- Expected companion services and revisions are present.
- UI static assets exist and are served.
- rc.d and libexec scripts have correct modes.
- `visudo -cf` succeeds on installed sudoers content.
- Database migrations and integrity checks succeed.
- TLS key, database, configuration, and helper permissions are correct.
- No stale build artifacts or missing external binaries are shipped.

Companion repository revisions should be recorded in the build manifest and preferably pinned. Cloning each default branch at build time makes artifact composition non-reproducible.

### Appliance health

- `aifw_daemon`, `aifw_ids`, `aifw_api`, and watchdog are running.
- Expected DNS, DHCP, time, and reverse-proxy services match configuration.
- API TLS and certificate behavior are correct.
- `pf` and `pflog` are enabled.
- Correct anchors and base rules are loaded.
- IDS IPC and packet-capture access work.
- Disk, memory, logs, and singleton lockfiles are healthy.
- Service start, stop, restart, and reload paths work.

### API and control plane

Exercise the real API on the deployed appliance:

- Login, refresh, logout, invalid credentials, lockout, and RBAC.
- Rule CRUD, reorder, reload, and live `pfctl` verification.
- NAT, aliases, interfaces, schedules, DNS, DHCP, VPN, IDS, and settings.
- Backup/export, mutation, restore, and equality verification.
- WebSocket and SSE connectivity.
- Failed apply and rollback.
- Update installation, restart, status, and rollback.
- Audit and snapshot creation for mutations.

Assertions should compare all three layers:

```text
API/database intent == generated configuration == live kernel/service state
```

### Data plane

Drive real packets between helper VMs through AiFw:

- LAN-to-WAN allowed by the standard policy.
- WAN-to-LAN blocked by default.
- Stateful return traffic works.
- NAT rewrites source addresses correctly.
- Explicit pass and block rules affect real TCP and UDP.
- ICMP behavior matches policy.
- IPv4 and IPv6 work.
- DNS resolution, custom blocking, and allowlisting work.
- A LAN client acquires and renews a DHCP lease.
- Large-transfer and multi-connection smoke tests pass.
- Existing and new sessions behave correctly across rule changes.
- Management access is not unintentionally reachable from WAN.
- Packet, byte, rule, and state counters change as expected.

### Browser and UI

Add Playwright under `aifw-ui` and run it against the deployed appliance:

- Login and logout.
- Dashboard and live metrics rendering.
- WebSocket-driven updates.
- Create, edit, reorder, and delete firewall rules.
- NAT, DNS, IDS, user/RBAC, interface, update, and settings workflows.
- Client-side validation.
- API error presentation.
- Session expiry and unauthorized redirects.
- Core responsive-layout smoke checks.

Run Chromium on pull requests. Add Firefox and WebKit to nightly coverage if they are supported targets.

On failure, retain Playwright HTML, screenshots, video, and traces. Configure traces for the first retry and avoid recording credentials in reusable authentication state or request attachments.

### Lifecycle and resilience

- Graceful reboot followed by complete authenticated readiness.
- Database, configuration, and live `pf` state converge after reboot.
- Kill each core service and verify watchdog recovery.
- Restart all services without losing configuration or management access.
- Simulate failed `pfctl` apply and confirm rollback.
- Verify connectivity remains after a failed mutation.
- Simulate WAN loss and restoration.
- Exercise controlled disk-full or read-only failures where practical.
- Test interrupted update recovery in nightly destructive suites.
- Verify clock and certificate behavior after restart.

### HA suite

Provision two appliances plus LAN, WAN, management, and dedicated pfsync connectivity.

Test:

- Exactly one CARP master.
- Configuration replication.
- State synchronization.
- Existing connection survival during failover.
- Failover after API/daemon stop.
- Failover after NIC disconnect.
- Failover after VM power-off.
- Recovery without split brain.
- Primary return and preferred-role behavior.
- Configuration hashes and health checks match.

Reuse `scripts/ha-verify.sh` as one assertion inside this larger suite rather than treating it as the entire HA harness.

## Diagnostics and artifacts

Diagnostics must be captured before destroying guests, while they are still reachable.

Collect:

- Run manifest with commit SHA, artifact SHA-256, companion SHAs, VMIDs, MACs, addresses, timings, and Proxmox version.
- Proxmox VM configuration and relevant task logs.
- Full serial-console output.
- `dmesg`, `uname`, uptime, disk usage, mount state, and `rc.conf`.
- Interface, address, route, ARP/NDP, and socket state.
- `service ... onestatus`, process list, and singleton lock state.
- `pfctl -si`, rules, NAT, anchors, tables, and states.
- `aifw-diag.sh` output.
- API, daemon, IDS, watchdog, DNS, DHCP, time, and proxy logs.
- Database integrity result and non-sensitive schema/version metadata.
- Request/response summaries with authorization data removed.
- Traffic captures for failed data-plane cases where safe.
- Playwright HTML report, screenshots, video, and trace.
- JUnit XML and a concise machine-readable suite summary.

Artifacts must exclude:

- Bearer and refresh tokens.
- API keys.
- Admin plaintext password.
- SSH private key.
- TOTP secret and recovery codes.
- HA shared secrets.
- TLS private keys.

## Teardown contract

Teardown is a core framework responsibility, not the last test step.

The top-level runner should use `try/finally` plus handlers for normal exit, test failure, timeout, cancellation, SIGINT, and SIGTERM.

Cleanup sequence:

1. Stop scheduling new tests.
2. Capture diagnostics while guests remain reachable.
3. Request graceful VM shutdown with a bounded timeout.
4. Force-stop VMs only when required.
5. Destroy VMs and all referenced and unreferenced run-owned disks.
6. Delete temporary seed ISOs and artifact staging files.
7. Release VLAN, subnet, address, and VMID leases.
8. Verify that no resources tagged with the run UUID remain.
9. Report cleanup failures separately from test failures.

Manual preservation after failure should require an explicit flag and must still assign an expiration timestamp.

### Stale-resource janitor

Run a scheduled janitor independently of test jobs. It should:

- Enumerate only resources tagged `aifw-e2e` in the dedicated pool.
- Compare their expiration timestamps with the current time.
- Confirm they are not associated with an active CI run.
- Destroy expired VMs, disks, and seed media.
- Release expired allocation leases.
- Emit an audit report of everything removed.

The janitor must never enumerate and destroy untagged or non-E2E resources.

## Security model

- Use a Proxmox API token scoped to the E2E resource pool, selected storage, and test network resources.
- Avoid unrestricted root SSH from CI where a narrow node-side import helper can be used.
- Validate artifact and staging paths before importing or deleting them.
- Keep destructive operations scoped by run UUID and known VMIDs.
- Never use broad recursive deletion against a workspace, storage root, or unresolved variable.
- Use unique ephemeral credentials per run.
- Redact request headers and secret-bearing JSON fields before artifact upload.
- Separate public pull-request jobs from jobs allowed to access the private Proxmox lab.

## Suggested repository layout

```text
e2e/
  README.md
  pyproject.toml
  lab.example.yaml
  orchestrator/
    cli.py
    proxmox.py
    allocation.py
    seed.py
    readiness.py
    diagnostics.py
    cleanup.py
  tests/
    test_boot.py
    test_services.py
    test_api.py
    test_firewall.py
    test_nat.py
    test_dns_dhcp.py
    test_reboot.py
    test_update.py
    test_ha.py
  fixtures/
    setup.json.j2
  helpers/
    wan-server/
    lan-client/

aifw-ui/
  playwright.config.ts
  e2e/
    auth.spec.ts
    dashboard.spec.ts
    rules.spec.ts
    settings.spec.ts

.github/workflows/
  e2e-pr.yml
  e2e-nightly.yml
  e2e-release.yml

scripts/
  e2e
```

Python with `pytest` is a practical orchestration layer because it provides mature Proxmox clients, fixtures, structured reports, timeouts, and cleanup primitives. Shell should remain limited to narrow guest helpers. Rust can be used for traffic or assertion tooling where type safety and reuse justify it.

## CI tiers

### Tier 0: local and every commit

- Rust formatting, Clippy, and unit/integration tests.
- UI lint made blocking after existing debt is addressed.
- UI component tests.
- Browser tests against mocked APIs where they provide fast feedback.
- Shell syntax and helper allowlist tests.

Target: under 10-15 minutes.

### Tier 1: every eligible pull request

- Build exact IMG artifact.
- Boot it in Proxmox.
- Run boot, readiness, service, API, core browser, and core data-plane suites.
- Reboot once and verify recovery.
- Always collect diagnostics and tear down.

Target: approximately 15-30 minutes after artifact availability.

### Tier 2: main and nightly

- Full data plane, IPv6, update, rollback, failure injection, and recovery.
- BIOS and UEFI matrix.
- ISO installation smoke tests.
- HA failover tests.
- Longer throughput and stability tests with broad VM tolerances.

### Tier 3: release candidate

- Exact ISO-to-disk installation.
- UFS and ZFS.
- Supported firmware modes.
- Complete functional and browser suite.
- Reboot, update, rollback, and HA validation.
- Publishing depends on successful completion.

Performance regression thresholds should initially warn rather than block until enough stable lab history exists to define meaningful variance.

## Implementation phases

### Phase 1: appliance automation prerequisites

- Add seed-media detection and unattended first boot.
- Add explicit unattended installer arguments.
- Add serial-console progress and failure output.
- Add a minimal non-sensitive health endpoint.
- Add reproducible build metadata with companion SHAs.

### Phase 2: Proxmox lifecycle foundation

- Implement scoped Proxmox authentication.
- Implement VMID, address, subnet, and VLAN allocation.
- Import and boot the IMG.
- Generate and attach seed media.
- Implement layered readiness.
- Implement diagnostic collection.
- Implement verified teardown and scheduled janitor.

### Phase 3: core appliance tests

- Boot and packaging assertions.
- Service health.
- Authenticated API smoke tests.
- Live `pf` state checks.
- LAN-to-WAN and WAN-to-LAN traffic tests.
- NAT, DNS, DHCP, TCP, UDP, and ICMP tests.

### Phase 4: browser and broader functional coverage

- Add Playwright configuration and fixtures.
- Cover login, dashboard, rules, NAT, DNS, IDS, users, and settings.
- Add WebSocket and SSE assertions.
- Add backup and restore tests.

### Phase 5: resilience and release validation

- Reboot and service-recovery suites.
- Update and rollback suites.
- ISO installation with UFS and ZFS.
- Failure injection.
- HA provisioning and failover.
- Release publication gate.

## Initial acceptance criteria

The first production-useful milestone should meet all of these conditions:

- One command provisions an exact AiFw IMG in Proxmox.
- Setup is completely unattended and uses ephemeral credentials.
- Readiness requires SSH, services, TLS, login, and authenticated status.
- A Linux client routes real TCP, UDP, ICMP, and DNS traffic through AiFw.
- At least one real pass rule and one real block rule are verified against live traffic and `pf` state.
- A core Playwright login/dashboard/rule workflow runs against the appliance.
- The appliance reboots and becomes fully ready again.
- Failures upload serial, service, firewall, application, and browser diagnostics.
- Teardown runs after success, failure, timeout, and cancellation.
- A final ownership check proves no run-scoped Proxmox resource remains.

Once this milestone is stable, ISO installation, HA, update rollback, IPv6, and destructive recovery tests can be layered onto the same lifecycle framework.
