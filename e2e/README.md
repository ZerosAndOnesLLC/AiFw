# AiFw Proxmox E2E harness

Status: the one-NIC lifecycle is validated and the full isolated WAN/LAN lane
is implemented as of 2026-07-19. The full lane uses a real two-NIC AiFw VM,
two Debian LXC traffic helpers, live NAT/pass/block checks, authenticated API
rule changes, Playwright login/rules checks, reboot persistence, diagnostics,
and ownership-verified teardown. A fresh exact-commit Woodpecker acceptance run
is the remaining validation step.

The harness provisions the exact writable AiFw IMG in Proxmox, attaches a
per-run unattended seed ISO, verifies the running appliance, reboots it, saves
diagnostics, and destroys every run-owned Proxmox resource in a `finally`
block.

## Safety model

- Every VM, helper container, and uploaded volume is named with a unique run ID.
- Only resources whose names begin with `aifw-e2e-` are deleted.
- Cleanup runs on success, failure, timeout, SIGINT, and SIGTERM.
- `--keep-on-failure` is a manual debugging escape hatch and is not used by CI.
- Credentials are accepted only through environment variables.
- The seed contains an ephemeral public SSH key and Argon2 password hash. It
  never contains the SSH private key or plaintext admin password.

Required secrets:

- `PVE_TOKEN_ID`
- `PVE_TOKEN_SECRET`
- `AIFW_E2E_ADMIN_PASSWORD`

Required non-secret settings:

- `PVE_URL`, `PVE_NODE`, `PVE_IMAGE_STORAGE`, `PVE_VM_STORAGE`, `PVE_BRIDGE`
- `PVE_E2E_WAN_BRIDGE`, `PVE_E2E_LAN_BRIDGE`
- `AIFW_E2E_ADDRESS`, `AIFW_E2E_GATEWAY`, `AIFW_E2E_DNS`

The manual Woodpecker workflow first creates an ephemeral FreeBSD 15 builder
VM in Proxmox, copies the exact checked-out Git commit to it, builds a fresh
seed-capable IMG, copies that IMG back into the job workspace, and destroys the
builder. It then deploys that IMG as a two-NIC VM plus two helper containers.
The builder and LAN helper run sequentially and reuse the reserved address.

The configured homelab lane uses:

- Proxmox node `trigproxmox`
- Upload storage `local`
- VM storage `local-lvm`
- Bridge `vmbr0`
- Isolated, portless bridges `vmbr998` (WAN) and `vmbr999` (LAN)
- Reserved address `192.168.0.26/23`
- Gateway and DNS `192.168.0.1`

These operational values live in the pipeline and manual-only Woodpecker
secrets. Credentials do not belong in this file or any repository file.

The static isolated bridges are durable lab substrate; per-run VMs, containers,
media, credentials, routes, and rules are disposable. The LAN helper has its
management NIC on `vmbr0` and an isolated NIC on `vmbr999`. AiFw has only WAN
and LAN NICs, so all appliance access is through the LAN helper.

## Current validation state

Passing direct checks:

- Proxmox authentication and asynchronous task polling.
- Disposable tagged VM create/read/destroy.
- `.raw` upload, import to `local-lvm`, disk attachment, purge, and upload
  deletion.
- The official FreeBSD 15.0 BASIC-CLOUDINIT image boots with a custom `cidata`
  ISO, applies `192.168.0.26/23` to `vtnet0`, installs the ephemeral key for
  its default `freebsd` user, and has the expected live default route.
- Non-interactive build privilege works through the stock wheel account's
  passwordless `su`; the official image does not include `sudo`.
- PVE disk import and `boot=order=virtio0` are applied as two sequential API
  tasks. Sending both in the import request silently omitted the not-yet-created
  disk from the boot order and left the guest attempting PXE/CD-ROM boot.
- Harness unit tests and cleanup verification with zero residual E2E VMs.
- A clean builder-only run compiled AiFw and all four companion projects,
  produced/checksummed a 211-MB compressed IMG, returned it to the runner, and
  destroyed the builder.
- The corrected appliance-only run passed SSH, all core services, TLS login,
  authenticated API/UI health, live `pf`, reboot recovery, and zero-residual
  teardown. Its manifest records `pf_running=true` both before and after reboot.
- Woodpecker pipeline 14 passed the combined native path in 1,840 seconds. It
  produced a 221,009,096-byte compressed IMG from commit `9c146232`, deployed
  it at the reserved address, and passed the same initial/reboot contract.
- A post-run Proxmox ownership audit found zero `aifw-e2e-*` VMs and zero
  matching uploaded or imported volumes.
- Cleanup now polls Proxmox and records `teardown_verified=true` in the run
  manifest only after the VM and every run-owned volume are absent.
- A focused Debian helper-container check passed both NIC/address assertions,
  SSH, source-observing HTTP service, and zero-residual teardown.
- Direct full-topology attempts proved helper provisioning and teardown. The
  retained 5.99.12 image did not configure its isolated LAN because it predates
  the current first-boot fixes; it is not the acceptance artifact.

Root cause and correction:

- FreeBSD 15 uses native `nuageinit`, not Python cloud-init. Proxmox-generated
  NoCloud metadata names the NIC `eth0`, while the VirtIO NIC is `vtnet0`.
- The first custom seed used network-config v1. FreeBSD's NoCloud parser
  expects a v2 document with `ethernets`, so it raised a Lua type error.
- The harness now attaches its own v2/vtnet0 `cidata` ISO, uses the early
  top-level `ssh_authorized_keys` field with the stock `freebsd` user, and
  checks live `ifconfig` and route state instead of Linux cloud-init markers.
- The harness waits for asynchronous disk import before setting the boot order;
  a regression test fixes this request ordering contract.

Remaining boundaries:

- The official image performs slow first-boot maintenance before sshd starts;
  the reliable lane tolerates that bounded delay.
- Full-lane exact-commit acceptance in Woodpecker is pending. Until it passes,
  pipeline 14 remains the last authoritative appliance acceptance result.
- Run evidence is currently emitted to the Woodpecker log and job-local
  manifest. Durable external artifact retention and a stale-resource janitor
  remain target-state work.

Appliance root causes corrected in source:

- The writable IMG now creates UFS label `aifw`; previously only GPT label
  `aifw` existed while loader/fstab requested `/dev/ufs/aifw`, causing a
  `mountroot` error 19.
- `aifw_firstboot` is a normal idempotent rc service, not sentinel-gated, so a
  staged writable IMG consumes unattended seed media.
- Setup persists `pf_rules=/usr/local/etc/aifw/pf.conf.aifw`; otherwise first
  boot enabled `pf` directly but reboot fell back to missing `/etc/pf.conf`.
- Reboot readiness retries the complete service/API/UI/`pf` contract instead
  of stopping at SSH readiness.
- Serial/VGA multicons output is enabled for future Proxmox boot diagnostics.

Do not promote this manual lane to a publication gate until repeat exact-commit
full runs pass and durable evidence retention is added.

## Development and validation order

Use the smallest test that can prove each change:

1. `pytest e2e/tests` for local logic and request encoding.
2. Disposable NIC-less VM for Proxmox API configuration contracts.
3. Official FreeBSD boot plus static IP, SSH, and teardown only.
4. Builder-only image production.
5. Appliance-only deployment and checks.
6. One combined Woodpecker manual run after all focused checks pass.

Every direct live test must use the `aifw-e2e-` prefix, a bounded timeout, and
the lifecycle cleanup guard. Always verify that no run-owned VM or uploaded
volume remains.

### Builder alternatives

The current implementation starts from the checksum-verified official image
for maximum reproducibility. The measured clean builder completed in roughly
15 minutes, so this remains the default manual/release lane while correctness
stabilizes. If measured duration becomes too high, use a versioned, periodically
rebuilt Proxmox builder template and clone it per run. Pin the template to a FreeBSD release,
record its package/toolchain manifest, inject a fresh key/network seed into
every clone, and retain an official-image canary job so cached state cannot
hide bootstrap regressions.

Other viable but less attractive options are offline qcow2 customization or a
persistent FreeBSD build host. Offline customization adds image tooling and a
second image supply chain; a persistent host weakens isolation and teardown.
Neither should replace deployment testing of the exact AiFw IMG produced by
the build.

## Run

Build an image through an ephemeral Proxmox builder:

```sh
python -m e2e.aifw_e2e build \
  --builder-image FreeBSD-15.0-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz \
  --output e2e/.run/aifw.img.xz
```

Run the quick one-NIC smoke or the full isolated suite:

```sh
python -m e2e.aifw_e2e run --artifact output/aifw-<version>-amd64.img.xz
python -m e2e.aifw_e2e full --artifact output/aifw-<version>-amd64.img.xz
```

Artifacts are written to `e2e/artifacts/<run-id>/`.
Ephemeral keys, seed media, and decompressed images live under `e2e/.run/`
and are deleted by the lifecycle `finally` block.

## Target state

The implemented first full lane still leaves these target extensions:

- UDP, ICMP, DNS, DHCP, and deeper state assertions.
- Broader Playwright coverage beyond login/dashboard/rules.
- ISO installation for UFS/ZFS and BIOS/UEFI.
- Update, rollback, watchdog, failure-recovery, and HA suites.
- Serial-console artifacts, JUnit, browser traces, packet captures on failure,
  and a scheduled stale-resource janitor.
- A scoped Proxmox pool/token and release publication gate.

See `testingUplift.md` for the detailed current-to-target roadmap.
