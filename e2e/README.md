# AiFw Proxmox E2E harness

Status: directly validated lifecycle foundation as of 2026-07-19. A clean
official-FreeBSD builder produced the IMG, and appliance-only deployment of the
corrected equivalent disk passed initial and post-reboot health plus teardown.
One final combined Woodpecker run of the natively corrected source is pending.

The harness provisions the exact writable AiFw IMG in Proxmox, attaches a
per-run unattended seed ISO, verifies the running appliance, reboots it, saves
diagnostics, and destroys every run-owned Proxmox resource in a `finally`
block.

## Safety model

- Every VM and uploaded volume is named with a unique run ID.
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
- `AIFW_E2E_ADDRESS`, `AIFW_E2E_GATEWAY`, `AIFW_E2E_DNS`

The manual Woodpecker workflow first creates an ephemeral FreeBSD 15 builder
VM in Proxmox, copies the exact checked-out Git commit to it, builds a fresh
seed-capable IMG, copies that IMG back into the job workspace, and destroys the
builder. It then deploys that IMG as a second ephemeral VM for the appliance
checks. The two VMs run sequentially and reuse the reserved test address.

The configured homelab lane uses:

- Proxmox node `trigproxmox`
- Upload storage `local`
- VM storage `local-lvm`
- Bridge `vmbr0`
- Reserved address `192.168.0.26/23`
- Gateway and DNS `192.168.0.1`

These operational values live in the pipeline and manual-only Woodpecker
secrets. Credentials do not belong in this file or any repository file.

The current Proxmox host has only an untagged management bridge. The supported
initial lane is therefore a one-NIC appliance lifecycle smoke test. The
orchestrator deliberately does not claim routed WAN/LAN coverage. Add isolated
test bridges or VLAN-aware networking before implementing data-plane suites.

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

Remaining integration boundary:

- The fixes discovered by the focused run must be rebuilt natively and pass one
  combined Woodpecker run; the passing appliance reused the built IMG with
  equivalent in-place boot metadata corrections to avoid another full compile.
- The official image performs slow first-boot maintenance before sshd starts.
  The current reliable lane tolerates that bounded delay.

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

Do not interpret the presence of `.woodpecker/e2e.yml` as evidence that the
full lane passes or gates releases yet.

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

Test an existing image:

```sh
python -m e2e.aifw_e2e run --artifact output/aifw-<version>-amd64.img.xz
```

Artifacts are written to `e2e/artifacts/<run-id>/`.
Ephemeral keys, seed media, and decompressed images live under `e2e/.run/`
and are deleted by the lifecycle `finally` block.

## Target state

The one-NIC lifecycle smoke is only the first lane. The full target adds:

- Isolated WAN and LAN networks plus helper client/origin VMs.
- Real TCP, UDP, ICMP, DNS, DHCP, NAT, state, and pass/block assertions.
- Playwright tests against the deployed UI.
- ISO installation for UFS/ZFS and BIOS/UEFI.
- Update, rollback, watchdog, failure-recovery, and HA suites.
- Serial-console artifacts, JUnit, browser traces, packet captures on failure,
  and a scheduled stale-resource janitor.
- A scoped Proxmox pool/token and release publication gate.

See `testingUplift.md` for the detailed current-to-target roadmap.
