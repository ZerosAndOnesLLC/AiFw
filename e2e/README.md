# AiFw Proxmox E2E harness

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

The manual Woodpecker run also requires an `artifact_url` pipeline parameter.
It must point to an IMG built from a revision containing the unattended seed
support; an older release image will fall back to its interactive wizard.

The current Proxmox host has only an untagged management bridge. The supported
initial lane is therefore a one-NIC appliance lifecycle smoke test. The
orchestrator deliberately does not claim routed WAN/LAN coverage. Add isolated
test bridges or VLAN-aware networking before implementing data-plane suites.

## Run

```sh
python -m e2e.aifw_e2e run --artifact output/aifw-<version>-amd64.img.xz
```

Artifacts are written to `e2e/artifacts/<run-id>/`.
Ephemeral keys, seed media, and decompressed images live under `e2e/.run/`
and are deleted by the lifecycle `finally` block.
