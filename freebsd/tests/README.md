# FreeBSD functional tests (#533 Phase 1)

Live-traffic validation of the AiFw data plane on a real FreeBSD kernel:
real `pfctl`, real packets, real jails — the layer the Linux/PfMock unit
suite cannot cover. The harness is standalone-first: the same scripts run
by hand on a test VM and under `vmactions/freebsd-vm` in CI
(`.github/workflows/freebsd-functional.yml`).

## What it does

1. Loads a harness `pf.conf` mirroring the appliance's anchor layout
   (from `aifw-setup::generate_pf_conf`), with the management interface
   passed `quick` **before** every anchor so a test rule can never lock
   out SSH/CI, and default-deny on the test path.
2. Creates two VNET jails joined to the host by epairs:
   `client (10.99.1.2) ↔ host pf ↔ server (10.99.2.2)`.
3. Starts a self-contained `aifw-api` (port 18080, temp DB, `--no-tls`)
   and `aifw-daemon`, then drives all configuration through the real REST
   API.
4. Runs the test scripts and collects artifacts (pfctl dumps, service
   logs, per-test logs) into the artifacts directory.
5. Tears everything down and restores the previous pf ruleset — the
   appliance's `pf.conf.aifw` if present, else `/etc/pf.conf`.

| Test | Verifies |
|---|---|
| `t01-pfctl-acceptance` | The real pf parser loads every rendered rule (actions, ports, ranges, families, state options) |
| `t02-pass-block` | Default-deny, pass opens the path, higher-precedence block closes it, removal reopens it — with live packets |
| `t03-schedule-gating` | #537: in-window rules compile + pass traffic; out-of-window rules are absent from pf and traffic stays blocked |
| `t04-nat` | Outbound SNAT (translation visible in the pf state table) and rdr port-forward into the server jail, with return traffic |
| `t05-restore-roundtrip` | #535: save → mutate → restore brings both DB and the live anchor back |
| `t06-wireguard` | Tunnel creation on the real kernel + #541 pubkey-derives-from-privkey via `wg pubkey` (skips without wireguard-kmod) |
| `t08-control-plane` | Unauthenticated access rejection, invalid-login rejection, live PF/rule counters, identity, and representative JSON response shapes |

## Running on a test VM

```sh
# prerequisites (once): pkg install -y curl jq sudo
cd /root/AiFw
cargo build -p aifw-api -p aifw-daemon
sh freebsd/tests/run-all.sh --stop-services
```

- **Run only on a disposable host** — the harness owns pf while it runs.
- `--stop-services` stops the installed `aifw_api`/`aifw_daemon` first and
  restarts them afterwards (the harness refuses to run alongside them).
- `MGMT_IF=vtnet0` overrides management-interface autodetection (default:
  the default-route interface).
- `--artifacts DIR` (default `/tmp/aifw-func-artifacts`), `--keep` to skip
  teardown while debugging, `TESTS="t02-pass-block"` to run a subset.
- Exit codes: 0 = all passed, 1 = failures (see `summary.txt`), 2 = setup
  problem. Individual tests exit 3 to record a SKIP.

## CI

`freebsd-functional.yml` runs on pull requests touching data-plane code
(path-filtered) and on manual dispatch. It builds debug binaries inside a
FreeBSD 15 VM, runs this harness, and uploads the artifacts directory.
Expect ~20–30 minutes; the FreeBSD VM boot + build dominates.

## Appliance boot smoke (`smoke-boot.sh`, #533 Phase 2)

Runs on a **Linux** host with qemu (KVM when available): boots the built
USB IMG unmodified with a seed ISO attached as a CD, waits for
`aifw_firstboot` to complete unattended setup, then asserts the seeded
admin can log in through the LAN side and that the WAN side stays
default-denied.

```sh
xz -dk aifw-<ver>-amd64.img.xz
sh freebsd/tests/smoke-boot.sh --img aifw-<ver>-amd64.img
```

In CI this runs as the `smoke-boot` job in `build-iso.yml` and **gates the
release** — an image nobody booted never ships. Artifacts: serial console
log, seed used, `/api/v1/status` response.

## Not yet covered (later phases of #533)

WireGuard peer handshake + traffic, IDS capture counters, multi-WAN
failover, IPv6 packet paths, install-to-disk path, and the two-node HA
suite (#534, Phase 3).
