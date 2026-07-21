# FQ-CoDel traffic shaping implementation plan

> Status: design plan for [#532](https://github.com/ZerosAndOnesLLC/AiFw/issues/532). This document does not claim that AiFw currently provides a working FQ-CoDel data plane.

## Problem and current state

AiFw currently exposes a CoDel queue type through the `pf` queue renderer. The
renderer emits fixed `flows`, `quantum`, `target`, and `interval` values, but
does not select FreeBSD's dummynet `fq_codel` scheduler. AiFw targets the
GENERIC FreeBSD kernel, where the documented `pf` ALTQ schedulers are not the
right implementation path for FQ-CoDel. Until a live dummynet implementation
is verified, CoDel should remain marked as in development in product claims.

The feature must solve more than command rendering: queue classification,
upload/download direction, rollback, ownership of shared kernel state, status,
backup/restore, HA, multi-WAN, and the UI all need one coherent lifecycle.

## Goals

- Provide real upload and download FQ-CoDel shaping on supported FreeBSD releases.
- Keep filtering in `pf`, while moving shaping to dummynet/IPFW.
- Support IPv4, IPv6, NAT, VPN, and multi-WAN traffic with explicit direction semantics.
- Apply configuration transactionally and verify live kernel state before reporting success.
- Preserve administrator-owned IPFW and dummynet objects.
- Expose live status and drift, and keep backup/restore and HA behavior coherent.
- Publish repeatable functional and performance evidence before changing maturity claims.

## Non-goals for the first release

- Exact parity with every OPNsense shaper control.
- A generic replacement for arbitrary administrator IPFW/dummynet rules.
- Strict performance gates on shared GitHub runners.
- Automatic conversion of ambiguous legacy queue configurations.

## Proposed architecture

```text
AiFw configuration
       |
       +-- ShapingEngine ------ SQLite
       |
       +-- ShaperBackend ------ dnctl pipes and schedulers
       |
       +-- ClassifierBackend -- IPFW classification rules
                                      |
                                      +-- traffic -> dummynet FQ-CoDel
```

Keep the existing `PfBackend` focused on pf operations. Introduce a separate
backend boundary, either as a focused crate or a clearly isolated shaping
module:

```rust
trait ShaperBackend {
    async fn validate(&self, config: &ShaperConfig) -> Result<()>;
    async fn apply(&self, config: &ShaperConfig) -> Result<ApplyReport>;
    async fn snapshot(&self) -> Result<ShaperSnapshot>;
    async fn restore(&self, snapshot: &ShaperSnapshot) -> Result<()>;
    async fn status(&self) -> Result<ShaperStatus>;
    async fn flush_managed(&self) -> Result<()>;
}
```

FreeBSD should use structured `dnctl`/IPFW argument vectors; Linux and ordinary
unit tests should use an in-memory mock executor. No backend may construct a
shell command string from user-controlled configuration.

## Configuration model and validation

The persisted model should describe links, optional classes, and rules that
send traffic into them. It needs explicit upload/download direction, interface
and address-family semantics, bandwidth units, scheduler parameters, and
stable managed identifiers.

Required validation includes:

- positive bandwidth and checked unit conversion;
- `target_ms < interval_ms`;
- FreeBSD-supported bounds for quantum, flows, packet limit, and ECN;
- unique dummynet identifiers in an AiFw-reserved range;
- valid queue-to-pipe and rule-to-target references;
- no rule targeting a disabled object;
- deterministic rule ordering;
- safe interface and resource names;
- explicit behavior for NAT and VPN classification points.

## Safe apply, ownership, and rollback

An apply should:

1. Validate the requested graph and render deterministic commands.
2. Snapshot only AiFw-managed state plus the references needed for rollback.
3. Validate commands without changing live state where the platform allows it.
4. Apply new pipes, schedulers, and classifiers in dependency order.
5. Verify the live `dnctl`/IPFW state, including scheduler and direction.
6. Remove stale AiFw-owned objects only after verification succeeds.
7. Restore the previous working state if any command or verification fails.
8. Report rollback failure separately and prominently.

AiFw must never issue broad IPFW or dummynet flushes. Every managed object
needs an ownership marker and cleanup must return or log failures.

## Delivery phases and gates

### Phase 0: FreeBSD proof of concept

Before the main implementation, prove the exact `dnctl` commands on the
supported FreeBSD release with upload and download traffic, IPv4/IPv6, and NAT.
Capture raw commands and measurements in issue #532.

**Gate:** no kernel-facing implementation until the scheduler and classification
model are verified on the target release.

### Phase 1: Models, validation, and pure renderers

Add types, persistence/migration, bounds validation, deterministic command
rendering, ownership identifiers, and mock tests. The existing CoDel `pf`
renderer remains clearly marked as legacy/in-development during this phase.

### Phase 2: Backend and atomic apply

Add the FreeBSD backend, privileged helper boundary, snapshot/restore,
failure-injection tests, and live-state verification. A failed apply must leave
the prior configuration active or return an explicit rollback failure.

### Phase 3: Engine and lifecycle

Integrate apply, deletion, drift detection, reboot recovery, backup/restore,
HA replication, and multi-WAN lifecycle. Database state must not be presented as
active until live dummynet state confirms it.

### Phase 4: API, CLI, and UI

Expose CRUD, preview/apply, status, and failure details through the REST API,
CLI, and UI. Cover create, edit, apply, failed apply, status, and deletion.

### Phase 5: Functional and performance validation

Use FreeBSD epair/jail tests for TCP, UDP, IPv4, IPv6, NAT, modification,
deletion, rollback, and preservation of unmanaged objects. Use a stable
self-hosted environment for throughput, loaded latency, fairness, ECN, reboot,
and reconfiguration measurements.

**Gate:** do not advertise CoDel as supported until live FQ-CoDel state and the
required packet-path tests pass.

## Test strategy

### Tier 1: Per-commit Linux CI

Run model/bounds, structured-command, migration, API authorization, backup,
mocked apply/rollback, failure injection, and UI tests. Keep this deterministic
and fast.

### Tier 2: Per-PR FreeBSD functional CI

Build the target on FreeBSD, create an epair/jail topology, load real IPFW and
dummynet state, run packet tests, inject failures, verify rollback, and assert
that unmanaged objects survive. Upload raw commands, state dumps, and packet
results as artifacts.

### Tier 3: Nightly/release performance lab

Measure upload, download, bidirectional load, multiple flows, interactive
traffic under load, IPv6, ECN, NAT, reconfiguration, failed apply, reboot, and
CPU. Store raw `iperf3`, ping/Flent, `dnctl`, IPFW, and system-stat output.
Start with warning thresholds and make them blocking only after normal variance
is established.

## Pull-request sequence

1. Design, models, validation, pure renderers, and unit tests.
2. Dummynet backend, privilege boundary, and FreeBSD functional tests.
3. Engine, persistence, lifecycle, verification, and rollback.
4. REST API and CLI.
5. UI, status, and operator documentation.
6. Performance harness and published results.

Each PR should be independently reviewable and leave the Linux suite green.
Unperformed FreeBSD, performance, reboot, or hardware tests must remain marked
as outstanding.

## Validation commands

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast

cd aifw-ui
npm ci
npm run lint
npm run build
```
