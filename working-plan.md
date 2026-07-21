# AiFw IPsec Data Plane (#530) — Working Plan

Goal: replace the CRUD-only IPsec surface with a real data plane: strongSwan
(charon) as the IKE daemon, driven via `swanctl`, establishing kernel
SAs/SPs on FreeBSD, with live negotiated state reported through the API/UI.

Decisions (triage + scoping):
- **Backend**: strongSwan from FreeBSD pkg (`security/strongswan`), config via
  `swanctl` conf files + CLI. Same architecture as pfSense/OPNsense.
- **v1 scope**: IKEv2, site-to-site **tunnel mode only**, **PSK and X.509
  cert** auth (certs can come from the ACME store or pasted PEM), NAT-T,
  AES-256-GCM / SHA-256 / ECP-256+MODP-2048 defaults. No transport mode, no
  AH, no IKEv1 in v1 — docs/UI must not claim them.
- Old `ipsec_sas` rows are preserved as read-only legacy records (never shown
  as active); new model is `ipsec_tunnels`.

Track progress per CLAUDE.md workflow: one sub-phase at a time, `cargo check`,
commit after each (bump Cargo.toml + package.json versions), mark `[x]`.
Branch: `feat/530-ipsec-dataplane` off `main`.

## Design Principles

1. `cargo check` zero warnings, tests green, `npm run build` before every commit.
2. Everything compiles and is testable on Linux/WSL: swanctl invocations go
   through a small `IkeControl` trait (real = sudo swanctl, mock = in-memory)
   mirroring the PfBackend pattern.
3. Live state comes from `swanctl --list-sas` (kernel/IKE truth), never from a
   DB `status` column. DB stores desired config only.
4. Apply is transactional: render new conf → load → on failure restore the
   previous conf set and reload (last working state survives).
5. Secrets (PSKs, private keys) live in 0600 files under
   `/usr/local/etc/swanctl/` owned by the service user; never logged, redacted
   in API responses.
6. Every new sudo command gets an `aifw-sudo-*` wrapper + narrow sudoers grant
   + guard test (sudoers-drift lesson: grants must match call sites exactly).

## Architecture

```
UI / CLI ──► aifw-api (routes/vpn.rs: ipsec_tunnels CRUD, start/stop, live status)
                 │
                 ▼
          IpsecEngine (aifw-core/src/ipsec.rs)
            │ desired config: SQLite ipsec_tunnels
            │ render: /usr/local/etc/swanctl/conf.d/aifw-<id>.conf (+ secrets)
            │ control: IkeControl trait
            │            ├── SwanctlControl (FreeBSD: sudo swanctl --load-all /
            │            │                   --initiate / --terminate / --list-sas)
            │            └── MockIkeControl (Linux/tests)
            ▼
        strongSwan charon ──PF_KEY──► FreeBSD kernel SAD/SPD ──► enc0 / ESP
```

pf side (existing anchors): IKE UDP 500/4500, ESP, and enc0 pass rules are
emitted from the new tunnel model (replacing `IpsecSa::to_pf_rules`).

## Data Model

```sql
ipsec_tunnels (
  id TEXT PK, name TEXT UNIQUE, enabled INTEGER,
  -- endpoints & identities
  local_addr TEXT,            -- IP or interface address; '' = %any
  remote_addr TEXT,           -- peer IP/FQDN
  local_id TEXT, remote_id TEXT,          -- IKE identities (default = addrs)
  -- auth
  auth_method TEXT,           -- 'psk' | 'cert'
  psk TEXT,                   -- redacted in API output
  cert_source TEXT,           -- 'acme' | 'manual' (cert auth only)
  acme_cert_id TEXT,          -- FK acme_cert when cert_source='acme'
  local_cert_pem TEXT, local_key_pem TEXT, ca_cert_pem TEXT,  -- manual PEM
  -- proposals
  ike_proposal TEXT,          -- default 'aes256gcm16-prfsha256-ecp256'
  esp_proposal TEXT,          -- default 'aes256gcm16-ecp256'
  -- traffic selectors (tunnel mode)
  local_ts TEXT,              -- CSV of local subnets
  remote_ts TEXT,             -- CSV of remote subnets
  -- behavior
  ike_lifetime_secs INTEGER,  -- default 14400 (rekey)
  esp_lifetime_secs INTEGER,  -- default 3600
  dpd_delay_secs INTEGER,     -- default 30, 0 = off
  start_action TEXT,          -- 'start' (initiate on load) | 'trap' (on-demand) | 'none'
  created_at TEXT, updated_at TEXT
)
-- legacy ipsec_sas table kept as-is, read-only, flagged legacy in API list
```

Live status (not stored): per-tunnel `{ ike_state, child_sas: [{ name, state,
local_ts, remote_ts, bytes_in, bytes_out, rekey_in_secs, enc_alg }],
established_secs, remote_host }` parsed from `swanctl --list-sas --raw`.

## Phases

### Phase 1 — Packaging + control plumbing (→ 5.105.0) — DONE

- [x] 1a. `freebsd/manifest.json`: `packages` list (strongswan + existing
      deps) — build-iso.sh/deploy.sh mirror it (guard test enforces sync);
      updater installs missing packages on upgrade from the manifest list.
      strongswan_enable via sysrc happens at engine apply time (Phase 3),
      not install time — no reason to run charon on boxes with no tunnels.
- [x] 1b. Overlay: `aifw-sudo-swanctl` wrapper (verbs `--load-all`,
      `--initiate/--terminate --ike|--child <aifw-*>`, `--list-sas`,
      `--list-conns`; names pinned to aifw-* namespace) + sudoers grant;
      swanctl dirs in manifest `directories`; also extended allowlists:
      aifw-sudo-write (swanctl conf/key/cert paths + `..` guard),
      aifw-sudo-rm (same paths), aifw-sudo-mkdir (/usr/local/etc/swanctl),
      aifw-sudo-service (strongswan), aifw-sudo-sysrc (strongswan_enable).
- [x] 1c. `aifw-core/src/sudo.rs`: `swanctl()` (no broad-grant fallback —
      none ever existed); embedded in EMBEDDED_SUDO_HELPERS for upgrade
      self-heal; sudoers refresh reaches upgraded boxes via aifw-restart.sh.
- [x] 1d. Guard tests: sudoers narrow_helpers_are_granted + new
      test_manifest_packages_synced_with_build_scripts; wrapper validator
      smoke-tested (17 arg-validation cases).
- [x] 1e. Version bump to 5.105.0, commit.

### Phase 2 — Types + engine core (→ 5.106.0) — DONE

- [x] 2a. `aifw-common/src/ipsec.rs`: `IpsecTunnel`, `IpsecAuthMethod`,
      `IpsecCertSource`, `IpsecStartAction`, `IpsecLiveStatus`,
      `ChildSaStatus`; curated proposal-token whitelist; validate() doubles
      as conf-injection guard (no quotes/newlines in rendered values);
      `redacted()` blanks psk/private key. Old `IpsecSa`/`IpsecSp` kept
      undeprecated (still compiled by legacy paths) with doc note.
- [x] 2b. `IkeControl` trait + `SwanctlControl` (sudo::swanctl, stderr
      surfaced) + `MockIkeControl` (records calls, canned list-sas output,
      injectable load failure).
- [x] 2c. `IpsecEngine`: migrate (ipsec_tunnels), add/list/get/update/delete
      with validation-before-persist; explicit column list (no SELECT *).
- [x] 2d. `render_swanctl_conf`: conn + children + PSK secrets sections
      (secrets bound to peer ids); cert auth via x509/private dirs, key
      never in conf. Golden tests: PSK, cert, multi-TS, trap action.
      NOTE for Phase 3/6: confirm FreeBSD pkg swanctl.conf includes
      conf.d/*.conf (ship an include line if not).
- [x] 2e. Version bump to 5.106.0, commit.

### Phase 3 — Apply lifecycle + rollback (→ 5.107.0) — DONE

- [x] 3a. `IpsecConfStore` trait (SystemConfStore via aifw-sudo-write/rm +
      readdir listing; MemConfStore for tests). `apply_all()` regenerates
      the full managed file set from DB, removes stale files, `--load-all`.
      Rollback model: DB is source of truth — failed apply reverts the DB
      mutation and re-applies the previous state (aifw user can't read
      root-owned conf files back, so file snapshots were a non-starter).
- [x] 3b. `create/update/delete_tunnel_applied` with rollback;
      `start_tunnel` (initiate child, 30s timeout) / `stop_tunnel`
      (terminate ike); delete terminates best-effort first.
- [x] 3c. `ensure_applied()` — no-op on boxes that never used IPsec;
      re-renders + reloads otherwise. `ensure_service()` (FreeBSD only):
      sysrc strongswan_enable=YES + service start when not running.
- [x] 3d. Cert material: manual PEM or ACME store (`acme::load_cert` by i64
      id — acme_cert_id type corrected from Uuid; cert→x509, key→private,
      chain→x509ca aifw-<id>-chain.pem, peer CA→aifw-<id>-ca.pem).
      NOTE: ACME renewal re-export hook deferred to Phase 6 verification
      (apply_all re-reads the store, so a renewal + apply picks up new
      material; automatic re-apply-on-renewal still to wire).
- [x] 3e. `endpoint_pf_rules` free fn + `IpsecTunnel::to_pf_rules`;
      `collect_vpn_rules` now emits rules for enabled ipsec_tunnels and
      NOTHING for legacy ipsec_sas (their pf holes were pure attack
      surface); tolerates missing table pre-migration.
- [x] 3f. Tests: apply writes+loads, disabled not rendered, create/update
      rollback on failing load, delete removes files + terminates, cert
      material files, missing ACME cert fails apply, start/stop,
      ensure_applied no-op, stale file cleanup. Full suite 754 green.
- [x] 3g. Version bump to 5.107.0, commit.

### Phase 4 — Live status + API/CLI (→ minor bump)

- [ ] 4a. `swanctl --list-sas` parser (`--raw` output) → `IpsecLiveStatus`;
      unit tests against captured real output fixtures.
- [ ] 4b. API: `GET/POST /vpn/ipsec/tunnels`, `GET/PUT/DELETE .../{id}`,
      `POST .../{id}/start|stop`, `GET .../{id}/status`, `GET /vpn/ipsec/status`
      (all tunnels, 1-min cached poll + on-demand refresh). PSK/keys redacted
      in every response. Legacy `GET /vpn/ipsec` keeps returning old rows with
      `legacy: true`; legacy `POST` returns 410 Gone with a pointer.
- [ ] 4c. Permissions: reuse existing VPN read/write perms; audit-log all
      mutations.
- [ ] 4d. Backup/config-io: include `ipsec_tunnels` (secrets included in
      encrypted backups, consistent with WG private keys).
- [ ] 4e. CLI: `aifw vpn ipsec list|add|delete|start|stop|status`.
- [ ] 4f. API integration tests (axum_test + mock control).
- [ ] 4g. Version bump, commit.

### Phase 5 — UI (→ minor bump)

- [ ] 5a. `src/lib/api/vpn.ts` + `useVpn.ts`: tunnel types, CRUD, start/stop,
      live status polling.
- [ ] 5b. Rework `IpsecSection`/`IpsecForm`: tunnel form (endpoints, IDs,
      auth method toggle PSK/cert with ACME cert picker, subnets, proposals
      with sane defaults collapsed under "Advanced"), live state badges
      (IKE up / child SAs / bytes / rekey countdown), start/stop buttons.
      Legacy SA rows shown read-only under a "legacy (inactive)" divider.
- [ ] 5c. `npm run lint` + build; version bump, commit.

### Phase 6 — Functional proof on FreeBSD (→ patch bumps as needed)

- [ ] 6a. Bring-up: deploy to test VM (172.29.50.220) and appliance
      (172.29.69.1); establish an IKEv2 PSK tunnel between them; verify
      `swanctl --list-sas`, kernel SAD/SPD (`setkey -D`, `setkey -DP`),
      bidirectional ping/iperf across the tunnel subnets.
- [ ] 6b. Cert-auth tunnel variant (manual CA-signed pair).
- [ ] 6c. NAT-T case (initiator behind NAT) — verify UDP 4500 encapsulation.
- [ ] 6d. Rekey observed (short lifetimes), DPD teardown, reboot recovery
      (tunnel re-establishes without operator action).
- [ ] 6e. Failure paths: bad PSK → clear error surfaced, previous config
      restored on bad apply.
- [ ] 6f. #533 boot-smoke harness: add IPsec check artifact (swanctl list-sas
      + cross-tunnel ping output) to CI/functional test collection.

### Phase 7 — Docs + issue close-out

- [ ] 7a. Flip #552 "in development" markers: claims become "IPsec IKEv2
      site-to-site (tunnel mode, PSK/cert), powered by strongSwan"; remove
      AH/transport claims everywhere (README, docs, comparison pages).
- [ ] 7b. `docs/` IPsec guide: setup walkthrough, interop notes (tested:
      strongSwan↔strongSwan; expected: any IKEv2 peer), troubleshooting.
- [ ] 7c. Comment + close #530 (and verify #529/#552 consistency), Project
      #12 → Done.

## Risk Summary

| Risk | Mitigation |
|---|---|
| charon runs as root; aifw user must drive it | sudo wrapper with whitelisted swanctl subcommands only; guard test |
| Secrets on disk | 0600 swanctl-owned files, redacted API, encrypted backups |
| swanctl output format drift | parse `--raw` (machine format); fixture tests from the real pkg version; pin strongSwan pkg version in manifest |
| Bad apply kills all tunnels | atomic conf-set swap + rollback reload |
| ACME renewal rotates cert under a live tunnel | hook acme export → re-write x509 files + `--load-all` (reload-safe) |
| Legacy `ipsec_sas` confusion | read-only, `legacy: true`, POST 410; migration doc note |
| Mock/real divergence | golden conf-render tests + Phase 6 live matrix is the gate for claims |
