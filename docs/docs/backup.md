---
layout: default
title: "Backup & migration — AiFw config backup, S3, OPNsense import"
description: "Back up AiFw config to JSON or S3. Import an OPNsense XML config with atomic rollback. Versioned config history and commit-confirm auto-revert."
permalink: /docs/backup/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Backup & migration", url: "/docs/backup/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Backup & migration — AiFw config backup, S3, OPNsense import",
  "description": "Back up AiFw config to JSON or S3. Import an OPNsense XML config with atomic rollback. Versioned config history and commit-confirm auto-revert.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Operations"
}
</script>

<div class="content-page">
<article markdown="1">

# Backup &amp; migration

> **Restore safety:** restore uses snapshot/reapply across SQLite and live services; it is not a single atomic database-and-kernel transaction. Required firewall, NAT, and GeoIP apply failures are returned as errors, but complete failure-injection and verified live-state rollback coverage is still in progress. Keep an out-of-band recovery path and a separately verified backup.

Release SHA-256 files detect corruption but do not authenticate publisher origin. Release signing, key rotation, and keyless provenance attestation remain required before artifacts can be treated as authenticated. The build now emits an SPDX inventory for the Rust workspace; companion binary inventories are tracked separately with their pinned revisions in `freebsd/manifest.json`.

Three workflows live in the same place: **JSON config backup &amp; restore** for day-to-day snapshots, **OPNsense / pfSense XML import** for migrating off another firewall, and **commit-confirm** for safe remote edits that auto-revert if you lose access. Versioned history sits underneath all three so any change is one click away from a rollback.

## JSON backup &amp; restore

Export the entire configuration &mdash; rules, NAT, aliases, VPN, geo-IP, DNS, DHCP, IDS settings, multi-WAN policy, reverse proxy, users, OAuth providers &mdash; as a single JSON document:

```bash
curl https://aifw.local/api/v1/config/export \
  -H "Authorization: Bearer $TOKEN" \
  -o aifw-backup-$(date +%F).json
```

Restore by `POST`ing the same document back. The importer validates the shape, snapshots the current config to history first, then applies the new state through the same engine writers (`RuleEngine`, `NatEngine`, `AliasEngine`, &hellip;) that the UI uses &mdash; so pf actually picks up the changes.

```bash
curl -X POST https://aifw.local/api/v1/config/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @aifw-backup.json
```

Preview a candidate import without applying via `POST /api/v1/config/import-preview`. The response lists every record that will be created / updated / deleted so you can sanity-check the diff first.

## S3 backup destination

Push backups off-box on a schedule. Configure a bucket, region, prefix, and access keys; AiFw uploads a fresh JSON snapshot on every config save plus on a configurable rotation schedule.

```bash
curl -X PUT https://aifw.local/api/v1/backup/s3/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "bucket": "ops-aifw-backups",
    "region": "us-east-1",
    "prefix": "site-a/",
    "path_style": false,
    "access_key_id": "AKIA...",
    "secret_access_key": "..."
  }'

# Verify credentials + bucket access without touching anything:
curl -X POST https://aifw.local/api/v1/backup/s3/test \
  -H "Authorization: Bearer $TOKEN"

# Restore a specific snapshot:
curl https://aifw.local/api/v1/backup/s3/list \
  -H "Authorization: Bearer $TOKEN"
curl -X POST https://aifw.local/api/v1/backup/s3/import \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "site-a/2026-05-08T03:15:22Z.json"}'
```

S3-compatible endpoints work too &mdash; set `endpoint` and `path_style: true` for MinIO, Backblaze B2, Wasabi, Cloudflare R2, &hellip;.

## OPNsense import

Migrating from OPNsense or pfSense? Drop the appliance&rsquo;s `config.xml` straight into AiFw. The importer was rewritten in [#230](https://github.com/ZerosAndOnesLLC/AiFw/pull/230) and hardened across [#248](https://github.com/ZerosAndOnesLLC/AiFw/pull/248)&ndash;[#252](https://github.com/ZerosAndOnesLLC/AiFw/pull/252) with a documented atomicity model and round-trip rollback test coverage.

### Atomicity model

1. **Parse first.** `quick-xml` walks the document. Every error that can be detected from the XML alone (malformed source/destination, unknown action, unparseable port range) surfaces in the preview &mdash; no half-applied state.
2. **Preview the diff.** `POST /api/v1/config/preview-opnsense` returns aliases, NAT entries, rules, and static routes that will be created, plus a **skipped list** for rules that referenced network keywords (`lan`, `wanip`, `(self)`, &hellip;) that don&rsquo;t map cleanly. AiFw drops those to skipped instead of guessing &mdash; silent fidelity loss is the worst outcome.
3. **Apply atomically.** `POST /api/v1/config/import-opnsense` runs the apply step inside a SQLite transaction that wraps every engine write. Aliases route through `AliasEngine`, NAT through `NatEngine`, rules through `RuleEngine`, static routes through the same `apply_route_to_system` path the manual REST endpoint uses, and DNS forwarders through the same path the rDNS resolver UI writes &mdash; not `/etc/resolv.conf` (see [#231](https://github.com/ZerosAndOnesLLC/AiFw/pull/231)).
4. **Snapshot &amp; commit-confirm.** Before any write the importer saves a `pre-OPNsense-import` config-history version, and after a successful apply it arms commit-confirm with a **600-second timeout**. If the admin loses access to the appliance before they confirm, AiFw rolls back automatically.
5. **Reject &rarr; BlockReturn.** OPNsense&rsquo;s `reject` action maps to AiFw `Action::BlockReturn`, which produces the same per-protocol response (TCP RST, ICMP unreachable for UDP/ICMP) the original ruleset emitted.

### Walkthrough (UI)

**Backup &amp; restore &rarr; OPNsense import &rarr; Upload `config.xml`** &rarr; review preview (aliases, NAT, rules, skipped list, interface map) &rarr; **Apply** &rarr; **Confirm** within the commit-confirm window.

### Walkthrough (API)

```bash
# 1) Preview
curl -X POST https://aifw.local/api/v1/config/preview-opnsense \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "xml": "'"$(base64 -w0 < /tmp/config.xml)"'",
    "interface_map": { "wan": "em0", "lan": "em1" }
  }'

# 2) Apply (uses same body shape; commit-confirm starts on success)
curl -X POST https://aifw.local/api/v1/config/import-opnsense \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @import-body.json

# 3) Confirm (within 600 seconds) — otherwise auto-rollback
curl -X POST https://aifw.local/api/v1/config/commit-confirm/confirm \
  -H "Authorization: Bearer $TOKEN"
```

Max XML size is **10 MiB** (real OPNsense configs are 50&ndash;500 KiB).

## Versioned config history

Every save &mdash; manual, scheduled, OPNsense import, S3 restore &mdash; produces a numbered version. The history endpoints expose them for inspection, diffing, and selective restore.

```bash
curl https://aifw.local/api/v1/config/history \
  -H "Authorization: Bearer $TOKEN"

# Diff two versions
curl "https://aifw.local/api/v1/config/diff?from=42&to=43" \
  -H "Authorization: Bearer $TOKEN"

# Preview what restoring a version would change
curl "https://aifw.local/api/v1/config/restore-preview?version=42" \
  -H "Authorization: Bearer $TOKEN"

# Apply
curl -X POST https://aifw.local/api/v1/config/restore \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"version": 42}'
```

Retention is configurable via `GET /` `PUT /api/v1/config/retention` &mdash; cap by count, by age, or both.

## Commit confirm

Editing remotely and worried about locking yourself out? Wrap the change in commit-confirm. AiFw applies the new config, starts a timer, and reverts unless you explicitly confirm.

```bash
# Arm — default timeout is 300 seconds
curl -X POST https://aifw.local/api/v1/config/commit-confirm \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"timeout_secs": 300, "description": "tightening LAN rules"}'

# Check status
curl https://aifw.local/api/v1/config/commit-confirm/status \
  -H "Authorization: Bearer $TOKEN"

# Confirm
curl -X POST https://aifw.local/api/v1/config/commit-confirm/confirm \
  -H "Authorization: Bearer $TOKEN"
```

If the timer expires, the snapshot taken at arm time is restored and the config that lost you access is rolled back &mdash; same engine writers, same atomic apply.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/config/export` | Export entire config as JSON |
| `POST` | `/api/v1/config/import` | Import a JSON config |
| `POST` | `/api/v1/config/import-preview` | Dry-run a candidate import |
| `GET` | `/api/v1/config/history` | List config-history versions |
| `GET` | `/api/v1/config/version` | Get one version |
| `GET` | `/api/v1/config/diff` | Diff two versions |
| `GET` | `/api/v1/config/check` | Validate the live config |
| `POST` | `/api/v1/config/save` | Save a manual version |
| `POST` | `/api/v1/config/restore` | Restore a version |
| `GET` | `/api/v1/config/restore-preview` | Preview a restore |
| `GET` `/` `PUT` | `/api/v1/config/retention` | Retention policy |
| `POST` | `/api/v1/config/preview-opnsense` | Preview an OPNsense XML import |
| `POST` | `/api/v1/config/import-opnsense` | Apply an OPNsense XML import |
| `POST` | `/api/v1/config/commit-confirm` | Arm commit-confirm |
| `GET` | `/api/v1/config/commit-confirm/status` | Status of pending confirm |
| `POST` | `/api/v1/config/commit-confirm/confirm` | Accept the pending change |
| `GET` `/` `PUT` | `/api/v1/backup/s3/config` | S3 backup destination config |
| `POST` | `/api/v1/backup/s3/test` | Test S3 credentials + bucket |
| `GET` | `/api/v1/backup/s3/list` | List S3-stored snapshots |
| `POST` | `/api/v1/backup/s3/import` | Restore a snapshot from S3 |

## See also

- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }}) (OPNsense migration row)
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }}) (`backup:read` / `backup:write` perms)
- [Features overview &rarr;]({{ '/features/' | relative_url }})
- Source: [`aifw-api/src/backup.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/backup.rs)
- Source: [`aifw-api/src/opnsense/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-api/src/opnsense)
- Source: [`aifw-api/src/backup_s3.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/backup_s3.rs)

</article>
</div>
