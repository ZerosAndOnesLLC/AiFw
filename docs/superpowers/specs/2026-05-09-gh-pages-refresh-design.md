---
name: GitHub Pages full content refresh + SEO
description: Bring aifw.zerosandones.us up to date with shipped features (Multi-WAN, OPNsense importer, Reverse proxy + ACME, DNS blocklists, S3 backup, etc.), restructure docs into a real hub with grouped nav, and heavily optimise for SEO.
type: design
---

# GitHub Pages full content refresh + SEO

The published site at `https://aifw.zerosandones.us/` has fallen behind the codebase. Multi-WAN ships and is documented in `docs/multi-wan.md`, but it's not linked from the homepage or nav and `compare.md` still tells visitors it's "planned." The OPNsense importer was rewritten end-to-end (#230 / #248-#252) and isn't mentioned anywhere on the site. The published feature card list misses Reverse proxy, ACME, Geo-IP, DNS blocklists, and S3 backup. The `docs.md` page is mostly placeholder text. The hero stat for API endpoints (257) under-counts the actual ~396 `.route()` calls in `aifw-api/src/`.

This spec covers a full content refresh: 12 new doc pages, 6 refreshed pages, a new grouped-dropdown nav, an FAQ page, and a comprehensive SEO pass. The visual design stays as-is — no CSS overhaul beyond the new nav and breadcrumbs.

## Goals

- **Truth.** Every page on the site reflects shipped behaviour as of v5.92.4. No "planned" tags on shipped features. No undercounted stats.
- **Coverage.** Every meaningful subsystem (rules, NAT, VPN, IDS, multi-WAN, HA, DNS, DHCP, auth, reverse proxy, plugins, backup, geo-IP, API, CLI) gets a dedicated quickstart page. AI is documented as opt-in / experimental, matching the README.
- **Discoverability.** Grouped Docs ▾ dropdown surfaces every guide in one click. `docs.md` becomes a real hub, not a list of placeholders.
- **SEO.** Schema.org JSON-LD on every page. Per-page titles + descriptions targeting long-tail keywords. FAQ page with `FAQPage` schema for rich snippets. Internal hub-and-spoke linking. Breadcrumbs. Last-updated stamps. Lazy-loaded images with proper alt text.

## Non-goals

- Visual redesign / color rework / font changes. CSS edits limited to the new nav, dropdown, breadcrumb, and last-updated stamp.
- JavaScript beyond what Jekyll + `jekyll-seo-tag` already emits.
- Interactive demos, playgrounds, WASM widgets.
- i18n / multi-language.
- Blog or changelog feed.
- Moving off Jekyll.
- Capturing fresh UI screenshots from the running app — if a needed screenshot doesn't exist in `/screenshots/`, the page launches without it and the missing capture is logged as a follow-up.
- Paid SEO monitoring tooling. GSC + Bing Webmaster verification stays as instructions for the maintainer.

## Sitemap (final)

```
docs/
├── _layouts/default.html         (UPDATED: nav dropdown, breadcrumbs, schema injection, last-updated stamp)
├── assets/style.css              (UPDATED: nav dropdown, breadcrumb, last-updated styles)
├── assets/screenshots/           (UPDATED: copy ~14 more PNGs/GIFs from /screenshots/)
├── _config.yml                   (UPDATED: add `superpowers` to exclude:, verify jekyll-sitemap is loaded)
│
├── index.html                    (REFRESHED)
├── features.md                   (REFRESHED)
├── compare.md                    (REFRESHED)
├── install.md                    (REFRESHED)
├── docs.md                       (REWRITTEN as hub)
├── faq.md                        (NEW)
├── plugins.md                    (LIGHT REFRESH)
├── ha.md                         (LIGHT REFRESH)
├── multi-wan.md                  (REFRESHED)
│
└── docs/
    ├── firewall.md               (NEW)
    ├── nat.md                    (NEW)
    ├── vpn.md                    (NEW)
    ├── ids.md                    (NEW)
    ├── dns.md                    (NEW)
    ├── dhcp.md                   (NEW)
    ├── auth.md                   (NEW)
    ├── reverse-proxy.md          (NEW)
    ├── geoip.md                  (NEW)
    ├── backup.md                 (NEW)
    ├── api.md                    (NEW)
    └── cli.md                    (NEW)
```

## Top nav

Desktop (and mobile-collapsed):

```
[ AiFw logo ]   Features   Docs ▾   Compare   Download ↗   GitHub ↗
                            │
                            ├── Install
                            ├── First boot
                            ├── ──────────
                            ├── Firewall
                            ├── NAT
                            ├── VPN
                            ├── IDS / IPS
                            ├── Multi-WAN
                            ├── HA cluster
                            ├── DNS
                            ├── DHCP
                            ├── Auth & RBAC
                            ├── Reverse proxy
                            ├── Plugins
                            ├── ──────────
                            ├── API reference
                            ├── CLI reference
                            └── FAQ
```

- "Download" links to the GitHub releases page in a new tab.
- Implementation: pure CSS dropdown (`:hover` + `:focus-within`); no JS. Mobile collapses the dropdown into an inline group under "Docs".

## Per-page outlines

### Homepage (`index.html`) — REFRESHED

**Hero**
- Tagline updated to include Multi-WAN: `"…CARP/pfsync HA, multi-WAN with FIB isolation, AI threat detection, and a live React dashboard"`.
- Stats: replace `257` with verified count (run `grep -rE '^\s*\.route\(' aifw-api/src/ | wc -l` at the time of the change). Currently ~396, so `300+` is conservative and accurate. Other stats: `34 RBAC perms`, `5 AI detectors`, `6 NAT types`, `3 rule formats` — kept.

**Feature cards** (12, replacing current 10)

| # | Card | Note |
|---|---|---|
| 1 | Stateful firewall | kept |
| 2 | WireGuard & IPsec | kept |
| 3 | **Multi-WAN with FIB isolation** | NEW; links to `/multi-wan/` |
| 4 | IDS/IPS Suricata + Sigma + YARA | kept |
| 5 | AI threat detection | kept, add `badge-beta` "experimental, opt-in" tag to match README |
| 6 | Full NAT suite (incl. NAT64/46) | kept |
| 7 | Live dashboard | kept |
| 8 | Active-passive HA | kept; links to `/ha/` |
| 9 | **Reverse proxy + ACME** | NEW; links to `/docs/reverse-proxy/` |
| 10 | Granular RBAC + OAuth | kept; links to `/docs/auth/` |
| 11 | **OPNsense config import** | NEW; links to `/docs/backup/#opnsense-import` |
| 12 | Commit confirm (auto-revert) | kept |

**Screenshot gallery** — expand from 6 to ~12 figures. New entries: Threats (AI), Cluster, Reverse proxy, Time service, Roles & perms, Multi-WAN policy view (latter only if a UI capture exists). Each `<figcaption>` leads with a strong noun phrase ("Multi-WAN policy editor — drag policies to reorder priority"). Every `<img>` carries a descriptive `alt` and `loading="lazy"` plus explicit `width`/`height`.

**Comparison teaser**
- Drop the "Multi-WAN: planned" row.
- Add: "OPNsense config import" (AiFw ✓, others —), "Built-in reverse proxy" (AiFw TrafficCop, others —).
- Bump teaser to ~12 rows; full matrix link unchanged.

**Architecture block** — keep crate listing; add `aifw-multiwan` (or wherever the multi-WAN module compiles from — verify against the workspace `Cargo.toml` at implementation time). Keep version pin line at the bottom.

**Schema.org** — keep existing `SoftwareApplication`. Add `BreadcrumbList` (Home only).

### `features.md` — REFRESHED

Add these new top-level sections (in this order, after existing Firewall/NAT/VPN/IDS/AI sections):

- **Multi-WAN** — FIB isolation, gateway groups (failover / weighted / adaptive MOS), policy routing on 5-tuple+DSCP+geo, blast-radius preview, GitOps YAML export, anomaly scoring hook. Cross-link `/multi-wan/`.
- **Reverse proxy & ACME** — TrafficCop HTTP/TCP/UDP routers + services + middlewares; ACME issuance (push to TLS store / file / webhook). Cross-link `/docs/reverse-proxy/`.
- **DNS blocklists** (separate from DNS resolver) — source URL refresh, hit counters, allowlist override.
- **Backup & migration** — JSON backup/restore, S3 push, OPNsense XML importer, commit-confirm auto-revert, versioned config history with diff. Cross-link `/docs/backup/`.
- **Time service** — rTIME companion (NTP/PTP).
- **TLS inspection** — JA3/JA3S fingerprints, SNI filtering, cert validation, version enforcement (mentioned in README but absent from features.md today).

Update existing sections:
- "Authentication" — note OAuth is first-class (not plugin); link to `/docs/auth/` for full RBAC matrix.
- "Plugin system" — keep beta callout (still accurate per README + plugins.md).
- "Interfaces" — bump endpoint count from "300+" to verified count; bump CLI subcommand count to whatever `aifw-cli/src/commands.rs` actually exposes.

Schema.org: `ItemList` of `SoftwareFeature`.

### `compare.md` — REFRESHED

**Matrix changes:**

| Row | Change |
|---|---|
| "Multi-WAN / failover / LB" | AiFw: `planned` → `✓` |
| (new) "FIB-based isolation per WAN" | AiFw `✓`, OPNsense `—`, pfSense `—` |
| (new) "OPNsense config import" | AiFw `✓`, others `n/a` / `—` |
| (new) "Built-in reverse proxy" | AiFw `TrafficCop`, OPNsense `—` (HAProxy plugin), pfSense `—` (HAProxy pkg) |
| (new) "ACME / Let's Encrypt automation" | AiFw `✓`, OPNsense `plugin`, pfSense `pkg` |
| (new) "DNS blocklists" | AiFw `✓`, OPNsense `external (pi-hole)`, pfSense `pfBlockerNG pkg` |
| (new) "Backup to S3" | AiFw `✓`, OPNsense `plugin`, pfSense `pkg` |

**"Where AiFw wins"** — add: Multi-WAN with FIB isolation + blast-radius preview, OPNsense importer, Built-in reverse proxy + ACME, S3 backup.

**"Where AiFw is behind"** — remove the multi-WAN bullet entirely. Keep: OpenVPN, LDAP/RADIUS, captive portal, DDNS WAN client, CBQ, Snort rules, project age.

**"Should you switch?"** decision tree — remove "multi-WAN load balancing" from the "stay on pfSense/OPNsense" list. Otherwise prose stands.

Schema.org: keep existing `ItemList`.

### `install.md` — REFRESHED

- Verify the first-boot wizard step ordering against `aifw-setup/` actual output (root password → hostname → tuning → NICs → admin user + 2FA → DNS → policy).
- Mention the multi-WAN bootstrap toggle (commit `c1f0208` exposes this in the UI; users no longer need to edit `/boot/loader.conf` by hand).
- Verify update CLI commands (`aifw update check / install / rollback`) against `aifw-cli/src/commands.rs`.
- Schema.org: keep `HowTo` (already present).

### `multi-wan.md` — REFRESHED

- Replace the "edit `/boot/loader.conf`, set `net.fibs=16`, reboot" section with the new UI bootstrap flow (commit `c1f0208`). Keep the manual instructions in a small "Manual setup" appendix for advanced users.
- Add a "See also" footer linking to `/features/`, `/compare/`, `/docs/firewall/`.
- Schema.org: `TechArticle`.

### `ha.md` — LIGHT REFRESH

Already comprehensive. Touch-ups only:
- Add "See also" footer linking to `/features/`, `/compare/`, `/docs/auth/` (for RBAC permissions for cluster ops).
- Add `TechArticle` schema if not already present.
- Verify `aifw cluster` CLI commands against current `aifw-cli/src/commands.rs`.

### `plugins.md` — LIGHT REFRESH

Already comprehensive. Touch-ups only:
- Verify the 12 hook points against `aifw-plugins/src/hooks.rs` at implementation time.
- Add "See also" footer.
- Add `TechArticle` schema.

### `docs.md` — REWRITTEN as hub

Replace the placeholder text with a four-column card grid:

```
Get started               Networking            Security              Operations
─────────────             ─────────────         ────────              ──────────────
Install                   Firewall              IDS / IPS             HA cluster
First boot                NAT                   AI threats            Backup & migration
Web UI tour (anchor)      Multi-WAN             Auth & RBAC           Reverse proxy & ACME
                          VPN                   Plugins               API reference
                          DNS                                         CLI reference
                          DHCP                                        FAQ
                          Geo-IP
```

Each card: title (link to the page) + one-sentence description. Removes the architecture/companion-services block (lives on the homepage).

Schema.org: `CollectionPage` + `ItemList` of links.

### `faq.md` — NEW

15 entries, each ~50-100 words, all wrapped in `FAQPage` JSON-LD. Targeting:

1. Is AiFw a fork of OPNsense or pfSense?
2. Does AiFw require AI features to work?
3. Can I import my existing OPNsense config?
4. Does AiFw support Multi-WAN failover and load balancing?
5. What hardware do I need to run AiFw?
6. Is AiFw production-ready?
7. How do I migrate from pfSense to AiFw?
8. Does AiFw have a paid version or paid tier?
9. Where can I get help?
10. How does AiFw compare to OPNsense and pfSense?
11. Does AiFw support OpenVPN?
12. Can I run AiFw in a VM (Proxmox, ESXi, KVM, bhyve)?
13. Does AiFw work with WireGuard mobile clients?
14. How does HA failover work?
15. Is the source code auditable / where do I read it?

### Doc pages — pattern

Every page in `docs/docs/*.md` follows this structure:

```markdown
---
layout: default
title: <Topic> — AiFw <Action verb>
description: <140-160 char meta description with primary keyword>
permalink: /docs/<slug>/
date: 2026-05-09
---

<JSON-LD TechArticle>

# <Topic>

<Breadcrumb: Docs › Section › Topic>

## What it is
2-3 sentences. Keyword-rich.

## Quickstart
UI path + 1-2 worked API examples.

## CLI
`aifw <subcommand>` examples.

## API endpoints
Table of routes (method, path, description).

## Configuration
Key fields with defaults and notes.

## See also
- /features/
- /compare/
- /docs/<sibling>/
- Repo source pointer: aifw-core/src/<file>.rs

<small>Last updated: {{ page.date | date: "%Y-%m-%d" }}</small>
```

Source-of-truth notes per page:

| Page | Source files | Key keywords |
|---|---|---|
| `docs/firewall.md` | `aifw-core/src/engine.rs`; CLAUDE.md rules section; README CLI block | "FreeBSD pf rules", "stateful firewall scheduling" |
| `docs/nat.md` | `aifw-core/src/nat.rs`; NAT API in CLAUDE.md | "NAT64 NAT46 firewall", "1:1 NAT binat FreeBSD" |
| `docs/vpn.md` | `aifw-core/src/vpn.rs`; README WG/IPsec block | "WireGuard FreeBSD firewall", "IPsec ESP FreeBSD" |
| `docs/ids.md` | `aifw-ids/`; IDS endpoints in CLAUDE.md; cross-link AI detectors | "Suricata Sigma YARA firewall", "open source IPS" |
| `docs/dns.md` | `aifw-api/src/dns_resolver.rs`, `dns_blocklists.rs`; commit #231 | "FreeBSD DNS resolver", "DNS blocklist firewall" |
| `docs/dhcp.md` | rDHCP companion; HA failover; DDNS; #224 UI grouping | "FreeBSD DHCP server HA", "DHCP failover" |
| `docs/auth.md` | `aifw-api/src/auth/`; enumerate 34 perms; OAuth flows; TOTP; API keys | "firewall RBAC OAuth SSO", "TOTP 2FA firewall" |
| `docs/reverse-proxy.md` | `aifw-api/src/reverse_proxy.rs`; ACME endpoints; TrafficCop | "FreeBSD reverse proxy ACME", "Let's Encrypt firewall" |
| `docs/geoip.md` | `aifw-core/src/geoip.rs`; lookup endpoint | "geo-IP firewall blocking", "country block firewall" |
| `docs/backup.md` | `aifw-api/src/backup.rs`, `backup_s3.rs`, `opnsense/`; commit-confirm | "OPNsense to AiFw migration", "OPNsense XML import" |
| `docs/api.md` | `aifw-api/src/main.rs` route inventory grouped by subsystem; WS ticket flow | "AiFw REST API", "firewall API reference" |
| `docs/cli.md` | `aifw-cli/src/commands.rs` subcommand groups | "AiFw CLI", "firewall command line FreeBSD" |

## SEO plan

### Schema.org per page

- Homepage → `SoftwareApplication` (already there) + `BreadcrumbList`
- `install.md` → `HowTo` (already there) + `BreadcrumbList`
- `compare.md` → `ItemList` (already there) + `BreadcrumbList`
- `features.md` → `ItemList` of `SoftwareFeature` + `BreadcrumbList`
- `faq.md` → `FAQPage` (highest rich-snippet ROI)
- All other pages → `TechArticle` + `BreadcrumbList`

### Per-page meta

Each page gets a unique 50-60 char `<title>` and 140-160 char `<meta description>` targeting the primary keyword in the table above. `jekyll-seo-tag` already handles the boilerplate; we just need accurate `title:` and `description:` front-matter on every page.

### Internal linking

- Every doc page footer links back to `/features/` and `/compare/`.
- Homepage feature cards each link to their canonical doc page.
- `docs.md` hub links to every doc page.
- `compare.md` matrix rows hot-link to the relevant doc page where helpful (e.g., "WireGuard ✓" → `/docs/vpn/`).
- `features.md` deep-links each feature section to `/docs/<topic>/`.

### Per-page assets

- All `<img>` tags get descriptive `alt` (keyword-aware, no "screenshot"), explicit `width`/`height`, and `loading="lazy"`.
- Hero `vid-01-dashboard-live.gif` — audit size; if >2 MB, swap to `<video autoplay muted loop playsinline>` with MP4 + WebM sources. Defer the swap if size is fine.
- Add Open Graph image fallback per page via the `image:` front-matter (already defaulted to `/assets/AiFw-1.png`).

### Other infra

- `_config.yml`: confirm `jekyll-seo-tag` and `jekyll-feed` are loaded; add `jekyll-sitemap` if not already present (the existing `site-map.xml` is hand-maintained — replace with the plugin output to avoid drift). Add `superpowers` to `exclude:` so spec files don't ship.
- `robots.txt`: confirm not blocking `/superpowers/` accidentally; allow the new sitemap.
- Last-updated stamp on every page using `{{ page.date }}` (set in front-matter); falls back to `site.time` if absent.
- Breadcrumb partial in `_layouts/default.html` reads `page.section` and `page.title`.

### Out-of-band SEO actions (instructions to maintainer, not implementation)

Document in the spec but do not perform:

- Submit `https://aifw.zerosandones.us/sitemap.xml` to Google Search Console.
- Submit the same to Bing Webmaster Tools.
- Add the `google_site_verification` and `bing_site_verification` codes to `_config.yml` once obtained.
- After publish, validate every page through `https://search.google.com/test/rich-results`.

## Implementation phases

Each phase is committable on its own. Each commit bumps `Cargo.toml` workspace version + `aifw-ui/package.json` per the global rule.

1. **Layout + nav rebuild** — `_layouts/default.html` (dropdown, breadcrumbs, schema injection points, last-updated stamp), `assets/style.css` (dropdown + breadcrumb + last-updated styles), `_config.yml` (`jekyll-sitemap`, `superpowers` exclude). Verify existing pages render unchanged.
2. **Homepage refresh** — hero stats, 12 feature cards, gallery expansion, comparison teaser fix, AI experimental tag.
3. **`compare.md` + `features.md`** — matrix corrections + new rows; new sections in features.
4. **`multi-wan.md` + `install.md` + `ha.md` + `plugins.md`** — smaller refreshes; multi-wan.md replaces the loader.conf bootstrap section, install.md verifies wizard order and adds the multi-wan UI bootstrap note, ha.md and plugins.md get "See also" footers + schema + minor accuracy passes.
5. **Doc pages batch A (networking)** — firewall, nat, vpn, dns, dhcp, geoip.
6. **Doc pages batch B (security + ops)** — ids, auth, reverse-proxy, backup.
7. **Doc pages batch C (reference)** — api, cli.
8. **`docs.md` hub + `faq.md`** — depend on prior pages so links land.
9. **SEO polish** — schema validation, canonical verification, image alt audit, sitemap regen, breadcrumb wire-up.
10. **Local Jekyll preview + link audit** — `bundle exec jekyll build` + `htmlproofer`.

## Validation

Per phase:
- `cd docs && bundle exec jekyll build` succeeds with zero errors.
- New pages render locally without 404s in their internal links.

Final:
- `bundle exec htmlproofer ./_site` (or equivalent) reports zero broken internal links and all images have alt text.
- Manual click-through of every nav item and every "See also" link.
- (Maintainer step, post-merge) Spot-check 3-4 pages through Google's Rich Results Test.

## Asset list

Copy these from `/screenshots/` into `/docs/assets/screenshots/`:

```
08-ids-rulesets.png
09-dns.png
11-dhcp-subnets.png
12-interfaces.png
14-geoip.png
16-time.png
17-users.png
18-roles.png
19-settings.png
20-updates.png
vid-02-rules-browse.gif
vid-03-blocked-live.gif
vid-04-connections-live.gif
vid-05-ids-overview.gif
```

If a Multi-WAN screen capture exists in `/screenshots/`, copy it. If not, the multi-WAN page launches without a screenshot; capture is logged as a follow-up.

## Risks and trade-offs

- **Stat drift.** Hero stats and route counts drift over time. Mitigation: spec calls for verification at implementation time, not hardcoded numbers from this doc. Same applies to CLI subcommand count.
- **Screenshot drift.** UI evolves and screenshots go stale. No good mitigation in this scope; flagged as a follow-up.
- **OG image per page.** Every page sharing the same `AiFw-1.png` is the cheap option. Per-page generated OG images would be a noticeable SEO win but require a build step (e.g., `jekyll-og-image`). Out of scope for this spec; logged as a follow-up.
- **Schema validation.** The maintainer has to run rich-results test manually post-publish. No automated check in CI.

## Estimated work

12 new pages × ~150 lines avg + 6 refreshed pages + layout/CSS changes + asset copies ≈ **2,500-3,000 lines of new content + ~200 lines of layout/CSS**. Mostly markdown.
