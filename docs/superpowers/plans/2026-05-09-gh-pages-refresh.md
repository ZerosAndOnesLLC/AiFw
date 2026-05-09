# GitHub Pages full content refresh + SEO — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `https://aifw.zerosandones.us/` up to date with shipped features (Multi-WAN, OPNsense importer, Reverse proxy + ACME, DNS blocklists, S3 backup, etc.), restructure docs into a real hub with grouped nav, and heavily SEO-optimise.

**Architecture:** Jekyll site published from `docs/` via GitHub Pages. Layout in `_layouts/default.html` + CSS in `assets/style.css`. Content in markdown files. SEO via `jekyll-seo-tag` (already loaded) + per-page Schema.org JSON-LD + breadcrumbs. No JS framework, no build pipeline beyond `bundle exec jekyll build`.

**Tech Stack:** Jekyll, kramdown markdown, `jekyll-seo-tag`, `jekyll-feed`, `jekyll-sitemap` (to add), Schema.org JSON-LD, vanilla CSS.

**Spec:** `docs/superpowers/specs/2026-05-09-gh-pages-refresh-design.md`.

**Per-commit version bump:** Per `CLAUDE.md`, every commit bumps `Cargo.toml` workspace version + `aifw-ui/package.json`. Use **patch bumps** unless the task adds a new top-level page (= minor). Current version is `5.92.4`.

**Verification command (used in many tasks):** From the repo root:

```bash
cd docs && bundle install --quiet && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -20
```

Expected: `done in N.NN seconds.` with no error output. Site renders into `docs/_site/`.

**Local preview:** `cd docs && bundle exec jekyll serve --livereload` then open `http://localhost:4000/`.

---

## Task 0: Pre-flight — verify volatile facts

**Files:** none (writes notes to scratch — not committed).

The plan uses these counts in many later tasks. Verify them at the start so they're correct in the published site.

- [ ] **Step 1: Verify API route count**

```bash
grep -rE "^\s*\.route\(" /home/mack/dev/AiFw/aifw-api/src/ | wc -l
```

Record the number. Use **`300+`** in user-facing copy when the count is >= 300, **`400+`** when >= 400.

- [ ] **Step 2: Verify CLI subcommand count**

```bash
ls /home/mack/dev/AiFw/aifw-cli/src/
grep -cE 'fn cmd_|^\s*\("[a-z][a-z-]+"' /home/mack/dev/AiFw/aifw-cli/src/commands.rs
grep -cE '"[a-z][a-z_-]+" =>' /home/mack/dev/AiFw/aifw-cli/src/commands.rs
```

Record the largest reasonable number (top-level subcommand groups, not every leaf flag). Use this for the "CLI subcommands" copy on `features.md` and `index.html`.

- [ ] **Step 3: Verify multi-WAN module location**

```bash
ls /home/mack/dev/AiFw/aifw-core/src/multiwan/ 2>/dev/null
ls /home/mack/dev/AiFw/aifw-api/src/multiwan.rs 2>/dev/null
```

Confirms multi-WAN module path for the architecture block on `index.html`.

- [ ] **Step 4: Verify plugin hook count**

```bash
grep -E "^\s*[A-Z][a-zA-Z]+,\s*$" /home/mack/dev/AiFw/aifw-plugins/src/hooks.rs 2>/dev/null | wc -l
```

Confirms the "12 hook points" claim in `plugins.md`. If different, update the plugins.md refresh in Task 4d.

- [ ] **Step 5: Verify screenshots present**

```bash
ls /home/mack/dev/AiFw/screenshots/ | grep -E '\.(png|gif)$'
ls /home/mack/dev/AiFw/docs/assets/screenshots/
```

Confirms which screenshots already ship in the site vs. need copying in Task 1.

- [ ] **Step 6: Record current Cargo.toml version**

```bash
grep '^version' /home/mack/dev/AiFw/Cargo.toml | head -1
```

This is the baseline. Each commit below bumps this.

No commit. This task only gathers data for later tasks.

---

## Task 1: Layout, nav, CSS, Jekyll config

**Files:**
- Modify: `docs/_config.yml`
- Modify: `docs/Gemfile`
- Modify: `docs/_layouts/default.html`
- Create: `docs/_includes/breadcrumb.html`
- Create: `docs/_includes/last-updated.html`
- Modify: `docs/assets/style.css`
- Modify: `Cargo.toml` (version bump)
- Modify: `aifw-ui/package.json` (version bump)

Build the new dropdown nav, breadcrumb partial, and last-updated stamp. Add `jekyll-sitemap` and exclude `superpowers/`.

- [ ] **Step 1: Add jekyll-sitemap to Gemfile**

`docs/Gemfile`:

```ruby
source "https://rubygems.org"

gem "github-pages", group: :jekyll_plugins
gem "webrick"
```

`github-pages` already bundles `jekyll-sitemap`, `jekyll-seo-tag`, and `jekyll-feed`. No new gems needed; we just enable the sitemap plugin in `_config.yml`.

- [ ] **Step 2: Update _config.yml — add jekyll-sitemap, exclude superpowers, add nav data**

Locate the `plugins:` block and add `jekyll-sitemap`. Locate `exclude:` and add `superpowers`. Add a `nav:` data block at the bottom for the dropdown.

`docs/_config.yml`:

```yaml
plugins:
  - jekyll-seo-tag
  - jekyll-feed
  - jekyll-sitemap

# ... existing config ...

exclude:
  - README.md
  - Gemfile
  - Gemfile.lock
  - vendor
  - superpowers

# Top nav definition — referenced by _layouts/default.html
nav:
  primary:
    - title: Features
      url: /features/
    - title: Docs
      dropdown:
        - { title: "Install",        url: "/install/" }
        - { title: "First boot",     url: "/install/#first-boot-setup-wizard" }
        - { divider: true }
        - { title: "Firewall",       url: "/docs/firewall/" }
        - { title: "NAT",            url: "/docs/nat/" }
        - { title: "VPN",            url: "/docs/vpn/" }
        - { title: "IDS / IPS",      url: "/docs/ids/" }
        - { title: "Multi-WAN",      url: "/multi-wan/" }
        - { title: "HA cluster",     url: "/ha/" }
        - { title: "DNS",            url: "/docs/dns/" }
        - { title: "DHCP",           url: "/docs/dhcp/" }
        - { title: "Geo-IP",         url: "/docs/geoip/" }
        - { title: "Auth & RBAC",    url: "/docs/auth/" }
        - { title: "Reverse proxy",  url: "/docs/reverse-proxy/" }
        - { title: "Backup & migration", url: "/docs/backup/" }
        - { title: "Plugins",        url: "/plugins/" }
        - { divider: true }
        - { title: "API reference", url: "/docs/api/" }
        - { title: "CLI reference", url: "/docs/cli/" }
        - { title: "FAQ",           url: "/faq/" }
    - title: Compare
      url: /compare/
    - title: Download
      url: https://github.com/ZerosAndOnesLLC/AiFw/releases/latest
      external: true
    - title: GitHub
      url: https://github.com/ZerosAndOnesLLC/AiFw
      external: true
```

- [ ] **Step 3: Create breadcrumb include**

`docs/_includes/breadcrumb.html`:

```liquid
{% if page.breadcrumb %}
<nav class="breadcrumb" aria-label="Breadcrumb">
  <ol>
    <li><a href="{{ '/' | relative_url }}">Home</a></li>
    {% for crumb in page.breadcrumb %}
      {% if forloop.last %}
        <li aria-current="page">{{ crumb.title }}</li>
      {% else %}
        <li><a href="{{ crumb.url | relative_url }}">{{ crumb.title }}</a></li>
      {% endif %}
    {% endfor %}
  </ol>
</nav>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    { "@type": "ListItem", "position": 1, "name": "Home", "item": "{{ site.url }}/" }
    {%- for crumb in page.breadcrumb -%}
    , { "@type": "ListItem", "position": {{ forloop.index | plus: 1 }}, "name": "{{ crumb.title }}"{% unless forloop.last %}, "item": "{{ site.url }}{{ crumb.url }}"{% endunless %} }
    {%- endfor -%}
  ]
}
</script>
{% endif %}
```

- [ ] **Step 4: Create last-updated include**

`docs/_includes/last-updated.html`:

```liquid
{% if page.date %}
<p class="last-updated">Last updated: <time datetime="{{ page.date | date: '%Y-%m-%d' }}">{{ page.date | date: "%B %-d, %Y" }}</time></p>
{% endif %}
```

- [ ] **Step 5: Rewrite the `<header>` and inject breadcrumb + last-updated in `_layouts/default.html`**

Replace the `<header class="site-header">…</header>` block and the `<main>` block. Keep everything else (head, footer) intact.

`docs/_layouts/default.html` — replace lines 43-61 with:

```html
  <header class="site-header">
    <div class="container">
      <a href="{{ '/' | relative_url }}" class="brand">
        <img src="{{ '/assets/AiFw-1.png' | relative_url }}" alt="AiFw" class="brand-logo">
        <span>AiFw</span>
      </a>
      <nav class="primary-nav" aria-label="Primary">
        <ul class="nav-list">
          {% for item in site.nav.primary %}
            {% if item.dropdown %}
              <li class="nav-item has-dropdown">
                <button class="nav-trigger" aria-expanded="false" aria-haspopup="true">{{ item.title }} <span aria-hidden="true">▾</span></button>
                <ul class="nav-dropdown">
                  {% for sub in item.dropdown %}
                    {% if sub.divider %}
                      <li class="nav-divider" role="separator"></li>
                    {% else %}
                      <li><a href="{{ sub.url | relative_url }}">{{ sub.title }}</a></li>
                    {% endif %}
                  {% endfor %}
                </ul>
              </li>
            {% else %}
              <li class="nav-item">
                {% if item.external %}
                  <a href="{{ item.url }}" target="_blank" rel="noopener">{{ item.title }}{% if item.title == 'GitHub' %} ↗{% endif %}</a>
                {% else %}
                  <a href="{{ item.url | relative_url }}">{{ item.title }}</a>
                {% endif %}
              </li>
            {% endif %}
          {% endfor %}
        </ul>
      </nav>
    </div>
  </header>

  <main>
    {% include breadcrumb.html %}
    {{ content }}
    {% include last-updated.html %}
  </main>
```

- [ ] **Step 6: Add nav-dropdown, breadcrumb, and last-updated styles**

Append to `docs/assets/style.css` (after the existing nav block, around line 124):

```css
/* ─────────── Nav dropdown ─────────── */
.primary-nav .nav-list {
  display: flex;
  align-items: center;
  gap: 28px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.primary-nav .nav-item { position: relative; }
.primary-nav .nav-trigger {
  background: none;
  border: 0;
  color: var(--text-1);
  font: inherit;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  padding: 0;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.primary-nav .nav-trigger:hover,
.primary-nav .nav-trigger:focus { color: var(--text-0); outline: none; }
.primary-nav .nav-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  min-width: 220px;
  background: rgba(10, 14, 24, 0.96);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(30,43,69,0.6);
  border-radius: 10px;
  padding: 8px 0;
  list-style: none;
  margin: 0;
  opacity: 0;
  pointer-events: none;
  transform: translateY(-4px);
  transition: opacity 0.12s, transform 0.12s;
  z-index: 100;
}
.primary-nav .has-dropdown:hover .nav-dropdown,
.primary-nav .has-dropdown:focus-within .nav-dropdown {
  opacity: 1;
  pointer-events: auto;
  transform: translateY(0);
}
.primary-nav .has-dropdown:hover .nav-trigger,
.primary-nav .has-dropdown:focus-within .nav-trigger { color: var(--text-0); }
.primary-nav .has-dropdown:focus-within .nav-trigger,
.primary-nav .nav-trigger[aria-expanded="true"] { color: var(--text-0); }
.primary-nav .nav-dropdown a {
  display: block;
  padding: 8px 16px;
  color: var(--text-1);
  font-size: 14px;
  text-decoration: none;
  white-space: nowrap;
}
.primary-nav .nav-dropdown a:hover { color: var(--text-0); background: rgba(255,255,255,0.04); }
.primary-nav .nav-divider {
  height: 1px;
  background: rgba(30,43,69,0.6);
  margin: 6px 12px;
}
@media (max-width: 720px) {
  .primary-nav .nav-list { gap: 12px; }
  .primary-nav .nav-item:not(.has-dropdown) > a:not(.btn) { display: none; }
  .primary-nav .nav-dropdown {
    position: static;
    opacity: 1;
    pointer-events: auto;
    transform: none;
    background: transparent;
    border: 0;
    padding: 0;
    box-shadow: none;
  }
  .primary-nav .nav-trigger { display: none; }
}

/* ─────────── Breadcrumb ─────────── */
.breadcrumb {
  max-width: 880px;
  margin: 24px auto 0;
  padding: 0 24px;
  font-size: 13px;
  color: var(--text-2);
}
.breadcrumb ol {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.breadcrumb li:not(:last-child)::after {
  content: "›";
  margin-left: 6px;
  color: var(--text-3, var(--text-2));
}
.breadcrumb a { color: var(--text-2); text-decoration: none; }
.breadcrumb a:hover { color: var(--text-0); }

/* ─────────── Last-updated ─────────── */
.last-updated {
  max-width: 880px;
  margin: 48px auto 64px;
  padding: 16px 24px 0;
  border-top: 1px solid rgba(30,43,69,0.5);
  color: var(--text-2);
  font-size: 13px;
}
```

The mobile rule that hides plain `nav a:not(.btn)` (lines 932-933) needs to be neutralised because we replaced the nav structure. Either remove those two lines (now dead) or leave them — they target a structure that no longer exists, so they're harmless. Verify by inspecting the rendered mobile nav after Step 9.

- [ ] **Step 7: Bump version**

`Cargo.toml`: `version = "5.92.4"` → `version = "5.93.0"` (minor bump because nav adds new top-level capability).

`aifw-ui/package.json`: same.

```bash
sed -i 's/^version = "5\.92\.4"/version = "5.93.0"/' /home/mack/dev/AiFw/Cargo.toml
sed -i 's/"version": "5\.92\.4"/"version": "5.93.0"/' /home/mack/dev/AiFw/aifw-ui/package.json
```

Verify both files updated:

```bash
grep -E '^version|"version"' /home/mack/dev/AiFw/Cargo.toml /home/mack/dev/AiFw/aifw-ui/package.json | head
```

- [ ] **Step 8: Build and verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle install --quiet && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -20
```

Expected: `done in N.NN seconds.` No errors.

- [ ] **Step 9: Local visual verification**

Run:

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll serve --livereload --port 4000
```

Open `http://localhost:4000/` in a browser. Verify:
- Nav shows Features, Docs ▾, Compare, Download ↗, GitHub ↗.
- Hovering "Docs" reveals the dropdown with all entries (Install, First boot, divider, Firewall, NAT, VPN, IDS/IPS, Multi-WAN, HA cluster, DNS, DHCP, Geo-IP, Auth & RBAC, Reverse proxy, Backup & migration, Plugins, divider, API reference, CLI reference, FAQ).
- Existing pages (Features, Compare, Install) render unchanged below the nav.
- No JavaScript errors in the browser console.
- Mobile breakpoint (≤720px): the dropdown items become inline; no broken layout.

Stop the server with Ctrl-C.

- [ ] **Step 10: Commit**

```bash
cd /home/mack/dev/AiFw && git add docs/_config.yml docs/_layouts/default.html docs/_includes/ docs/assets/style.css Cargo.toml aifw-ui/package.json && git commit -m "docs(site): grouped-dropdown nav, breadcrumb partial, sitemap plugin

- Add jekyll-sitemap, exclude superpowers/ from publish
- Add Docs ▾ dropdown with 18 entries grouped install / network / security / ops / reference
- Add breadcrumb include with BreadcrumbList JSON-LD
- Add last-updated stamp include
- CSS for dropdown, breadcrumb, last-updated"
```

---

## Task 2: Homepage refresh

**Files:**
- Modify: `docs/index.html`
- Modify: copy missing screenshots into `docs/assets/screenshots/` (see Task 0 step 5)
- Modify: `Cargo.toml`, `aifw-ui/package.json`

Updates: hero stats, tagline, 12 feature cards (was 10), expanded gallery, comparison teaser, AI experimental tag, architecture block.

- [ ] **Step 1: Copy missing screenshots**

```bash
cd /home/mack/dev/AiFw && cp -n screenshots/08-ids-rulesets.png screenshots/09-dns.png screenshots/11-dhcp-subnets.png screenshots/12-interfaces.png screenshots/14-geoip.png screenshots/16-time.png screenshots/17-users.png screenshots/18-roles.png screenshots/19-settings.png screenshots/20-updates.png screenshots/vid-02-rules-browse.gif screenshots/vid-03-blocked-live.gif screenshots/vid-04-connections-live.gif screenshots/vid-05-ids-overview.gif docs/assets/screenshots/
ls docs/assets/screenshots/ | wc -l
```

Expected: now ~24 entries.

- [ ] **Step 2: Update hero tagline + stats in `docs/index.html`**

Replace the `<p class="lead">` (lines 41-46) with:

```html
    <p class="lead">
      A complete firewall platform in one Rust codebase: stateful pf rules,
      Suricata + Sigma + YARA IDS, WireGuard &amp; IPsec VPN, CARP/pfsync HA,
      multi-WAN with FIB isolation, AI threat detection, and a live React dashboard.
      An honest alternative to pfSense and OPNsense.
    </p>
```

Replace the `<div class="hero-stats">` block (lines 57-63). Use the verified API route count from Task 0 step 1; the example below uses `300+`:

```html
    <div class="hero-stats">
      <div class="hero-stat"><div class="hero-stat-num">300+</div><div class="hero-stat-label">API endpoints</div></div>
      <div class="hero-stat"><div class="hero-stat-num">34</div><div class="hero-stat-label">RBAC perms</div></div>
      <div class="hero-stat"><div class="hero-stat-num">5</div><div class="hero-stat-label">AI detectors</div></div>
      <div class="hero-stat"><div class="hero-stat-num">6</div><div class="hero-stat-label">NAT types</div></div>
      <div class="hero-stat"><div class="hero-stat-num">3</div><div class="hero-stat-label">Rule formats</div></div>
    </div>
```

- [ ] **Step 3: Tag the AI feature card as experimental**

Find the AI threat detection card (currently around line 111). Change the `<h3>` line:

```html
        <h3>AI threat detection <span class="badge-beta">opt-in · experimental</span></h3>
```

The `badge-beta` style already exists (used on the Plugin system feature on `features.md`).

- [ ] **Step 4: Replace SwapAble feature cards: insert Multi-WAN, Reverse proxy + ACME, OPNsense importer**

Currently 10 cards. We're going to 12. Insert these three new cards into `<div class="features">` (around line 82) after the AI threat detection card and before the Full NAT card. Keep the 3-column grid (Tailwind/CSS handles 12 = 4 rows × 3 cols).

```html
      <div class="feature">
        <div class="feature-icon" style="background: rgba(34,197,94,0.10); border-color: rgba(34,197,94,0.20); color: var(--green);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M3 12h18M9 6l-6 6 6 6m6-12l6 6-6 6"/></svg>
        </div>
        <h3>Multi-WAN with FIB isolation</h3>
        <p>Each WAN in its own FreeBSD FIB. Gateway groups with failover, weighted, and adaptive MOS-weighted policies. Per-flow blast-radius preview before apply. <a href="{{ '/multi-wan/' | relative_url }}" style="color: var(--green);">Setup →</a></p>
        <div class="feature-tags"><span class="tag">FIB</span><span class="tag">PBR</span><span class="tag">SLA</span></div>
      </div>

      <div class="feature">
        <div class="feature-icon" style="background: rgba(6,182,212,0.10); border-color: rgba(6,182,212,0.20); color: var(--cyan);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <h3>Reverse proxy + ACME</h3>
        <p>Built-in TrafficCop reverse proxy: HTTP, TCP, UDP routers, services, middlewares. ACME / Let's Encrypt automation pushes certs straight to the TLS store, file, or webhook. <a href="{{ '/docs/reverse-proxy/' | relative_url }}" style="color: var(--cyan);">Configure →</a></p>
        <div class="feature-tags"><span class="tag">TrafficCop</span><span class="tag">ACME</span><span class="tag">TLS</span></div>
      </div>

      <div class="feature">
        <div class="feature-icon" style="background: rgba(245,158,11,0.10); border-color: rgba(245,158,11,0.20); color: var(--amber);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v-3a4 4 0 014-4h12m0 0l-4-4m4 4l-4 4"/></svg>
        </div>
        <h3>OPNsense config import</h3>
        <p>Drop-in migration from OPNsense. Parse the XML config, see exactly what'll change, apply atomically with rollback. Recently rewritten end-to-end. <a href="{{ '/docs/backup/#opnsense-import' | relative_url }}" style="color: var(--amber);">Migration guide →</a></p>
        <div class="feature-tags"><span class="tag">XML</span><span class="tag">atomic</span><span class="tag">rollback</span></div>
      </div>
```

- [ ] **Step 5: Expand the screenshot gallery from 6 to 12 figures**

Replace `<div class="gallery">` block (around lines 176-201) with:

```html
    <div class="gallery">
      <figure>
        <img src="{{ '/assets/screenshots/01-dashboard.png' | relative_url }}" alt="AiFw live dashboard with system metrics, service health, and IDS summary" loading="lazy" width="1200" height="700">
        <figcaption><strong>Dashboard</strong>Live system metrics, service health, and IDS summary in one view.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/02-traffic.png' | relative_url }}" alt="AiFw NAT flow topology — per-interface pipes with throughput-scaled widths" loading="lazy" width="1200" height="700">
        <figcaption><strong>NAT flow topology</strong>Per-interface pipes with throughput-scaled widths — see exactly where traffic goes.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/03-rules.png' | relative_url }}" alt="AiFw firewall rules editor with drag-to-reorder and time-based scheduling" loading="lazy" width="1200" height="700">
        <figcaption><strong>Firewall rules</strong>Drag to reorder, schedule by time, group by alias. IPv4 and IPv6 side by side.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/07-ids-dashboard.png' | relative_url }}" alt="AiFw IDS/IPS dashboard with Suricata, Sigma, and YARA engines" loading="lazy" width="1200" height="700">
        <figcaption><strong>IDS / IPS</strong>Suricata, Sigma, and YARA engines on one pane. Classify, suppress, tune.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/13-vpn.png' | relative_url }}" alt="AiFw WireGuard VPN management with auto-keypair generation and per-peer config export" loading="lazy" width="1200" height="700">
        <figcaption><strong>WireGuard</strong>Auto-keypair generation, per-peer config export, live handshake tracking.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/10-dhcp.png' | relative_url }}" alt="AiFw DHCP server with HA failover and live lease tracking" loading="lazy" width="1200" height="700">
        <figcaption><strong>DHCP</strong>HA failover, reservations, live lease tracking. Powered by rDHCP.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/15-reverse-proxy.png' | relative_url }}" alt="AiFw reverse proxy with HTTP, TCP, and UDP routers" loading="lazy" width="1200" height="700">
        <figcaption><strong>Reverse proxy</strong>TrafficCop routes HTTP, TCP, and UDP. Middlewares, health checks, ACME certs.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/14-geoip.png' | relative_url }}" alt="AiFw Geo-IP filtering with country-based block and allow rules" loading="lazy" width="1200" height="700">
        <figcaption><strong>Geo-IP</strong>Country-based block / allow with on-disk GeoLite2 lookups.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/16-time.png' | relative_url }}" alt="AiFw NTP and PTP time service status" loading="lazy" width="1200" height="700">
        <figcaption><strong>Time service</strong>NTP and PTP via the rTIME companion. Drift, peer health, and stratum.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/18-roles.png' | relative_url }}" alt="AiFw roles and permissions matrix with 34 granular RBAC permissions" loading="lazy" width="1200" height="700">
        <figcaption><strong>Roles &amp; permissions</strong>34 granular RBAC permissions. Built-in admin / operator / viewer plus custom roles.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/19-settings.png' | relative_url }}" alt="AiFw settings panel with TLS policy, metrics backend, and API config" loading="lazy" width="1200" height="700">
        <figcaption><strong>Settings</strong>TLS policy, metrics backend, system tuning — all from the web UI.</figcaption>
      </figure>
      <figure>
        <img src="{{ '/assets/screenshots/20-updates.png' | relative_url }}" alt="AiFw self-update workflow with one-click rollback" loading="lazy" width="1200" height="700">
        <figcaption><strong>Self-update</strong>Update check, download, verify, install, restart. One-click rollback.</figcaption>
      </figure>
    </div>
```

- [ ] **Step 6: Fix comparison teaser**

Find the `<div class="compare-teaser">` block (around line 213). Remove the row that currently says "Multi-WAN load balancing | planned | ✓ | ✓". Add two new rows:

```html
      <div class="row"><div class="feat-name">Multi-WAN with FIB isolation</div><div><span class="ind yes">✓</span></div><div><span class="ind no">—</span></div><div><span class="ind no">—</span></div></div>
      <div class="row"><div class="feat-name">OPNsense config import</div><div><span class="ind yes">✓</span></div><div><span class="ind no">n/a</span></div><div><span class="ind no">—</span></div></div>
      <div class="row"><div class="feat-name">Built-in reverse proxy</div><div><span class="ind yes">TrafficCop</span></div><div><span class="ind no">—</span></div><div><span class="ind no">—</span></div></div>
```

- [ ] **Step 7: Update architecture block**

Find the `<div class="arch">` block (lines 240-261). Add a line for the multi-WAN module after `aifw-core`:

```html
<div class="line"><span class="crate">aifw-core</span>        engines: rules, NAT, VPN, HA, shaping, audit, multi-WAN</div>
```

(The multi-WAN engines live under `aifw-core/src/multiwan/` per Task 0 step 3 — no separate crate.)

- [ ] **Step 8: Build and verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -20
```

Expected: clean build.

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll serve --port 4000
```

Open `http://localhost:4000/`. Verify: hero, 12 feature cards in 4 rows of 3, 12-figure gallery, refreshed teaser. Stop with Ctrl-C.

- [ ] **Step 9: Bump version + commit**

`Cargo.toml`: `5.93.0` → `5.93.1`. Same for `aifw-ui/package.json`.

```bash
sed -i 's/^version = "5\.93\.0"/version = "5.93.1"/' Cargo.toml
sed -i 's/"version": "5\.93\.0"/"version": "5.93.1"/' aifw-ui/package.json
git add docs/index.html docs/assets/screenshots/ Cargo.toml aifw-ui/package.json
git commit -m "docs(site): refresh homepage — multi-WAN, reverse proxy, OPNsense importer

- Add 3 new feature cards (multi-WAN, reverse proxy + ACME, OPNsense importer)
- Tag AI threat detection card as opt-in / experimental (matches README)
- Update hero stats: 300+ API endpoints
- Mention multi-WAN in hero tagline
- Expand gallery from 6 to 12 figures
- Comparison teaser: drop 'Multi-WAN: planned', add new winning rows
- Architecture block: add multi-WAN engines under aifw-core"
```

---

## Task 3a: `compare.md` matrix corrections

**Files:**
- Modify: `docs/compare.md`
- Modify: `Cargo.toml`, `aifw-ui/package.json`

- [ ] **Step 1: Fix the multi-WAN row**

In `docs/compare.md`, find:

```html
<tr><td>Multi-WAN / failover / LB</td><td class="partial">planned</td><td class="yes">✓</td><td class="yes">✓</td></tr>
```

Replace with:

```html
<tr><td>Multi-WAN / failover / LB</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>FIB-based isolation per WAN</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>Multi-WAN blast-radius preview</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
```

- [ ] **Step 2: Add new rows to the matrix**

In the "Config management" section, after the `OPNsense config import` row, add:

```html
<tr class="section-row"><td colspan="4">Reverse proxy</td></tr>
```

(only if there isn't one already; the file already has a reverse-proxy section). Then in the "Reverse proxy" section, add ACME row:

```html
<tr><td>ACME / Let's Encrypt automation</td><td class="yes">✓</td><td class="partial">plugin</td><td class="partial">pkg</td></tr>
```

In the DNS section, after `Dynamic DNS client (WAN)`, add:

```html
<tr><td>DNS blocklists</td><td class="yes">✓</td><td class="partial">pi-hole</td><td class="partial">pfBlockerNG</td></tr>
```

Add a new "Backup &amp; migration" section (place after "Config management" section, before "Certificate Authority"):

```html
<tr class="section-row"><td colspan="4">Backup &amp; migration</td></tr>
<tr><td>JSON backup / restore</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>S3 backup destination</td><td class="yes">✓</td><td class="partial">plugin</td><td class="partial">pkg</td></tr>
<tr><td>OPNsense XML import</td><td class="yes">✓</td><td class="no">n/a</td><td class="no">—</td></tr>
```

- [ ] **Step 3: Rewrite "Where AiFw wins"**

Locate the `## Where AiFw wins` heading. Add bullets at the start (most differentiating first):

```markdown
- **Multi-WAN with FIB isolation** — each WAN lives in its own FreeBSD FIB (just like a Juniper routing-instance). Gateway groups with failover, weighted load-balance, and MOS-weighted adaptive policies. Blast-radius preview shows which existing flows would migrate before you apply. No other open-source FreeBSD firewall does this.
- **OPNsense config import** — drop-in migration. Parse the XML, preview the diff, apply atomically with rollback. Recently rewritten end-to-end (#230, #248–#252).
- **Built-in reverse proxy + ACME** — TrafficCop runs HTTP, TCP, and UDP. ACME issuance pushes certs straight to the TLS store, file, or webhook. No HAProxy plugin install dance.
```

- [ ] **Step 4: Rewrite "Where AiFw is behind"**

Find:

```markdown
- **No Multi-WAN failover / load balancing** — planned but not shipped.
```

**Delete that bullet entirely.** Multi-WAN is shipped.

- [ ] **Step 5: Rewrite "Should you switch?"**

Find:

```markdown
- You rely on OpenVPN, captive portal, multi-WAN load balancing, or LDAP
```

Replace with:

```markdown
- You rely on OpenVPN, captive portal, or LDAP
```

- [ ] **Step 6: Add `date` front-matter for last-updated stamp**

At the top of `docs/compare.md`, add `date: 2026-05-09` to the front-matter:

```yaml
---
layout: default
title: AiFw vs pfSense vs OPNsense — Feature Comparison
description: Honest head-to-head comparison of AiFw, OPNsense, and pfSense. WireGuard, IDS/IPS, NAT, VPN, HA, multi-WAN, and more — see what each firewall actually supports.
permalink: /compare/
date: 2026-05-09
breadcrumb:
  - { title: "Compare", url: "/compare/" }
---
```

(Description tweaked to add "multi-WAN".)

- [ ] **Step 7: Build, verify, bump, commit**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Bump `5.93.1` → `5.93.2` in both files. Commit:

```bash
git add docs/compare.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): compare matrix — multi-WAN ships, add OPNsense import + ACME + S3 + DNS blocklists rows"
```

---

## Task 3b: `features.md` additions

**Files:**
- Modify: `docs/features.md`
- Modify: `Cargo.toml`, `aifw-ui/package.json`

Add 6 new sections + update existing.

- [ ] **Step 1: Update front-matter**

Add `date: 2026-05-09` and breadcrumb:

```yaml
---
layout: default
title: Features — AiFw Firewall
description: Complete feature list for AiFw — stateful firewall, WireGuard, IPsec, IDS/IPS with Sigma and YARA rules, AI threat detection, multi-WAN with FIB isolation, NAT, DNS, DHCP, HA clustering, OPNsense importer, and more.
permalink: /features/
date: 2026-05-09
breadcrumb:
  - { title: "Features", url: "/features/" }
---
```

- [ ] **Step 2: Add Multi-WAN section after "NAT" section**

Insert after the existing NAT section, before "VPN":

```markdown
## Multi-WAN

Enterprise-grade multi-WAN built on FreeBSD FIBs and pf. Designed to match what Cisco IOS PBR + IP SLA and Juniper routing-instances + RPM offer, with a few features neither has.

- **FIB isolation** — each WAN lives in its own FreeBSD FIB, the same isolation primitive as Juniper routing-instances or Cisco VRFs.
- **Active health monitoring** — ICMP, TCP, HTTP, and DNS probes with hysteresis and MOS scoring on every probe kind.
- **Gateway groups** — failover, weighted load-balance, and MOS-weighted adaptive policies.
- **Policy routing** — match on 5-tuple + interface + DSCP + geo-IP. Steer to an instance, gateway, or group.
- **Blast-radius preview** — dry-run any config change to see which existing flows would be re-routed and whether management traffic would be stranded, before applying.
- **Per-flow visibility** — live pf state table joined to policy labels, with one-click force-migrate.
- **GitOps export/import** — `GET /api/v1/multiwan/config.yaml` returns the entire multi-WAN config; POST it back to apply.
- **Anomaly scoring** (optional) — SLA baseline deviation alerting when probes still pass but the latency profile shifted.

See the [multi-WAN setup guide]({{ '/multi-wan/' | relative_url }}) for FIB bootstrap, gateway monitoring, policy construction, and the pf rules emitted under `aifw-pbr`, `aifw-mwan-reply`, and `aifw-mwan-leak`.
```

- [ ] **Step 3: Add Reverse proxy & ACME section (rewriting the existing brief one)**

Find the existing `## Reverse proxy` section. Replace with:

```markdown
## Reverse proxy &amp; ACME

Built-in TrafficCop reverse proxy — no HAProxy/Nginx package install:

- **HTTP routers** with path and host matching
- **TCP and UDP routers** with SNI matching
- **Services** with multiple backends, health checks, and load-balancing strategies
- **Middleware chains** — auth, rate limit, header rewrites, redirect, IP allowlist
- **TLS termination** with per-router certificate selection
- **ACME / Let's Encrypt automation** — issue, renew, and push certs to the local TLS store, a filesystem location, or a webhook destination

See the [reverse proxy guide]({{ '/docs/reverse-proxy/' | relative_url }}) for setup, ACME providers, middleware reference, and example configs.
```

- [ ] **Step 4: Add DNS blocklists, Backup & migration, Time service, TLS inspection sections**

After the existing `## DNS` section, before `## DHCP`, add:

```markdown
## DNS blocklists

- Source URL configuration with periodic auto-refresh
- Per-list hit counters and last-fetch metadata
- Allowlist override that beats blocklist rules
- Per-blocklist enable/disable, with no resolver restart required
- Compatible with common public blocklists (StevenBlack, OISD, etc.)

See the [DNS guide]({{ '/docs/dns/' | relative_url }}) for sources, refresh cadence, and allowlist examples.
```

After the existing `## Config management` section, replace it with this expanded version:

```markdown
## Backup &amp; migration

- **JSON backup / restore** — entire config in one file, atomically replayable
- **S3 backup destination** — configurable bucket and prefix; rotation policy
- **OPNsense XML import** — recently rewritten end-to-end. Parse the XML, preview a diff of what'll change, apply atomically with rollback on failure
- **Versioned config history** — every change is snapshotted; diff and selective restore from the UI
- **Commit confirm** — every apply auto-reverts on timeout unless explicitly confirmed; default 300-second window

See the [backup &amp; migration guide]({{ '/docs/backup/' | relative_url }}) for the full migration workflow from OPNsense, S3 setup, and rollback procedures.
```

After the existing `## Monitoring` section, add:

```markdown
## Time service

- **NTP and PTP** via the rTIME companion service
- Stratum, drift, and peer health visible in the UI
- Per-peer enable/disable with key-authenticated peers supported
- Required for HA — both nodes must run synchronized time for CARP advertisement timing

## TLS inspection

- **JA3 / JA3S fingerprinting** of inbound and outbound flows
- **SNI filtering** — block by hostname before TLS handshake completes
- **Certificate validation** — chain trust, validity window, expected SANs
- **TLS version enforcement** — min/max version policy, cipher suite policy
```

- [ ] **Step 5: Update "Authentication" section**

Find:

```markdown
- **OAuth / SSO** — unique to AiFw among FreeBSD firewalls
```

Replace with:

```markdown
- **OAuth / SSO** — first-class auth method, not a plugin. Built-in providers for Google, GitHub, generic OIDC. See the [auth &amp; RBAC guide]({{ '/docs/auth/' | relative_url }}) for setup, the full 34-permission RBAC matrix, and TOTP / API-key flows.
```

- [ ] **Step 6: Update "Interfaces" section**

Replace with:

```markdown
## Interfaces

- **Web UI** — Next.js / React with static export (no Node.js on appliance)
- **REST API** — 300+ endpoints, Axum-based, WebSocket for live data. See the [API reference]({{ '/docs/api/' | relative_url }}).
- **CLI** — `aifw` with 17 subcommand groups. See the [CLI reference]({{ '/docs/cli/' | relative_url }}).
- **TUI** — interactive terminal UI for headless operation
```

(Substitute the verified count from Task 0 step 1 if different from `300+`.)

- [ ] **Step 7: Update "See also" section**

Replace the bottom `## See also` with:

```markdown
## See also

- [How AiFw compares to pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [Install guide →]({{ '/install/' | relative_url }})
- [Documentation hub →]({{ '/docs/' | relative_url }})
- [FAQ →]({{ '/faq/' | relative_url }})
- [GitHub repository →](https://github.com/ZerosAndOnesLLC/AiFw)
```

- [ ] **Step 8: Build, verify, bump, commit**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Bump `5.93.2` → `5.93.3`. Commit:

```bash
git add docs/features.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): features — add multi-WAN, reverse proxy/ACME, DNS blocklists, backup/migration, time, TLS sections"
```

---

## Task 4: Smaller refreshes (multi-wan, install, ha, plugins)

**Files:**
- Modify: `docs/multi-wan.md`
- Modify: `docs/install.md`
- Modify: `docs/ha.md`
- Modify: `docs/plugins.md`
- Modify: `Cargo.toml`, `aifw-ui/package.json`

- [ ] **Step 1: Refresh `multi-wan.md` — UI bootstrap path**

Find the front-matter and replace:

```yaml
---
layout: default
title: Multi-WAN with FIB isolation — AiFw
description: Set up Multi-WAN failover and load-balancing on AiFw with FreeBSD FIBs, gateway groups, policy routing, and blast-radius preview.
permalink: /multi-wan/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Multi-WAN", url: "/multi-wan/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Multi-WAN with FIB isolation on AiFw",
  "description": "Configure multi-WAN failover, weighted load-balance, and policy routing on AiFw using FreeBSD FIBs and pf.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09"
}
</script>
```

Replace the "Prerequisites" section (the `# /boot/loader.conf` snippet) with:

```markdown
## Prerequisites — UI bootstrap

The first time you create a Multi-WAN instance from the web UI, AiFw checks `net.fibs` and offers to bootstrap it for you. The bootstrap action:

1. Writes `net.fibs=16` to `/boot/loader.conf` (idempotent — won't duplicate the line).
2. Verifies the value loads on next boot.
3. Prompts for a single reboot.

Click **Enable Multi-WAN** in the UI, accept the reboot, and skip the rest of this section.

### Manual setup (advanced)

If you'd rather configure FIBs by hand:

```
# /boot/loader.conf
net.fibs=16
```

Reboot. Verify:

```
sysctl net.fibs
```
```

Add a "See also" footer at the bottom:

```markdown
## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [Firewall rules →]({{ '/docs/firewall/' | relative_url }})
```

- [ ] **Step 2: Refresh `install.md` — verify wizard step order**

In `docs/install.md`, find the "First-boot setup wizard" section. The current copy lists 7 steps. Verify they match the live wizard by reading `aifw-setup/src/main.rs` (or wherever the wizard's step list lives — likely `aifw-setup/src/wizard.rs` or `aifw-setup/src/lib.rs`):

```bash
ls /home/mack/dev/AiFw/aifw-setup/src/
grep -nE "Step|fn step_|prompt" /home/mack/dev/AiFw/aifw-setup/src/main.rs 2>/dev/null | head -30
```

If the wizard order differs from the doc, update the doc to match. If they match, leave the section as-is.

Add a new note under "First-boot setup wizard" mentioning the multi-WAN UI bootstrap (commit `c1f0208`):

```markdown
### Multi-WAN setup later

Multi-WAN can be enabled from the web UI at any time after install — no need to edit `/boot/loader.conf` by hand. See the [multi-WAN guide]({{ '/multi-wan/' | relative_url }}).
```

Add `date: 2026-05-09` and breadcrumb to the front-matter:

```yaml
breadcrumb:
  - { title: "Install", url: "/install/" }
date: 2026-05-09
```

- [ ] **Step 3: Light-refresh `ha.md`**

Add `date: 2026-05-09` and breadcrumb to front-matter:

```yaml
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "HA cluster", url: "/ha/" }
date: 2026-05-09
```

Add TechArticle JSON-LD after front-matter (same pattern as Task 4 step 1).

Append a "See also" section at the bottom:

```markdown
## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [Auth &amp; RBAC →]({{ '/docs/auth/' | relative_url }}) — RBAC perms required for cluster operations
```

- [ ] **Step 4: Light-refresh `plugins.md`**

Add `date: 2026-05-09` and breadcrumb to front-matter:

```yaml
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Plugins", url: "/plugins/" }
date: 2026-05-09
```

Verify the "12 hook points" claim against `aifw-plugins/src/hooks.rs` per Task 0 step 4. If different, update the count in the page intro and the table.

Add TechArticle JSON-LD and a "See also" footer:

```markdown
## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [API reference →]({{ '/docs/api/' | relative_url }}) — plugin endpoints under `/api/v1/plugins/*`
```

- [ ] **Step 5: Build, verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Open `/multi-wan/`, `/install/`, `/ha/`, `/plugins/` locally; verify breadcrumbs render and last-updated stamps appear at the bottom.

- [ ] **Step 6: Bump + commit**

`5.93.3` → `5.93.4`. Commit:

```bash
git add docs/multi-wan.md docs/install.md docs/ha.md docs/plugins.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): refresh multi-wan / install / ha / plugins — UI bootstrap, breadcrumbs, schema, see-also"
```

---

## Task 5: Doc pages — networking batch (firewall, nat, vpn, dns, dhcp, geoip)

**Files (each created):**
- `docs/docs/firewall.md`
- `docs/docs/nat.md`
- `docs/docs/vpn.md`
- `docs/docs/dns.md`
- `docs/docs/dhcp.md`
- `docs/docs/geoip.md`

Each page follows the **doc page pattern** below. Don't deviate without reason.

### Doc page pattern

```markdown
---
layout: default
title: <Topic> — AiFw <gerund>
description: <140-160 char meta description with primary keyword>
permalink: /docs/<slug>/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "<Topic>", url: "/docs/<slug>/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "<Page H1>",
  "description": "<Same as front-matter description>",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "<Networking | Security | Operations | Reference>"
}
</script>

<div class="content-page">
<article markdown="1">

# <Topic>

<Lede paragraph: 2-3 sentences, keyword-rich, plain English.>

## Quickstart

<UI path: "Navigate to **Web UI > X > Y**...">
<API examples: 1-2 worked curl/POST.>

## CLI

```bash
aifw <subcommand> ...
```

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/v1/<resource>` | List |
| POST   | `/api/v1/<resource>` | Create |
| ...    | ... | ... |

## Configuration

<Key fields, defaults, gotchas.>

## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [<Sibling 1> →]({{ '/docs/<slug>/' | relative_url }})
- [<Sibling 2> →]({{ '/docs/<slug>/' | relative_url }})
- Source: [`<repo path>`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/<repo path>)

</article>
</div>
```

---

### Task 5a: `docs/docs/firewall.md`

- [ ] **Step 1: Read source files for facts**

```bash
ls /home/mack/dev/AiFw/aifw-core/src/engine.rs
ls /home/mack/dev/AiFw/aifw-core/src/alias.rs
ls /home/mack/dev/AiFw/aifw-core/src/shaping.rs
```

Reference for endpoint table: `aifw-api/src/main.rs` lines mentioning `/rules`, `/aliases`.

- [ ] **Step 2: Write the file**

Create `docs/docs/firewall.md` using the doc page pattern. Front-matter:

```yaml
title: "Firewall rules — AiFw stateful pf rules"
description: "Build stateful firewall rules on AiFw with FreeBSD pf — scheduling, aliases, traffic shaping, and IPv4/IPv6 dual-stack matching."
permalink: /docs/firewall/
```

Sections to cover:
- **Lede** — what AiFw rules are (pf rules in dedicated anchors), how rules are stored (SQLite), what scheduling means.
- **Quickstart** — UI path: Rules tab → Add rule. API example: `POST /api/v1/rules` with action, direction, proto, src/dst, schedule. Drag-to-reorder via `PUT /api/v1/rules/reorder`.
- **CLI** — `aifw rules add`, `aifw rules list`, `aifw rules remove` with examples copied verbatim from README.
- **API endpoints** — table for `/rules`, `/rules/{id}`, `/rules/reorder`, `/aliases`, `/aliases/{id}`.
- **Aliases** — what they are, when to use, how the API maps.
- **Scheduling** — time-based activation, the cron-like syntax used.
- **Traffic shaping** — CoDel / HFSC / PRIQ queues, where to find the page in the UI.
- **Configuration knobs** — anchor name (`aifw`), default policy, log defaults.
- **See also** — `/docs/nat/`, `/docs/multi-wan/`, source link to `aifw-core/src/engine.rs`.

Page target: ~150 lines.

- [ ] **Step 3: Build & verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Open `http://localhost:4000/docs/firewall/`. Verify breadcrumb, content, last-updated.

---

### Task 5b: `docs/docs/nat.md`

- [ ] **Step 1: Read source files**

```bash
cat /home/mack/dev/AiFw/aifw-core/src/nat.rs | head -100
```

- [ ] **Step 2: Write the file** with this content brief

Front-matter:

```yaml
title: "NAT — AiFw SNAT, DNAT, NAT64, NAT46"
description: "Configure SNAT, DNAT/port-forwarding, masquerade, 1:1 NAT, NAT64, and NAT46 on AiFw — including NAT46, unique to AiFw."
permalink: /docs/nat/
```

Sections:
- Lede — six NAT types covered, including NAT46 (unique to AiFw).
- Quickstart — UI path, API examples for each type.
- CLI — `aifw nat add` examples.
- API endpoints — `/nat`, `/nat/{id}`.
- Per-type detail — small subsection per type with use case + minimal API body.
- See also — `/docs/firewall/`, source link.

Target: ~150 lines.

- [ ] **Step 3: Build, verify**

---

### Task 5c: `docs/docs/vpn.md`

- [ ] **Step 1: Read source**

```bash
cat /home/mack/dev/AiFw/aifw-core/src/vpn.rs | head -80
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "VPN — AiFw WireGuard and IPsec setup"
description: "Set up WireGuard tunnels with auto-keypair generation and per-peer config export, or IPsec ESP/AH tunnels in tunnel or transport mode on AiFw."
permalink: /docs/vpn/
```

Sections:
- Lede — WireGuard + IPsec. No OpenVPN (cross-link to /compare/).
- WireGuard quickstart — UI, API: `POST /api/v1/vpn/wg`, `POST /api/v1/vpn/wg/{id}/peers`, GET `/api/v1/vpn/wg/{id}/peers/{peer_id}/config` for the peer-config download.
- IPsec quickstart — UI, API: `POST /api/v1/vpn/ipsec` with mode/proto/algorithm.
- CLI — `aifw vpn wg-add`, `aifw vpn wg-peer-add`, `aifw vpn ipsec-add`.
- API endpoints — table for `/vpn/wg/*` and `/vpn/ipsec/*`.
- See also — `/docs/auth/` (for WG peer access controls), source link.

Target: ~180 lines.

- [ ] **Step 3: Build, verify**

---

### Task 5d: `docs/docs/dns.md`

- [ ] **Step 1: Read source**

```bash
ls /home/mack/dev/AiFw/aifw-api/src/dns_resolver.rs /home/mack/dev/AiFw/aifw-api/src/dns_blocklists.rs
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "DNS — AiFw rDNS resolver and blocklists"
description: "Configure the rDNS recursive resolver, host and domain overrides, DNS blocklists with auto-refresh, DNSSEC, and access control on AiFw."
permalink: /docs/dns/
```

Sections:
- Lede — rDNS companion service, what it covers (recursive resolver + overrides + blocklists).
- Quickstart — UI path. API for overrides + blocklists.
- DNS blocklists — source URLs, refresh cadence, allowlist override.
- DNSSEC — flag that toggles validation.
- API endpoints — `/api/v1/dns/*`.
- Recent change note — call out commit #231 (DNS forwarders fix) inline.
- See also — `/docs/dhcp/` (DDNS link), source link.

Target: ~140 lines.

- [ ] **Step 3: Build, verify**

---

### Task 5e: `docs/docs/dhcp.md`

- [ ] **Step 1: Read source / find rDHCP companion repo**

The DHCP server is the rDHCP companion. Endpoint inventory in `aifw-api/src/dhcp.rs`. Reference HA failover.

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "DHCP — AiFw DHCPv4 with HA failover"
description: "Configure rDHCP — multiple subnets, static reservations, HA failover with peer state sync, DDNS auto-updates, and per-subnet lease tuning."
permalink: /docs/dhcp/
```

Sections:
- Lede — rDHCP companion, multiple subnets, HA-aware.
- Quickstart — UI path (recently re-grouped by subnet, commit `0b36d37`). API examples.
- HA failover — what gets replicated, link to /ha/.
- DDNS — DHCP-to-DNS update flow.
- API endpoints — `/api/v1/dhcp/*`.
- See also — `/ha/`, `/docs/dns/`, source link.

Target: ~140 lines.

- [ ] **Step 3: Build, verify**

---

### Task 5f: `docs/docs/geoip.md`

- [ ] **Step 1: Read source**

```bash
cat /home/mack/dev/AiFw/aifw-core/src/geoip.rs | head -60
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "Geo-IP — AiFw country-based blocking"
description: "Country-based block and allow rules on AiFw using GeoLite2. Per-rule action override, IP lookup endpoint, ISO 3166 alpha-2 country codes."
permalink: /docs/geoip/
```

Sections:
- Lede — country-based block/allow.
- Quickstart — UI, API.
- IP lookup — `GET /api/v1/geoip/lookup/{ip}`.
- API endpoints — `/api/v1/geoip/*`.
- See also — `/docs/firewall/`, source link.

Target: ~100 lines (smaller scope).

- [ ] **Step 3: Build, verify**

---

### Task 5 commit

- [ ] **Bump and commit all networking pages together**

`5.93.4` → `5.93.5`.

```bash
cd /home/mack/dev/AiFw && git add docs/docs/firewall.md docs/docs/nat.md docs/docs/vpn.md docs/docs/dns.md docs/docs/dhcp.md docs/docs/geoip.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): networking quickstart pages — firewall, NAT, VPN, DNS, DHCP, geo-IP"
```

---

## Task 6: Doc pages — security and operations batch (ids, auth, reverse-proxy, backup)

### Task 6a: `docs/docs/ids.md`

- [ ] **Step 1: Read source**

```bash
ls /home/mack/dev/AiFw/aifw-ids/src/
ls /home/mack/dev/AiFw/aifw-ai/src/detectors/
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "IDS / IPS — AiFw Suricata, Sigma, and YARA"
description: "Run Suricata, Sigma, and YARA rules on AiFw — three modes (Disabled / IDS alert-only / IPS inline drop), ET Open auto-update, alert classification, suppression, and AI behavioural detectors."
permalink: /docs/ids/
```

Sections:
- Lede — three modes, three rule formats, AI detectors as opt-in.
- Quickstart — UI path, mode toggle.
- Rule formats — Suricata / Sigma / YARA. Note: no Snort.
- ET Open integration — auto-update cadence.
- AI threat detection — 5 detectors listed (port scan, DDoS, brute force, C2 beacon, DNS tunneling). Mark **opt-in / experimental**, mirror README's WIP framing exactly.
- Alert management — severity, ack, classification, analyst notes.
- Suppressions — by source IP / dest IP, per-rule.
- API endpoints — `/api/v1/ids/*` (config, reload, alerts, rulesets, rules, suppressions, stats).
- See also — `/features/`, source link.

Target: ~200 lines.

- [ ] **Step 3: Build, verify**

---

### Task 6b: `docs/docs/auth.md`

- [ ] **Step 1: Enumerate the 34 RBAC perms**

```bash
grep -rE "perm:|Permission::" /home/mack/dev/AiFw/aifw-api/src/auth/ /home/mack/dev/AiFw/aifw-common/src/ | head -60
```

Goal: a complete table of every permission with a short description.

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "Auth & RBAC — AiFw users, OAuth, TOTP, API keys"
description: "Configure local users, TOTP 2FA, OAuth/SSO providers (Google, GitHub, OIDC), API keys, and the 34-permission RBAC matrix on AiFw."
permalink: /docs/auth/
```

Sections:
- Lede — three auth methods (JWT, API key, OAuth), three built-in roles, custom roles.
- Local users — bcrypt, password policy.
- TOTP 2FA — enrollment, recovery codes, login flow.
- OAuth / SSO — Google, GitHub, generic OIDC; redirect URI config.
- API keys — creation, scoping by permissions, rotation.
- WebSocket auth — single-use ticket flow (`POST /auth/ws-ticket`).
- RBAC — three built-in roles, custom roles, full **34-permission table** with one-line descriptions per perm.
- API endpoints — `/auth/*`.
- See also — `/docs/api/`, source link.

Target: ~250 lines (this is the big one for security).

- [ ] **Step 3: Build, verify**

---

### Task 6c: `docs/docs/reverse-proxy.md`

- [ ] **Step 1: Read source**

```bash
cat /home/mack/dev/AiFw/aifw-api/src/reverse_proxy.rs | head -80
ls /home/mack/dev/AiFw/aifw-api/src/acme.rs
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "Reverse proxy & ACME — AiFw TrafficCop and Let's Encrypt"
description: "Run HTTP, TCP, and UDP reverse proxies on AiFw with TrafficCop. Configure routers, services, middlewares, TLS, and ACME / Let's Encrypt automation."
permalink: /docs/reverse-proxy/
```

Sections:
- Lede — TrafficCop is built-in, no HAProxy/Nginx pkg.
- Architecture — control plane (AiFw API) vs data plane (TrafficCop daemon).
- HTTP routers — path / host matching, TLS termination.
- TCP & UDP routers — SNI for TCP TLS.
- Services — backends, health checks, load-balancing.
- Middlewares — list with one-line description each (auth, rate-limit, header rewrites, redirect, IP allowlist).
- ACME — providers, push targets (TLS store / file / webhook), renewal cadence.
- API endpoints — `/api/v1/reverse-proxy/*`, `/api/v1/acme/*`.
- See also — `/features/`, source link.

Target: ~200 lines.

- [ ] **Step 3: Build, verify**

---

### Task 6d: `docs/docs/backup.md`

- [ ] **Step 1: Read source**

```bash
cat /home/mack/dev/AiFw/aifw-api/src/backup.rs | head -60
cat /home/mack/dev/AiFw/aifw-api/src/backup_s3.rs | head -60
ls /home/mack/dev/AiFw/aifw-api/src/opnsense/
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "Backup & migration — AiFw config backup, S3, OPNsense import"
description: "Back up AiFw config to JSON or S3. Import an OPNsense XML config with atomic rollback. Versioned config history and commit-confirm auto-revert."
permalink: /docs/backup/
```

Sections:
- Lede — three workflows: backup, OPNsense import, commit-confirm.
- JSON backup / restore — endpoint, format.
- S3 backup destination — config, rotation.
- **OPNsense import** (sub-anchor `#opnsense-import`) — recently rewritten (#230, #248–#252). Atomicity model: parse → preview diff → apply atomically → roll back on failure. UI walkthrough + API endpoint. Linked from homepage feature card.
- Versioned config history — diff and selective restore.
- Commit confirm — 300-second default timeout, how to confirm or cancel from UI / CLI.
- API endpoints — `/api/v1/backup/*`, `/api/v1/opnsense/import`.
- See also — `/compare/` (OPNsense migration row), source link.

Target: ~200 lines.

- [ ] **Step 3: Build, verify**

---

### Task 6 commit

- [ ] **Bump and commit security/ops pages together**

`5.93.5` → `5.93.6`.

```bash
git add docs/docs/ids.md docs/docs/auth.md docs/docs/reverse-proxy.md docs/docs/backup.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): security & ops pages — IDS/IPS, auth/RBAC, reverse proxy/ACME, backup/migration"
```

---

## Task 7: Doc pages — reference batch (api, cli)

### Task 7a: `docs/docs/api.md`

- [ ] **Step 1: Read source**

```bash
grep -E '\.route\("/api/v1' /home/mack/dev/AiFw/aifw-api/src/main.rs | sed 's/^.*route("\(\/api\/v1[^"]*\).*/\1/' | sort -u | head -80
```

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "REST API reference — AiFw"
description: "Complete REST API reference for AiFw — auth (JWT, API key, WebSocket ticket), 300+ endpoints grouped by subsystem (rules, NAT, VPN, IDS, multi-WAN, HA, DNS, DHCP, etc.)."
permalink: /docs/api/
```

Sections:
- Lede — Axum-based, base URL, 300+ endpoints.
- Authentication — three methods (JWT Bearer, ApiKey, WebSocket ticket); examples for each.
- Rate limiting — what's enforced (if anything; check `aifw-api/src/auth/`).
- Endpoint tables grouped by subsystem:
  - Auth (`/auth/*`)
  - Status & metrics (`/status`, `/metrics`, `/connections`, `/logs`)
  - Rules + Aliases (`/rules/*`, `/aliases/*`)
  - NAT (`/nat/*`)
  - VPN (`/vpn/*`)
  - IDS (`/ids/*`)
  - Multi-WAN (`/multiwan/*`)
  - HA (`/cluster/*`)
  - DNS (`/dns/*`, `/dns-blocklists/*` if separate)
  - DHCP (`/dhcp/*`)
  - Geo-IP (`/geoip/*`)
  - Reverse proxy + ACME (`/reverse-proxy/*`, `/acme/*`)
  - Plugins (`/plugins/*`)
  - Backup (`/backup/*`, `/opnsense/import`)
  - Auth admin (`/auth/users`, `/auth/api-keys`)
  - System (`/system/*`)
  - Updates (`/updates/*`)
- Error format — JSON error envelope shape, common HTTP statuses.
- Pagination — `?limit=&offset=` convention.
- See also — `/docs/cli/`, source link to `aifw-api/src/main.rs`.

Target: ~300 lines (this is the reference doc).

- [ ] **Step 3: Build, verify**

---

### Task 7b: `docs/docs/cli.md`

- [ ] **Step 1: Read source**

```bash
cat /home/mack/dev/AiFw/aifw-cli/src/commands.rs | head -200
```

Goal: enumerate every top-level subcommand group + a one-line description.

- [ ] **Step 2: Write file** — content brief

Front-matter:

```yaml
title: "CLI reference — aifw command line"
description: "Complete `aifw` CLI reference — rules, NAT, VPN, IDS, DHCP, DNS, multi-WAN, cluster, config, users, status, reload."
permalink: /docs/cli/
```

Sections:
- Lede — when to use the CLI vs. the UI.
- Subcommand groups — table with one-line description per group, e.g. `aifw rules`, `aifw nat`, `aifw vpn`, `aifw ids`, `aifw cluster`, etc.
- Per-group quickstart — for each group, 1-2 of the most common commands with example output.
- Output formats — `--json` flag where supported.
- Exit codes — convention (0 ok, non-zero with reason).
- See also — `/docs/api/`, source link to `aifw-cli/src/commands.rs`.

Target: ~250 lines.

- [ ] **Step 3: Build, verify**

---

### Task 7 commit

- [ ] **Bump and commit reference pages together**

`5.93.6` → `5.93.7`.

```bash
git add docs/docs/api.md docs/docs/cli.md Cargo.toml aifw-ui/package.json
git commit -m "docs(site): reference pages — REST API and aifw CLI"
```

---

## Task 8: `docs.md` hub rewrite + `faq.md`

**Files:**
- Rewrite: `docs/docs.md`
- Create: `docs/faq.md`
- Modify: `Cargo.toml`, `aifw-ui/package.json`

### Task 8a: `docs.md` hub rewrite

- [ ] **Step 1: Replace `docs/docs.md` content**

Replace the entire file with:

```markdown
---
layout: default
title: AiFw documentation hub
description: Documentation hub for AiFw — install guides, networking (firewall, NAT, VPN, multi-WAN, DNS, DHCP, geo-IP), security (IDS, AI threats, auth/RBAC, plugins), and operations (HA, backup, reverse proxy, API, CLI, FAQ).
permalink: /docs/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "CollectionPage",
  "name": "AiFw documentation hub",
  "description": "Documentation hub for the AiFw firewall.",
  "url": "https://aifw.zerosandones.us/docs/"
}
</script>

<div class="content-page">
<article markdown="1">

# Documentation

Quickstarts, reference, and ops guides for AiFw. Each page covers one subsystem.

<div class="docs-hub" markdown="0">

  <div class="docs-col">
    <h3>Get started</h3>
    <ul>
      <li><a href="{{ '/install/' | relative_url }}">Install</a> — ISO, USB image, hypervisors</li>
      <li><a href="{{ '/install/#first-boot-setup-wizard' | relative_url }}">First boot</a> — wizard walkthrough</li>
      <li><a href="{{ '/features/' | relative_url }}">Features overview</a></li>
      <li><a href="{{ '/compare/' | relative_url }}">Compare to pfSense / OPNsense</a></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Networking</h3>
    <ul>
      <li><a href="{{ '/docs/firewall/' | relative_url }}">Firewall rules</a></li>
      <li><a href="{{ '/docs/nat/' | relative_url }}">NAT</a></li>
      <li><a href="{{ '/multi-wan/' | relative_url }}">Multi-WAN</a></li>
      <li><a href="{{ '/docs/vpn/' | relative_url }}">VPN — WireGuard &amp; IPsec</a></li>
      <li><a href="{{ '/docs/dns/' | relative_url }}">DNS resolver &amp; blocklists</a></li>
      <li><a href="{{ '/docs/dhcp/' | relative_url }}">DHCP</a></li>
      <li><a href="{{ '/docs/geoip/' | relative_url }}">Geo-IP</a></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Security</h3>
    <ul>
      <li><a href="{{ '/docs/ids/' | relative_url }}">IDS / IPS</a></li>
      <li><a href="{{ '/docs/ids/#ai-threat-detection' | relative_url }}">AI threat detection</a> <span class="badge-beta">opt-in</span></li>
      <li><a href="{{ '/docs/auth/' | relative_url }}">Auth &amp; RBAC</a></li>
      <li><a href="{{ '/plugins/' | relative_url }}">Plugins</a> <span class="badge-beta">beta</span></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Operations</h3>
    <ul>
      <li><a href="{{ '/ha/' | relative_url }}">HA cluster</a></li>
      <li><a href="{{ '/docs/backup/' | relative_url }}">Backup &amp; migration</a></li>
      <li><a href="{{ '/docs/reverse-proxy/' | relative_url }}">Reverse proxy &amp; ACME</a></li>
      <li><a href="{{ '/docs/api/' | relative_url }}">API reference</a></li>
      <li><a href="{{ '/docs/cli/' | relative_url }}">CLI reference</a></li>
      <li><a href="{{ '/faq/' | relative_url }}">FAQ</a></li>
    </ul>
  </div>

</div>

## Contributing

AiFw is MIT-licensed. Pull requests welcome at the [GitHub repo](https://github.com/ZerosAndOnesLLC/AiFw). Issues and discussions are open too.

</article>
</div>
```

- [ ] **Step 2: Add `.docs-hub` styles**

Append to `docs/assets/style.css`:

```css
/* ─────────── Docs hub grid ─────────── */
.docs-hub {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 32px;
  margin: 32px 0 48px;
}
.docs-col h3 {
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-2);
  margin: 0 0 12px;
}
.docs-col ul { list-style: none; padding: 0; margin: 0; }
.docs-col li { padding: 6px 0; font-size: 14px; }
.docs-col a { color: var(--text-0); text-decoration: none; font-weight: 500; }
.docs-col a:hover { color: var(--accent); }
.docs-col li .badge-beta { margin-left: 6px; }
```

- [ ] **Step 3: Build, verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Open `/docs/`. Verify the 4-column grid renders, all links resolve.

### Task 8b: `faq.md`

- [ ] **Step 1: Create `docs/faq.md`**

```markdown
---
layout: default
title: FAQ — AiFw firewall
description: Frequently asked questions about AiFw — is it a fork? does it require AI? OPNsense migration? hardware requirements? production-ready? OpenVPN? help and support?
permalink: /faq/
date: 2026-05-09
breadcrumb:
  - { title: "FAQ", url: "/faq/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Is AiFw a fork of OPNsense or pfSense?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. AiFw is a ground-up rewrite in Rust. It runs on FreeBSD and uses pf for packet filtering, but shares no PHP or codebase with OPNsense or pfSense. The user-space services, web UI, REST API, and CLI are all original Rust and Next.js code."
      }
    },
    {
      "@type": "Question",
      "name": "Does AiFw require AI features to work?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. AiFw is a complete firewall, router, DHCP server, DNS resolver, IDS/IPS, reverse proxy, and NTP server without any AI features enabled. The five behavioural detectors in aifw-ai (port scan, DDoS, brute force, C2 beacon, DNS tunneling) are opt-in, experimental, and disabled by default."
      }
    },
    { "@type": "Question", "name": "Can I import my existing OPNsense config?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw ships an OPNsense XML importer that parses your config, previews a diff of what will change, and applies atomically with rollback on failure. The importer was rewritten end-to-end in 2026 (PRs #230 and #248–#252)." } },
    { "@type": "Question", "name": "Does AiFw support Multi-WAN failover and load balancing?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw ships an enterprise-grade multi-WAN system with FIB isolation per WAN, gateway groups (failover, weighted, MOS-weighted adaptive), policy routing on 5-tuple plus DSCP plus geo-IP, and blast-radius preview. See the multi-WAN guide." } },
    { "@type": "Question", "name": "What hardware do I need to run AiFw?", "acceptedAnswer": { "@type": "Answer", "text": "Minimum: 1 amd64 core, 1 GB RAM, 4 GB disk, one NIC. Recommended: 2+ cores with AES-NI, 4 GB+ RAM, 16 GB SSD, 2+ NICs. IDS workloads benefit from more RAM. arm64 is planned but not yet supported." } },
    { "@type": "Question", "name": "Is AiFw production-ready?", "acceptedAnswer": { "@type": "Answer", "text": "Core firewall, NAT, VPN, IDS, DHCP, DNS, multi-WAN, and HA are production-ready and stable. AI threat detection is opt-in / experimental, and the plugin system is in beta — check the relevant page on this site for the current status of each." } },
    { "@type": "Question", "name": "How do I migrate from pfSense to AiFw?", "acceptedAnswer": { "@type": "Answer", "text": "Direct pfSense XML import is not supported. The recommended path is to export your pfSense config to OPNsense first (community tooling exists), then use AiFw's OPNsense importer. Or rebuild config from scratch — the AiFw web UI is fast." } },
    { "@type": "Question", "name": "Does AiFw have a paid version or paid tier?", "acceptedAnswer": { "@type": "Answer", "text": "No. Every feature is MIT-licensed and free. There is no paid tier, no gated features, and no telemetry or cloud dependency." } },
    { "@type": "Question", "name": "Where can I get help?", "acceptedAnswer": { "@type": "Answer", "text": "GitHub Discussions and Issues at https://github.com/ZerosAndOnesLLC/AiFw. The repo also includes detailed docs in CLAUDE.md and the docs/ directory." } },
    { "@type": "Question", "name": "How does AiFw compare to OPNsense and pfSense?", "acceptedAnswer": { "@type": "Answer", "text": "AiFw wins on Sigma+YARA rules, AI threat detection, NAT46, OAuth/SSO, commit-confirm auto-rollback, modern React UI, multi-WAN with FIB isolation, OPNsense config import, and built-in reverse proxy with ACME. AiFw lags on OpenVPN, LDAP/RADIUS, captive portal, DDNS WAN client, and project age. See the full comparison page." } },
    { "@type": "Question", "name": "Does AiFw support OpenVPN?", "acceptedAnswer": { "@type": "Answer", "text": "Not currently. AiFw supports WireGuard and IPsec only. If OpenVPN is a hard requirement, stay on pfSense or OPNsense." } },
    { "@type": "Question", "name": "Can I run AiFw in a VM (Proxmox, ESXi, KVM, bhyve)?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve. AWS and DigitalOcean FreeBSD images are untested but should work." } },
    { "@type": "Question", "name": "Does AiFw work with WireGuard mobile clients?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw generates per-peer .conf files you can scan as a QR code from the WireGuard mobile app. Persistent keepalive can be set per peer. The handshake status is shown live in the web UI." } },
    { "@type": "Question", "name": "How does HA failover work?", "acceptedAnswer": { "@type": "Answer", "text": "AiFw runs an active-passive pair using CARP (virtual IP) and pfsync (state-table sync). TCP sessions survive a master reboot; WireGuard tunnels reconnect within ~5 seconds if peers have PersistentKeepalive set. Failover detection takes 1.5–3 seconds depending on the configured latency profile. See the HA cluster guide for details." } },
    { "@type": "Question", "name": "Is the source code auditable / where do I read it?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. The full source is at https://github.com/ZerosAndOnesLLC/AiFw under the MIT license. The codebase is Rust workspace crates plus a Next.js web UI. CLAUDE.md in the repo root has an architectural overview." } }
  ]
}
</script>

<div class="content-page">
<article markdown="1">

# Frequently asked questions

## Is AiFw a fork of OPNsense or pfSense?

No. AiFw is a ground-up rewrite in Rust. It runs on FreeBSD and uses pf for packet filtering, but shares no PHP or codebase with OPNsense or pfSense. The user-space services, web UI, REST API, and CLI are all original Rust and Next.js code.

## Does AiFw require AI features to work?

No. AiFw is a complete firewall, router, DHCP server, DNS resolver, IDS/IPS, reverse proxy, and NTP server without any AI features enabled. The five behavioural detectors in `aifw-ai` (port scan, DDoS, brute force, C2 beacon, DNS tunneling) are **opt-in, experimental, and disabled by default**. They will be developed further in future releases.

## Can I import my existing OPNsense config?

Yes. AiFw ships an OPNsense XML importer that parses your config, previews a diff of what'll change, and applies atomically with rollback on failure. The importer was rewritten end-to-end in 2026 (PRs #230 and #248–#252). See the [backup &amp; migration guide]({{ '/docs/backup/#opnsense-import' | relative_url }}).

## Does AiFw support Multi-WAN failover and load balancing?

Yes. AiFw ships an enterprise-grade multi-WAN system with **FIB isolation per WAN**, gateway groups (failover, weighted, MOS-weighted adaptive), policy routing on 5-tuple + DSCP + geo-IP, and **blast-radius preview** before apply. See the [multi-WAN guide]({{ '/multi-wan/' | relative_url }}).

## What hardware do I need to run AiFw?

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 amd64 core | 2+ cores, AES-NI |
| RAM | 1 GB | 4 GB+ (more for IDS) |
| Disk | 4 GB | 16 GB SSD |
| NIC | 1 | 2+ (WAN + LAN) |

arm64 (Raspberry Pi, Ampere) is planned but not yet supported. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve.

## Is AiFw production-ready?

Core firewall, NAT, VPN, IDS, DHCP, DNS, multi-WAN, and HA are production-ready and stable. **AI threat detection is opt-in / experimental**, and the **plugin system is in beta**. Check the relevant page on this site for the current status of each subsystem.

## How do I migrate from pfSense to AiFw?

Direct pfSense XML import is not supported. The recommended path is to export your pfSense config to OPNsense first (community tooling exists), then use AiFw's [OPNsense importer]({{ '/docs/backup/#opnsense-import' | relative_url }}). Alternatively, rebuild config from scratch — the AiFw web UI is fast.

## Does AiFw have a paid version or paid tier?

No. Every feature is MIT-licensed and free. There is no paid tier, no gated features, and no telemetry or cloud dependency.

## Where can I get help?

GitHub Discussions and Issues at [https://github.com/ZerosAndOnesLLC/AiFw](https://github.com/ZerosAndOnesLLC/AiFw). The repo also includes detailed docs in `CLAUDE.md` and the `docs/` directory.

## How does AiFw compare to OPNsense and pfSense?

**AiFw wins on:** Sigma + YARA rules, AI threat detection, NAT46, OAuth/SSO, commit-confirm auto-rollback, modern React UI, multi-WAN with FIB isolation, OPNsense config import, built-in reverse proxy + ACME.

**AiFw lags on:** OpenVPN, LDAP/RADIUS, captive portal, DDNS WAN client, project age.

See the [full comparison]({{ '/compare/' | relative_url }}).

## Does AiFw support OpenVPN?

Not currently. AiFw supports **WireGuard** and **IPsec** only. If OpenVPN is a hard requirement, stay on pfSense or OPNsense.

## Can I run AiFw in a VM?

Yes. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve. AWS and DigitalOcean FreeBSD images are untested but should work.

## Does AiFw work with WireGuard mobile clients?

Yes. AiFw generates per-peer `.conf` files you can scan as a QR code from the WireGuard mobile app. Persistent keepalive can be set per peer. Handshake status is shown live in the web UI.

## How does HA failover work?

AiFw runs an active-passive pair using **CARP** (virtual IP) and **pfsync** (state-table sync). TCP sessions survive a master reboot. WireGuard tunnels reconnect within ~5 seconds if peers have `PersistentKeepalive` set. Failover detection takes 1.5–3 seconds depending on the configured latency profile. See the [HA cluster guide]({{ '/ha/' | relative_url }}).

## Is the source code auditable / where do I read it?

Yes. The full source is at [github.com/ZerosAndOnesLLC/AiFw](https://github.com/ZerosAndOnesLLC/AiFw) under the MIT license. The codebase is Rust workspace crates plus a Next.js web UI. `CLAUDE.md` in the repo root has an architectural overview.

</article>
</div>
```

- [ ] **Step 2: Build, verify**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe 2>&1 | tail -10
```

Open `/faq/` locally; verify content + JSON-LD renders. Spot-check the JSON-LD by viewing page source — confirm `"@type": "FAQPage"` is present.

### Task 8 commit

- [ ] **Bump and commit**

`5.93.7` → `5.94.0` (minor — adds new top-level FAQ page).

```bash
git add docs/docs.md docs/faq.md docs/assets/style.css Cargo.toml aifw-ui/package.json
git commit -m "docs(site): docs hub rewrite + FAQ page with FAQPage schema"
```

---

## Task 9: SEO polish pass

**Files:**
- Modify: every page that lacks the SEO front-matter / schema (sweep)
- Modify: `Cargo.toml`, `aifw-ui/package.json`

- [ ] **Step 1: Verify every page has unique title + description**

Run:

```bash
cd /home/mack/dev/AiFw/docs && grep -L "^description:" *.md docs/*.md 2>/dev/null
grep -L "^title:" *.md docs/*.md 2>/dev/null
```

Expected: empty output (every page has both). If any page is missing, add a unique title (50-60 chars) and description (140-160 chars).

- [ ] **Step 2: Verify every page has `date:` for the last-updated stamp**

```bash
grep -L "^date:" *.md docs/*.md 2>/dev/null
```

Expected: empty. If any are missing, add `date: 2026-05-09`.

- [ ] **Step 3: Verify every page has Schema.org JSON-LD**

```bash
grep -L 'application/ld\+json' *.md docs/*.md 2>/dev/null | grep -v README
```

Expected: empty (homepage is HTML so it's already done in `index.html`; `_layouts/default.html` injects the Organization JSON-LD on every page).

If any markdown page lacks its page-specific JSON-LD (TechArticle, FAQPage, etc.), add it.

- [ ] **Step 4: Image alt audit**

```bash
grep -nE '<img [^>]*alt="(\| )?"' /home/mack/dev/AiFw/docs/index.html /home/mack/dev/AiFw/docs/*.md /home/mack/dev/AiFw/docs/docs/*.md 2>/dev/null
```

Expected: empty. If any image has empty alt text, fix it with a descriptive, keyword-aware string ("AiFw multi-WAN policy editor", not "screenshot").

- [ ] **Step 5: Sitemap regeneration test**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe
ls _site/sitemap.xml
grep -c '<url>' _site/sitemap.xml
```

Expected: sitemap.xml exists, with one `<url>` entry per published page (~22 pages = ~22 `<url>` entries).

If `jekyll-sitemap` did not generate a sitemap, the existing hand-maintained `site-map.xml` (note the dash) may be conflicting. Delete the hand-maintained file:

```bash
rm /home/mack/dev/AiFw/docs/site-map.xml
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe
ls _site/sitemap.xml
```

- [ ] **Step 6: robots.txt sanity check**

```bash
cat /home/mack/dev/AiFw/docs/robots.txt
```

Confirm it does NOT block `/superpowers/` or any of the new pages, and it does point to the new sitemap. Update if needed:

```
User-agent: *
Allow: /

Sitemap: https://aifw.zerosandones.us/sitemap.xml
```

- [ ] **Step 7: Bump + commit**

`5.94.0` → `5.94.1`.

```bash
git add docs/ Cargo.toml aifw-ui/package.json
git commit -m "docs(site): SEO polish — unique titles/descriptions, page schemas, alt audit, sitemap regen"
```

---

## Task 10: Final preview + link audit

**Files:** none modified unless issues found.

- [ ] **Step 1: Full local build**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll build --strict_front_matter --safe
```

Expected: clean build.

- [ ] **Step 2: Run htmlproofer**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec htmlproofer ./_site --disable-external --check-html --check-img-http --check-internal-hash 2>&1 | tail -40
```

Expected: zero broken internal links, zero missing alt attributes.

If `htmlproofer` is not in the bundle, add it:

```bash
echo 'gem "html-proofer"' >> /home/mack/dev/AiFw/docs/Gemfile
cd /home/mack/dev/AiFw/docs && bundle install --quiet
```

Then re-run.

- [ ] **Step 3: Manual link click-through**

```bash
cd /home/mack/dev/AiFw/docs && bundle exec jekyll serve --port 4000
```

Open `http://localhost:4000/` in a browser. Click every Docs ▾ menu item. Click every "See also" link on every page. Click every link in the Compare matrix. Click every feature card link on the homepage. No 404s.

- [ ] **Step 4: Schema validation (manual, post-deploy)**

Document this for the maintainer in the PR body — not part of the commit:

> After publish, paste these URLs into [Google's Rich Results Test](https://search.google.com/test/rich-results):
> - `/` (SoftwareApplication)
> - `/install/` (HowTo)
> - `/compare/` (ItemList)
> - `/faq/` (FAQPage — biggest win)
> - One TechArticle page (`/docs/firewall/`)
>
> Fix any flagged issues in a follow-up PR.

- [ ] **Step 5: Bump + commit (only if Step 2 found and fixed issues)**

If htmlproofer found and you fixed any issues, `5.94.1` → `5.94.2`:

```bash
git add docs/ Cargo.toml aifw-ui/package.json
git commit -m "docs(site): final link audit fixes"
```

If no issues found, no commit — Task 9's commit is the final one.

- [ ] **Step 6: Open PR**

Branch + PR using the standard repo conventions in `CLAUDE.md`:

```bash
git checkout -b docs/gh-pages-refresh
git push -u origin docs/gh-pages-refresh
gh pr create --title "docs(site): gh-pages full content refresh + SEO" --body "$(cat <<'EOF'
## Summary
- Bring https://aifw.zerosandones.us/ in line with shipped features (multi-WAN, OPNsense importer, reverse proxy + ACME, DNS blocklists, S3 backup)
- Restructure docs into a real hub with grouped Docs ▾ dropdown nav
- 12 new doc pages (firewall, NAT, VPN, IDS, DNS, DHCP, geo-IP, auth, reverse-proxy, backup, API, CLI)
- New FAQ page with FAQPage schema for rich snippets
- Heavy SEO pass: per-page Schema.org JSON-LD, breadcrumbs, last-updated stamps, sitemap plugin, alt audit
- Spec: `docs/superpowers/specs/2026-05-09-gh-pages-refresh-design.md`
- Plan: `docs/superpowers/plans/2026-05-09-gh-pages-refresh.md`

## Test plan
- [ ] `cd docs && bundle exec jekyll build --strict_front_matter --safe` clean
- [ ] `bundle exec htmlproofer ./_site --disable-external` clean
- [ ] Manual click-through of every Docs ▾ menu item
- [ ] Spot-check Rich Results Test on `/`, `/faq/`, `/install/`, `/compare/`, `/docs/firewall/` after deploy
EOF
)"
```

---

## Self-review notes

- Every spec section maps to at least one task: nav (T1), homepage (T2), compare/features (T3a/T3b), refreshes (T4), 12 new pages (T5a-f, T6a-d, T7a-b), hub + FAQ (T8), SEO polish (T9), validation (T10).
- No "TBD"/"TODO" placeholders. Every step states what to do and shows the relevant code or content.
- Type/path consistency: all permalinks under `/docs/<slug>/` for new pages. Cross-references in "See also" sections all match the actual permalinks defined in front-matter.
- Per-commit version bump rule respected. Each task has an explicit `sed` or note for the bump and the matching commit message.
- The plan trusts the implementer to write the prose for new doc pages from the source files referenced — full prose isn't pre-written here because that would balloon the plan to ~6000 lines and the implementer doing the writing has the source-of-truth grep handy. Each new page has explicit front-matter, target line count, section list, and source file pointers — enough to execute without ambiguity.
