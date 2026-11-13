---
layout: default
title: "CLI reference — aifw command line"
description: "The aifw CLI: log in to one or many AiFw firewalls, manage rules, NAT, VPN, IDS, DNS, DHCP, certificates, HA and updates from a terminal or a script, with stable JSON output and exit codes."
permalink: /docs/cli/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "CLI", url: "/docs/cli/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "CLI reference — aifw command line",
  "description": "The aifw CLI: log in to one or many AiFw firewalls, manage rules, NAT, VPN, IDS, DNS, DHCP, certificates, HA and updates from a terminal or a script, with stable JSON output and exit codes.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-11-13",
  "articleSection": "Reference"
}
</script>

<div class="content-page">
<article markdown="1">

# CLI reference

`aifw` is a client for the AiFw REST API. Everything it changes goes through
the same validation, audit log, config versioning and HA replication as the
web UI. It runs:

- **on the appliance**, as root, with no setup at all;
- **from any machine** (a laptop, a jump host, CI) after `aifw login`;
- **against several firewalls at once** for read-only commands.

A small `aifw local` group keeps working when the API itself is down.

## Getting started

### On the appliance

As root, just run commands:

```sh
aifw status
aifw rules list
```

The first time it runs as root, `aifw` creates an admin API key for itself in
`/usr/local/etc/aifw/cli.key` (mode 0600) and talks to `https://127.0.0.1:8080`,
pinned to the API's own certificate. `aifw local cli-key --rotate` replaces it.

### From another machine

```sh
aifw login https://fw1.example.com:8080 --context fw1
```

`login` shows the SHA-256 fingerprint of the certificate the firewall presents
and asks before trusting it (compare it with **Settings → TLS** in the UI), then
asks for your username, password and TOTP code. Pass `--pin <fingerprint>` to
skip the question, `--password-stdin` for scripts, or log in with an API key:

```sh
aifw api-keys create --name laptop --expires-days 90      # on a box you're logged in to
printf '%s' "$KEY" | aifw login https://fw1:8080 --context fw1 --api-key-stdin
```

Sessions refresh themselves; `aifw logout` revokes the session on the firewall.
`aifw whoami` shows who you are, the role and where the credential came from.

### Contexts

Each saved firewall is a *context*. Contexts live in `~/.config/aifw/config.toml`
(URL, certificate pin, default output) and their secrets in
`~/.config/aifw/credentials.toml` (mode 0600). `$AIFW_CONFIG_DIR` moves both.

```sh
aifw context list
aifw context use fw2
aifw --context fw1 rules list
aifw context set-pin fw1               # after the firewall's certificate changed
aifw context rename fw1 edge-1
aifw context rm old-box
```

### Credentials for scripts

| Source | How |
|---|---|
| A context | `aifw --context fw1 …` |
| API key in the environment | `AIFW_TOKEN=aifw_… AIFW_API_URL=https://fw1:8080 aifw … --pin <sha256>` |
| Ad hoc flags | `--url`, `--api-key`, `--pin` |

Precedence: flags and environment, then the selected context, then the on-box
default. Keys can be narrowed to a role and given an expiry
(`aifw api-keys create --role builtin-viewer --expires-days 30`).

## Global flags

| Flag | Meaning |
|---|---|
| `--context NAME[,NAME…]` | Context to use (`AIFW_CONTEXT`); several = fan-out |
| `--all-contexts` | Fan a read-only command out to every saved context |
| `--parallel N` | Fan-out concurrency (default 8) |
| `--url URL` | API base URL (`AIFW_API_URL`) |
| `--api-key KEY` | API key or bearer token (`AIFW_TOKEN`) |
| `--pin SHA256` | Pin the API certificate |
| `-o, --output table\|wide\|json\|yaml` | Output format |
| `--no-input` | Never prompt; fail when input would be needed |
| `--request-timeout SECS` | Per-request timeout |
| `--db PATH` | Database path, used only by `aifw local` |

## Output

Tables by default; `-o wide` adds columns. `-o json` and `-o yaml` print the
API's own response unchanged, so scripts get a stable shape. The old per-command
`--json` flags still work. Errors go to stderr; with `-o json` they are JSON too:

```json
{"error":"not authenticated: …","kind":"unauthenticated","exit_code":3}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Other error (including a declined confirmation, or a check that failed) |
| 2 | Usage error |
| 3 | Not authenticated (HTTP 401) |
| 4 | Permission denied (HTTP 403) |
| 5 | Not found (HTTP 404) |
| 6 | Rejected by validation (HTTP 400/422) |
| 7 | API unreachable, or TLS/certificate-pin failure |
| 8 | Fan-out: some contexts failed |
| 9 | Commit-confirm: nothing to confirm (the change rolled back) |

Commands that delete or replace things ask first. `-y/--yes` answers yes;
with no terminal (cron) an unanswered prompt means **no**.

## Staged changes and commit-confirm

Like the UI, filter/NAT/alias/VLAN changes are **staged** until applied:

```sh
aifw rules add --action block --src 203.0.113.0/24 --label bad-net
aifw pending                 # Unapplied changes: firewall (run `aifw apply`)
aifw apply                   # load into pf
aifw rules add … --apply     # or apply right away
```

For risky changes on a remote box, arm a rollback window **first**:

```sh
aifw confirm arm --timeout 5m --description "tighten WAN rules"
aifw rules edit 3f2a… --action block --apply
aifw confirm accept          # keep it; if you lost access, it reverts by itself
```

`aifw pending --watch` streams pending-state changes. `aifw reload` = apply plus
re-applying traffic-shaping queues.

## Several firewalls at once

Read-only commands accept several contexts:

```sh
aifw --context fw1,fw2 status
aifw --all-contexts cluster verify -o json
```

Tables print one section per firewall; JSON is
`[{"context":…,"exit_code":…,"result":…,"error":…}]`. The exit code is 0 when all
succeed, 8 when some fail. Commands that change things refuse to fan out.

## Command reference

`aifw <group> --help` lists every subcommand and flag. Most collections have
`list` (`ls`), `show`, `add`, `edit` (only the flags you pass change), `enable`,
`disable` and `rm`. Where an object has many fields, `add -f file.json` (or YAML,
or `-f -` for stdin) takes it in the API's shape — `list -o json` shows examples.

### Firewall

| Command | |
|---|---|
| `aifw rules list\|show\|add\|edit\|enable\|disable\|rm\|reorder\|system\|block-logging` | Filter rules |
| `aifw nat list\|show\|add\|edit\|enable\|disable\|rm\|reorder\|pf-output\|embed` | NAT (snat, dnat, masquerade, binat, nat64, nat46, nonat) |
| `aifw aliases …` | Address/port tables, used in rules as `<name>`; `edit --add/--del` entries |
| `aifw schedules …` | Time-of-day windows for rules |
| `aifw geoip list\|add\|edit\|rm\|lookup\|database\|refresh\|import` | Country rules and the GeoLite2 database |
| `aifw queue …` | Traffic-shaping queues |
| `aifw ratelimit …` | Connection rate limits (local only — no API yet) |

```sh
aifw rules add --action pass --proto tcp --dst 10.0.0.5 --dst-port 443 --interface em0 --label web
aifw nat add --type dnat --interface em0 --dst-port 80 --redirect 10.0.0.5 --redirect-port 8080
aifw aliases add --name admins --type network --entries 10.1.0.0/24,10.2.0.0/24
```

### Network and services

| Command | |
|---|---|
| `aifw interfaces [list\|detail\|stats\|role\|configure]` | Interfaces, roles, live addressing |
| `aifw vlans …` | VLAN interfaces |
| `aifw routes list\|add\|edit\|rm\|system` | Static routes |
| `aifw multiwan instances\|gateways\|groups\|policies\|leaks\|flows\|apply\|export\|import\|probe` | Multi-WAN |
| `aifw dns list\|set\|status\|apply\|start\|stop\|restart\|config\|hosts\|add-host\|domains\|acls\|logs\|stats\|probe` | Upstreams and the resolver |
| `aifw dns blocklists …`, `aifw dns whitelist`, `aifw dns customblocks` | DNS blocking |
| `aifw dhcp status\|subnets\|subnet-add\|subnet-edit\|reservations\|leases\|release\|apply\|logs` | DHCP server |
| `aifw time status\|config\|sources\|add-source\|apply\|logs` | NTP/PTP |
| `aifw reverse-proxy status\|apply\|validate\|logs\|<collection> …` | TrafficCop routers, services, middlewares, TLS |

### VPN

```sh
aifw vpn wg add --name road --address 10.8.0.1/24
aifw vpn wg peers add <tunnel> --name laptop --generate-key
aifw vpn wg peers config <tunnel> <peer> -O laptop.conf      # 0600
printf '%s' "$PSK" | aifw vpn ipsec add --name branch --remote 198.51.100.7 \
    --local-ts 10.0.0.0/24 --remote-ts 10.1.0.0/24 --psk-stdin
aifw vpn ipsec status
```

### Security

| Command | |
|---|---|
| `aifw ids config\|alerts\|stats\|reload\|rulesets\|rules\|suppressions\|retention\|purge-alerts` | Intrusion detection |
| `aifw ai analyze\|audit` | AI classification of alerts |
| `aifw plugins list\|show\|enable\|disable\|set\|reset\|status\|logs\|run` | Plugins (threat feeds, notifier) |

### Certificates

| Command | |
|---|---|
| `aifw acme account\|certs\|dns-providers\|test-provider\|targets` | Let's Encrypt |
| `aifw ddns records\|update\|config` | Dynamic DNS |
| `aifw ca show\|init\|pem\|crl\|certs issue\|pem\|key\|revoke` | Internal CA; `issue --out-dir` writes the cert and a 0600 key |

### Users and access

| Command | |
|---|---|
| `aifw users list\|show\|add\|set-role\|passwd\|enable\|disable\|rm` | Accounts (id or username) |
| `aifw roles list\|show\|permissions\|add\|edit\|rm` | Custom roles |
| `aifw api-keys list\|create\|revoke` | API keys; `create` prints the secret alone on stdout |
| `aifw totp setup\|verify\|disable` | Your 2FA (needs a login session) |
| `aifw audit` | Account audit trail |

### Configuration and backup

| Command | |
|---|---|
| `aifw config show\|history\|save\|diff\|check\|retention` | Versions |
| `aifw config export [--secrets passphrase] [-O file]` | Export (secrets redacted or passphrase-wrapped) |
| `aifw config import FILE [--preview]` | Import an export (applies it; asks first) |
| `aifw config import-opnsense FILE [--preview] [--map lan=em1]` | Migrate from OPNsense |
| `aifw config rollback VERSION` | Restore and apply a version |
| `aifw backup s3 config\|test\|list\|restore`, `aifw notify smtp config\|test` | Off-box backups, email |

### Appliance

| Command | |
|---|---|
| `aifw status`, `aifw top`, `aifw about`, `aifw metrics` | Health and counters |
| `aifw connections`, `aifw blocked`, `aifw logs` | State table, blocked traffic, change log |
| `aifw system info\|general\|banner\|ssh\|console\|timezones` | System settings |
| `aifw settings get\|set SECTION`, `aifw settings auth\|oauth-providers\|oauth-url\|ai-models\|ai-test` | Settings |
| `aifw syslog …`, `aifw logrotate …` | Remote syslog, log rotation |
| `aifw cluster status\|carp\|pfsync\|nodes\|health\|promote\|demote\|maintenance\|sync\|verify` | HA; `verify --json` is what `scripts/ha-verify.sh` reads |
| `aifw update check\|install [--from tarball]\|rollback\|restart\|reboot\|os-check\|os-install\|os-upgrade [--wait]\|status\|history\|prerelease` | Updates |
| `aifw reboot`, `aifw shutdown` | Power |

Service log tails (`dhcp logs`, `dns logs`, `time logs`, `reverse-proxy logs`)
take `-F/--follow`.

## When the API is down: `aifw local`

These run as root on the appliance and use the database and pf directly:

| Command | |
|---|---|
| `aifw local status` | pf, anchor hooks and DNS-backend drift, read from the box |
| `aifw local reload` (or `aifw reload --local`) | Load rules, NAT, queues and rate limits into pf |
| `aifw local reconcile` (also `aifw reconcile`) | Restore missing anchor hooks, fix rc.conf DNS backend flags |
| `aifw local update check\|install\|rollback\|restart\|reboot\|os-*` | The updater, e.g. to roll back a release that broke the API |
| `aifw local config-export --secrets plain` | Export with secrets in the clear (never served by the API) |
| `aifw local init`, `aifw local cli-key [--rotate]` | Create the database; mint the on-box CLI key |

When a normal command can't reach the API on the appliance, its error points at
the matching `aifw local` command.

## Shell completion and man page

```sh
aifw completions bash > /usr/local/share/bash-completion/completions/aifw
aifw completions zsh  > /usr/local/share/zsh/site-functions/_aifw
aifw completions fish > ~/.config/fish/completions/aifw.fish
```

The ISO installs the bash and zsh completions and `man aifw`.

## See also

- [REST API reference &rarr;]({{ '/docs/api/' | relative_url }})
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }})
- [Backup &amp; migration &rarr;]({{ '/docs/backup/' | relative_url }})
- Source: [`aifw-cli/src/commands/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-cli/src/commands)
- Source: [`aifw-client/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-client)

</article>
</div>
