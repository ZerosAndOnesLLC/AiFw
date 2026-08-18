# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| Latest  | :white_check_mark: |
| < Latest | :x:               |

We only provide security fixes for the latest release. Please upgrade to receive patches.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report security issues by emailing:

**support@zerosandones.us**

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment (if known)

## Response Timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Depends on severity, targeting 30 days for critical issues

## Disclosure Policy

We follow coordinated disclosure. We will:

1. Confirm the vulnerability and determine affected versions
2. Develop and test a fix
3. Release a patched version
4. Credit the reporter (unless anonymity is requested)

We ask that you give us reasonable time to address the issue before public disclosure.

## Scope

This policy covers the AiFw firewall software, including:

- `aifw-api` (REST API server)
- `aifw-daemon` (firewall daemon)
- `aifw-core` (rule and NAT engines)
- `aifw-pf` (pf backend)
- `aifw-ui` (web interface)
- `aifw-setup` (setup wizard)
- FreeBSD ISO/IMG build artifacts

## Secrets in the repository

Nothing in this repository is a live credential. Verified 2026-08-17 (#455) against every tracked file and the full history (`git log --all -S` for private-key headers and AWS / GitHub / Slack / Google token prefixes; every file ever added, filtered for key/env/credential names):

- **Intentionally checked in:** `freebsd/overlay/usr/local/etc/aifw/update-signing.pub` — the minisign *public* key the in-app updater verifies release tarballs with. Its private half lives outside the repo.
- **Fixtures only:** the strings `-----BEGIN PRIVATE KEY-----\nabc\n…` in `aifw-common`/`aifw-core` IPsec tests, `TestPass123`-style passwords in API tests, and `AKIA...` / `CHANGE-ME` placeholders in docs and the setup seed template. None are usable.
- **Ignored, never tracked:** `.env`, `*.pem`, `*.key`, key material and any local `status.md` (see `.gitignore`).

Runtime secrets live outside the tree: `/var/db/aifw/secrets.key` (AES-256-GCM master key for values in the database), `/var/db/aifw/jwt.key`, and the appliance TLS key under `/usr/local/etc/aifw/tls/`. If you find anything that looks like a real credential in the repo, report it through the channel above.
