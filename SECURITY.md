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
