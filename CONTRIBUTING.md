# Contributing to AiFw

Thanks for your interest in contributing to AiFw! This guide covers how to get started.

## Getting Started

### Prerequisites

- Rust (latest stable via [rustup](https://rustup.rs))
- Node.js 24+ and npm (for the web UI)
- FreeBSD 15 (for production testing) or Linux/WSL (for development with mock pf backend)

### Building

```bash
# Rust crates (all 12)
cargo build
cargo check  # quick type check
cargo test   # run test suite

# Web UI
cd aifw-ui
npm ci
npm run build
```

### Development

AiFw uses a mock pf backend on Linux/WSL so you can develop without FreeBSD:

```bash
cargo check          # type-checks all crates
cargo test           # runs all 273+ tests
```

The API server can be started locally for UI development:

```bash
cargo run --bin aifw-api -- --no-tls --db /tmp/aifw-dev.db
```

## How to Contribute

### Reporting Bugs

Open an issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- AiFw version
- FreeBSD version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

### Suggesting Features

Open an issue using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run `cargo check` (zero warnings required)
5. Run `cargo test`
6. If you changed the UI: `cd aifw-ui && npm run build`
7. Submit a pull request

### Pull Request Guidelines

- Keep PRs focused on a single change
- Include a clear description of what and why
- Update the README if your change affects user-facing behavior
- All CI checks must pass

## Code Standards

- **Rust**: `cargo check` must pass with zero warnings. No `#[allow]` to suppress real issues. Remove unused code rather than commenting it out.
- **UI**: ESLint must pass. No `eslint-disable` to hide real issues.
- **No paid crates**: All dependencies must be free/open-source.
- **Tests**: Add tests for new functionality. Don't break existing tests.

## Project Structure

```
aifw-common/     Shared types (rules, NAT, VPN, geo-IP, HA)
aifw-pf/         pf backend (FreeBSD ioctl + Linux mock)
aifw-core/       Engines: rules, NAT, VPN, TLS, geo-IP, audit, DB
aifw-conntrack/  Connection tracking
aifw-plugins/    Plugin framework
aifw-ai/         ML threat detection
aifw-metrics/    RRD ring buffer metrics
aifw-api/        Axum REST API (JWT auth, serves static UI)
aifw-tui/        Terminal UI
aifw-daemon/     Main firewall daemon
aifw-cli/        CLI tool
aifw-setup/      Interactive setup wizard
aifw-ui/         Next.js web UI (static export)
freebsd/         ISO/IMG build scripts and overlay files
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
