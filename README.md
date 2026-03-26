# AiFw

AI-powered firewall for FreeBSD built in Rust on top of pf. All features free and open source.

## Architecture

```
AiFw/
├── aifw-common/     # Shared types (rules, protocols, addresses, errors)
├── aifw-pf/         # pf integration layer (trait + mock/ioctl backends)
├── aifw-core/       # Rule engine (CRUD, validation, SQLite persistence)
├── aifw-daemon/     # Main daemon (loads rules, manages pf anchors)
└── aifw-cli/        # CLI tool (aifw init/rules/status/reload)
```

### Key Design

- **pf backend**: All packet filtering through FreeBSD's pf via `/dev/pf` ioctl
- **Trait-based abstraction**: `PfBackend` trait with real (FreeBSD) and mock (Linux) implementations
- **Anchor isolation**: AiFw rules live in dedicated pf anchors, never touching system pf config
- **Async runtime**: Tokio throughout
- **Storage**: SQLite via sqlx

## Development

Development happens in WSL/Linux. The mock pf backend allows full compilation and testing without FreeBSD.

```bash
cargo build          # Build all crates
cargo test           # Run all tests (uses mock pf backend)
```

## CLI Usage

```bash
# Initialize database
aifw init

# Add rules
aifw rules add --action pass --direction in --proto tcp --dst-port 443 --label "allow-https"
aifw rules add --action block --direction in --proto tcp --dst-port 22 --src 10.0.0.0/8

# List rules
aifw rules list
aifw rules list --json

# Remove a rule
aifw rules remove <uuid>

# Show status
aifw status

# Reload rules into pf
aifw reload
```

## Daemon

```bash
aifw-daemon --db /var/db/aifw/aifw.db --interface em0
```

## Target Environment

- **OS**: FreeBSD 14+
- **Requires**: `/dev/pf` accessible (root or dedicated group)
- **pf**: Must be enabled in `/etc/rc.conf` (`pf_enable="YES"`)

## License

Apache-2.0
