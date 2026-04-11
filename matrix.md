# Feature Comparison: AiFw vs OPNsense vs pfSense

| Feature | AiFw | OPNsense | pfSense |
|---------|:----:|:--------:|:-------:|
| **Firewall & Filtering** | | | |
| Stateful packet filtering | Yes | Yes | Yes |
| Rule scheduling | Yes | Yes | Yes |
| Aliases (IP/port groups) | Yes | Yes | Yes |
| IPv6 support | Yes | Yes | Yes |
| VLAN support | Yes | Yes | Yes |
| Static routing | Yes | Yes | Yes |
| Multi-WAN / failover / LB | Planned | Yes | Yes |
| Captive portal | No | Yes | Yes |
| **NAT** | | | |
| SNAT (outbound NAT) | Yes | Yes | Yes |
| DNAT / port forwarding | Yes | Yes | Yes |
| Masquerade | Yes | Yes | Yes |
| 1:1 NAT (binat) | Yes | Yes | Yes |
| NAT64 | Yes | Plugin (Tayga) | Yes |
| NAT46 | Yes | No | No |
| **VPN** | | | |
| WireGuard | Yes | Yes | Yes |
| IPsec | Yes | Yes | Yes |
| OpenVPN | No | Yes | Yes |
| **IDS/IPS** | | | |
| Suricata rules | Yes | Yes | Yes (pkg) |
| Snort rules | No | No | Yes (pkg) |
| Sigma rules | Yes | No | No |
| YARA rules | Yes | No | No |
| AI/ML threat detection | Yes | No | No |
| **DNS** | | | |
| DNS resolver | Yes (rDNS) | Yes (Unbound) | Yes (Unbound) |
| Host overrides | Yes | Yes | Yes |
| Domain overrides | Yes | Yes | Yes |
| DNSSEC | Yes | Yes | Yes |
| Dynamic DNS client (WAN IP) | No | Yes (plugin) | Yes |
| **DHCP** | | | |
| DHCPv4 server | Yes (rDHCP) | Yes (Kea/ISC) | Yes (Kea/ISC) |
| Subnet pools | Yes | Yes | Yes |
| Static reservations | Yes | Yes | Yes |
| HA failover | Yes | Yes | Yes |
| DDNS (DHCP→DNS) | Yes | Yes | Yes |
| **Geo-IP Blocking** | Yes | Yes | Yes (pfBlockerNG) |
| **Traffic Shaping** | | | |
| CoDel | Yes | Yes | Yes |
| HFSC | Yes | Yes | Yes |
| PRIQ | Yes | Yes | Yes |
| CBQ | No | Yes | Yes |
| **High Availability** | | | |
| CARP (virtual IPs) | Yes | Yes | Yes |
| pfsync (state sync) | Yes | Yes | Yes |
| Config sync | Yes | Yes | Yes |
| **Reverse Proxy** | | | |
| Built-in proxy | Yes (TrafficCop) | No | No |
| HAProxy | No | Yes (plugin) | Yes (pkg) |
| Nginx | No | Yes (plugin) | No |
| **Time Sync (NTP)** | Yes (rTIME) | Yes (ntpd) | Yes (ntpd) |
| **Certificate Authority** | Yes | Yes | Yes |
| **Authentication** | | | |
| Local users | Yes | Yes | Yes |
| TOTP 2FA | Yes | Yes | Partial (FreeRADIUS) |
| LDAP | No | Yes | Yes |
| RADIUS | No | Yes | Yes |
| OAuth / SSO | Yes | No | No |
| API keys | Yes | Yes | Partial (community) |
| **RBAC (granular perms)** | Yes (34 perms) | Yes (ACL) | Partial (user/group) |
| **Plugin System** | | | |
| Package/plugin support | Yes | Yes | Yes |
| WASM plugins | Yes | No | No |
| **Architecture** | | | |
| Web UI technology | React/Next.js | PHP/Phalcon | PHP |
| REST API | Yes (Axum/Rust) | Yes | Partial (community) |
| CLI tool | Yes | Partial | Partial |
| TUI (terminal UI) | Yes | No | No |
| WebSocket live dashboard | Yes | No | No |
| **Config Management** | | | |
| Backup / restore | Yes | Yes | Yes |
| Config versioning + diff | Yes | Yes | Yes |
| Commit confirm (auto-rollback) | Yes | No | No |
| OPNsense config import | Yes | N/A | N/A |
| **Unique to AiFw** | | | |
| AI/ML threat detection (5 detectors) | Yes | No | No |
| Sigma + YARA IDS rules | Yes | No | No |
| NAT46 | Yes | No | No |
| WASM plugin system | Yes | No | No |
| WebSocket real-time metrics | Yes | No | No |
| OAuth/SSO authentication | Yes | No | No |
| Commit confirm with auto-rollback | Yes | No | No |
| Modern React UI (static export) | Yes | No | No |
| Built-in Rust REST API | Yes | No | No |
