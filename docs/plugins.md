---
layout: default
title: Plugin System — AiFw
description: Extend AiFw with Rust and WASM plugins. 12 hook points across rules, connections, DNS, DHCP, VPN, and more.
permalink: /plugins/
---

<div class="content-page">
<article markdown="1">

# AiFw Plugin System

AiFw includes a plugin system that lets you extend firewall behavior without modifying core code. Plugins can react to network events, block traffic, add IPs to block tables, log activity, and integrate with external systems.

## Overview

- **12 hook points** across the firewall pipeline (rules, connections, DNS, DHCP, VPN, API, timer)
- **3 built-in plugins** (Logging, IP Reputation, Webhook) — disabled by default
- **Native Rust plugins** via the `Plugin` trait
- **WASM plugin support** (planned) for sandboxed third-party plugins
- **Plugin directory** at `/usr/local/lib/aifw/plugins/` for installable plugins
- **Web UI** for managing, configuring, and monitoring plugins
- **Database-backed** — plugin enable/disable state persists across restarts

## Quick Start

### Enable a Built-in Plugin

1. Navigate to **Extensions > Plugins** in the web UI
2. Find the plugin you want (e.g., "logging")
3. Click the toggle switch to enable it
4. The plugin starts immediately — no restart required

### View Plugin Configuration

1. Click on a plugin card to open the config editor
2. Edit the JSON settings
3. Click **Save Config**

### API

```bash
# List all plugins
curl -H "Authorization: Bearer $TOKEN" https://firewall:8080/api/v1/plugins

# Enable a plugin
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"logging","enabled":true}' \
  https://firewall:8080/api/v1/plugins/toggle

# Get plugin config
curl -H "Authorization: Bearer $TOKEN" \
  https://firewall:8080/api/v1/plugins/logging/config

# Update plugin config
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"max_entries":5000}}' \
  https://firewall:8080/api/v1/plugins/logging/config

# Discover installable plugins from plugin directory
curl -H "Authorization: Bearer $TOKEN" \
  https://firewall:8080/api/v1/plugins/discover
```

## Hook Points

Plugins subscribe to specific hooks. The firewall dispatches events to running plugins that are subscribed to the relevant hook.

| Hook | When it fires | Event data | Can block? |
|------|--------------|------------|------------|
| `pre_rule` | Before rule evaluation | src/dst IP, ports, protocol | Yes |
| `post_rule` | After rule evaluation (from pflog) | src/dst IP, ports, protocol, action | No (observe only) |
| `connection_new` | New connection in state table | src/dst IP, ports, protocol, state | Yes (AddToTable) |
| `connection_established` | Connection becomes established | Same as above | No |
| `connection_closed` | Connection removed from state table | src/dst IP, ports | No |
| `log_event` | Audit log entry written | action, details, source | No |
| `api_request` | Authenticated API request | method, path, remote_addr | Yes (returns 403) |
| `dns_query` | DNS query received (rDNS) | query name, type, src IP | Yes |
| `dns_response` | DNS response sent | query name, type, response code | Modify |
| `dhcp_lease` | DHCP lease action (rDHCP) | MAC, IP, hostname, action | No |
| `vpn_event` | VPN tunnel state change | tunnel name, peer, action | No |
| `timer` | Every 60 seconds | timestamp | No |

## Hook Actions

When a plugin processes a hook event, it returns an action:

| Action | Effect |
|--------|--------|
| `Continue` | Normal processing (default) |
| `Block` | Block the packet/request (pre_rule, api_request) |
| `Allow` | Allow and skip further checks |
| `Log(message)` | Log with extra context |
| `AddToTable { table, ip }` | Add IP to a pf table (e.g., blocklist) |
| `RemoveFromTable { table, ip }` | Remove IP from a pf table |
| `Modify(value)` | Modify a value (e.g., DNS response rewrite) |
| `Multi(actions)` | Return multiple actions |

## Writing a Native Plugin

### 1. Implement the Plugin Trait

```rust
use async_trait::async_trait;
use aifw_plugins::{
    Plugin, PluginInfo, PluginConfig, PluginContext,
    HookEvent, HookAction, HookPoint,
};

pub struct MyPlugin;

impl MyPlugin {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl Plugin for MyPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "my_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "My custom plugin".to_string(),
            author: "Your Name".to_string(),
            hooks: vec![
                HookPoint::PostRule,
                HookPoint::ConnectionNew,
            ],
        }
    }

    async fn init(
        &mut self,
        config: &PluginConfig,
        _ctx: &PluginContext,
    ) -> Result<(), String> {
        // Read config settings
        let threshold = config.get_u64("threshold").unwrap_or(100);
        println!("Plugin initialized with threshold: {}", threshold);
        Ok(())
    }

    async fn on_hook(
        &self,
        event: &HookEvent,
        ctx: &PluginContext,
    ) -> HookAction {
        match &event.data {
            aifw_plugins::hooks::HookEventData::Rule {
                src_ip, action, ..
            } => {
                if action == "block" {
                    if let Some(ip) = src_ip {
                        // Add blocked source to a custom table
                        return HookAction::AddToTable {
                            table: "my_blocklist".to_string(),
                            ip: *ip,
                        };
                    }
                }
                HookAction::Continue
            }
            aifw_plugins::hooks::HookEventData::Connection {
                src_ip, dst_port, ..
            } => {
                // Block connections to suspicious ports
                if *dst_port == 4444 {
                    return HookAction::Block;
                }
                HookAction::Continue
            }
            _ => HookAction::Continue,
        }
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        println!("Plugin shutting down");
        Ok(())
    }
}
```

### 2. Register the Plugin

In `aifw-api/src/main.rs`, add your plugin to the initialization:

```rust
let _ = plugin_mgr.register(
    Box::new(my_plugin::MyPlugin::new()),
    aifw_plugins::PluginConfig { enabled: false, ..Default::default() },
).await;
```

### 3. Enable via UI or API

Navigate to Extensions > Plugins and toggle your plugin on.

## Plugin Context

Plugins receive a `PluginContext` that provides:

```rust
// Access to pf table operations
ctx.add_to_table("blocklist", ip).await?;
ctx.remove_from_table("blocklist", ip).await?;

// Shared key-value store (inter-plugin communication)
ctx.store_set("last_scan_time", "1234567890").await;
let val = ctx.store_get("last_scan_time").await;
```

## Installable Plugin Directory

Third-party plugins can be installed to `/usr/local/lib/aifw/plugins/`. Each plugin is a directory with a `plugin.toml` manifest:

```
/usr/local/lib/aifw/plugins/
  my-plugin/
    plugin.toml
    plugin.wasm    (for WASM plugins)
```

### plugin.toml Format

```toml
name = "my-plugin"
version = "1.0.0"
description = "Does something useful"
author = "Your Name"
plugin_type = "wasm"        # "native" or "wasm"
wasm_file = "plugin.wasm"   # for WASM plugins
hooks = ["post_rule", "connection_new", "timer"]

[default_settings]
threshold = 100
log_level = "info"
```

## Built-in Plugins

### Logging Plugin

Captures all hook events to an in-memory buffer. Useful for debugging and auditing.

- **Hooks:** pre_rule, post_rule, connection_new, connection_closed, log_event
- **Settings:** `max_entries` (default: 10000)

### IP Reputation Plugin

Maintains a blocklist of known-bad IPs. Blocks traffic from blacklisted sources and adds them to a pf table.

- **Hooks:** pre_rule, connection_new
- **Settings:** `table_name` (pf table), `blocklist` (array of IPs)
- **Actions:** Block + AddToTable for matched IPs

### Webhook Plugin

Sends notifications to an HTTP endpoint for security events.

- **Hooks:** post_rule, connection_new, log_event
- **Settings:** `url`, `notify_on_block`, `notify_on_connection`
- **Actions:** Queues notifications for blocked traffic and new connections

## Data Flow

```
                    +-----------+
    pflog0 -------->| PostRule  |-----> plugins
                    +-----------+
                    
    state table --->| Conn New  |-----> plugins ---> AddToTable
    (1/sec diff)    | Conn Close|                    Block
                    +-----------+

    API request --->| ApiRequest|-----> plugins ---> Block (403)
                    +-----------+

    60s timer ----->| Timer     |-----> plugins (cron-like tasks)
                    +-----------+

    (future)
    rDNS query ---->| DnsQuery  |-----> plugins ---> Block/Modify
    rDHCP lease --->| DhcpLease |-----> plugins
    VPN event ----->| VpnEvent  |-----> plugins
```

## Performance Notes

- Hook dispatch only runs if there are running plugins (`running_count() > 0`)
- Connection tracking uses HashSet diff — O(n) per second with state table size
- pflog dispatch is per-packet but only for logged packets
- Timer hooks fire once per minute, not per-packet
- Plugin manager uses RwLock — reads don't block each other, only writes (toggle) block briefly

</article>
</div>
