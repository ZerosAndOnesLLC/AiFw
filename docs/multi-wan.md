---
layout: default
title: Multi-WAN
---

# Multi-WAN

AiFw ships an enterprise-grade multi-WAN system built on FreeBSD FIBs and pf.
The design exceeds what Cisco (IOS PBR + IP SLA) and Juniper (routing-instances + RPM) offer:

- **FIB isolation** — each WAN lives in its own FreeBSD FIB, just like a Juniper routing-instance.
- **Active health monitoring** — ICMP / TCP / HTTP / DNS probes with hysteresis and MOS scoring.
- **Gateway groups** — failover, weighted load-balance, and adaptive (MOS-weighted) policies.
- **Policy routing** — match on 5-tuple + interface + DSCP + geo-IP; steer to an instance, gateway, or group.
- **Pre-flight blast-radius** — dry-run any config change, see which existing flows would be re-routed and whether mgmt would be stranded, **before** applying.
- **Per-flow visibility** — live pf state table joined to policy labels, with 1-click force-migrate.
- **GitOps export/import** — `GET /api/v1/multiwan/config.yaml` returns the entire multi-WAN config.
- **AI anomaly detection** (optional) — SLA baseline deviation alerting when probes still pass but latency profile shifted.

## Prerequisites

Enable multi-FIB at boot:

```
# /boot/loader.conf
net.fibs=16
```

Reboot. Verify:

```
sysctl net.fibs
```

## Quick start

1. Create a routing instance for the second WAN (FIB 1):
   ```
   POST /api/v1/multiwan/instances
   { "name": "wan2", "fib_number": 1 }
   ```
2. Attach the WAN interface to the instance (this runs `ifconfig em1 fib 1`):
   ```
   POST /api/v1/multiwan/instances/<id>/members
   { "interface": "em1" }
   ```
3. Create a gateway with ICMP monitoring:
   ```
   POST /api/v1/multiwan/gateways
   {
     "name": "wan2-gw",
     "instance_id": "<wan2-id>",
     "interface": "em1",
     "next_hop": "203.0.113.1",
     "monitor_kind": "icmp"
   }
   ```
4. Seed management escape leaks (so admin traffic can always reach the default FIB):
   ```
   POST /api/v1/multiwan/leaks/seed-mgmt
   ```
5. Add a policy routing LAN→Netflix via wan2:
   ```
   POST /api/v1/multiwan/policies
   {
     "priority": 100,
     "name": "netflix-via-wan2",
     "iface_in": "em_lan",
     "src_addr": "10.0.0.0/24",
     "dst_addr": "any",
     "protocol": "tcp",
     "dst_port": "443",
     "action_kind": "set_gateway",
     "target_id": "<wan2-gw-id>"
   }
   ```

## pf rules emitted

For the policy above, AiFw generates:

```
# anchor "aifw-pbr"
pass out quick on em1 inet proto tcp from 10.0.0.0/24 to any port 443 \
  route-to (em1 203.0.113.1) keep state (if-bound) label "pbr:<uuid>"

# anchor "aifw-mwan-reply"
pass in quick on em_lan inet proto tcp from 10.0.0.0/24 to any port 443 \
  reply-to (em1 203.0.113.1) keep state (if-bound) label "pbr:<uuid>:rep"
```

`(if-bound)` prevents states from surviving a WAN change mid-flow; `reply-to`
handles asymmetric return traffic.

## Convergence

- Probe interval: 500 ms
- Down after 3 consecutive failures (1.5 s)
- End-to-end target: ≤3 s median, ≤5 s p99

## Compared to Cisco / Juniper

| Feature | Cisco IOS | Juniper Junos | AiFw |
|---|---|---|---|
| FIB-based isolation | VRF | routing-instances | yes |
| Live health monitoring | IP SLA | RPM | yes |
| Hysteresis + dampening | yes | yes | yes |
| MOS scoring | VoIP RTP probe only | yes | yes (all probe kinds) |
| Blast-radius preview | no | no | yes |
| Per-flow force-migrate | no | no | yes |
| GitOps YAML export | no | no | yes |
| Declarative leak policies | rib-groups (imperative) | rib-groups | yes (declarative) |
| Anomaly scoring on latency drift | no | no | yes (AI hook) |

## Anchors

Multi-WAN uses three dedicated pf anchors, evaluated before `aifw-nat` / `aifw`:

- `aifw-pbr` — policy routing rules (route-to / rtable)
- `aifw-mwan-reply` — paired reply-to rules
- `aifw-mwan-leak` — cross-FIB leak allowances

After your first multi-WAN policy lands, make sure `/usr/local/etc/aifw/pf.conf.aifw` references these:

```
anchor "aifw-pbr" all
anchor "aifw-mwan-leak" all
anchor "aifw-mwan-reply" all
anchor "aifw-nat" all
anchor "aifw" all
```
