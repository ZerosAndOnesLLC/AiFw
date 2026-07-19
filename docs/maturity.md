# Feature maturity

AiFw is beta software under active development. A schema, API, UI, or rendered command proves control-plane coverage only; it does not prove that FreeBSD accepts the configuration or that packets follow the intended path.

| Feature | Control plane | FreeBSD data plane | Automated FreeBSD functional test | Performance / multi-node validation | Production-supported |
|---|---|---|---|---|---|
| Stateful pf filtering | Implemented | Implemented | Partial (build/parser; packet suite pending) | Not published | No |
| Conventional SNAT/DNAT/BiNAT | Implemented | Implemented | Packet suite pending | Not published | No |
| NAT64/NAT46 | Experimental models | Not implemented | No | No | No |
| WireGuard | Implemented | Implemented | Appliance qualification pending | Not published | No |
| IPsec | Metadata CRUD only | Not implemented (no IKE or kernel SA/SP install) | No | No | No |
| IDS + reactive source blocking | Implemented | Passive capture plus pf-table response | Packet suite pending | Not published | No |
| Inline IPS | Stub/experimental | Not implemented | No | No | No |
| CoDel shaping | Experimental model | Not implemented with dummynet FQ-CoDel | No | No | No |
| Multi-WAN | Substantial | Implemented components | Environment-specific validation required | Not published | No |
| HA (CARP/pfsync) | Substantial | Implemented components | Two-node suite pending | Not published | No |
| OAuth login | Provider configuration | Callback/token exchange incomplete | No | No | No |
| Backup/import | Implemented | Best-effort snapshot/reapply | Failure-injection coverage incomplete | N/A | No |

Suricata, Sigma, and YARA input means compatibility with the subsets parsed by AiFw, not full compatibility with those upstream engines. Quantitative availability or performance claims require a reproducible test artifact from the exact released build before they may be added to this table.

## Claim policy

Documentation may call a feature implemented only when both its control plane and intended live data plane exist. “Verified” additionally requires a repeatable FreeBSD functional test. Production support requires released-build qualification, documented recovery behaviour, and (where relevant) performance or multi-node evidence.
