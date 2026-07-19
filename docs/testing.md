# Test layers and release evidence

Linux unit and integration tests validate models, parsers, persistence, APIs, command rendering, and mock-backend behaviour. They do not prove that FreeBSD accepts a generated configuration or that packets traverse the appliance correctly.

Every data-plane change should add the lowest applicable layers:

1. deterministic Rust/unit and API tests on each commit;
2. FreeBSD functional tests using jails and `epair` links, with real `pfctl` parsing and packet traffic;
3. an appliance smoke test that boots the exact produced ISO/IMG, completes first boot, checks service and pf health, and exercises one routed packet path;
4. scheduled qualification for multi-node, reboot, throughput, latency, and sustained-load scenarios.

A portable FreeBSD topology is `client jail -- epair -- firewall -- epair -- server jail`. Tests must retain rendered commands, `pfctl` rules/state, interface/routes, packet results, service logs, and source/artifact revisions. Infrastructure-specific hypervisor provisioning belongs in the operator's private harness; only portable assertions, fixtures, and artifact contracts belong in this repository.

Release notes must distinguish tests that passed from tests that were skipped. Skipped mandatory qualification cannot support a production-ready claim.
