---
name: Bug Report
about: Report a bug or unexpected behavior
title: "[Bug] "
labels: bug
assignees: ''
---

**AiFw Version**
e.g. 5.8.0

**FreeBSD Version**
e.g. FreeBSD 15.0-RELEASE

**Component**
Which part of AiFw is affected?
- [ ] Web UI
- [ ] REST API
- [ ] Firewall Rules / pf
- [ ] NAT
- [ ] DHCP (rDHCP)
- [ ] DNS (rDNS / Unbound)
- [ ] VPN (WireGuard / IPsec)
- [ ] Setup Wizard
- [ ] Other: ___

**Describe the Bug**
A clear description of what happened.

**Steps to Reproduce**
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What should have happened.

**Actual Behavior**
What actually happened.

**Logs / Screenshots**
Paste any relevant error messages, API responses, or screenshots.

```
# API logs: check browser console or
# ssh root@<firewall> tail -50 /var/log/messages | grep aifw
```

**Additional Context**
Any other information (network topology, hardware, etc).
