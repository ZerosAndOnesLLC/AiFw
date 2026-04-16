---
layout: default
title: Install AiFw — FreeBSD firewall installation guide
description: Step-by-step guide to install AiFw on FreeBSD from ISO, USB image, or update an existing installation.
permalink: /install/
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "Install AiFw on FreeBSD",
  "description": "Install the AiFw firewall appliance on bare metal or a hypervisor via ISO or USB image.",
  "totalTime": "PT10M",
  "supply": [
    {"@type": "HowToSupply", "name": "Target hardware or VM (bare metal, KVM, ESXi, bhyve, Proxmox)"},
    {"@type": "HowToSupply", "name": "USB stick or virtual CD-ROM"}
  ],
  "step": [
    {"@type": "HowToStep", "position": 1, "name": "Download the ISO or USB image",
     "text": "Grab the latest AiFw ISO or USB IMG from GitHub Releases.",
     "url": "https://github.com/ZerosAndOnesLLC/AiFw/releases/latest"},
    {"@type": "HowToStep", "position": 2, "name": "Boot from the image",
     "text": "Boot the target machine or VM from the ISO/USB. AiFw auto-logs into the console menu."},
    {"@type": "HowToStep", "position": 3, "name": "Run the first-boot wizard",
     "text": "Set root password, hostname, network interfaces (WAN/LAN), admin account with optional 2FA, and initial firewall policy."},
    {"@type": "HowToStep", "position": 4, "name": "Access the web dashboard",
     "text": "Browse to https://<appliance-ip>:8080 and log in with the admin account you created."}
  ]
}
</script>

<div class="content-page">
<article markdown="1">

# Install AiFw

AiFw runs on FreeBSD 15+ and anything that can boot a FreeBSD ISO — physical hardware, KVM, VMware, Proxmox, or any cloud VM.

## Quick install (recommended)

Grab the latest ISO from the [releases page](https://github.com/ZerosAndOnesLLC/AiFw/releases/latest):

```bash
# ISO (for CD/DVD or VM boot)
aifw-X.Y.Z-amd64.iso.xz

# USB image (for a USB installer stick)
aifw-X.Y.Z-amd64.img.xz
```

Uncompress first:

```bash
xz -d aifw-*-amd64.iso.xz
```

### Boot from ISO

1. Attach the ISO to your VM or burn it to a USB/DVD
2. Boot — you'll land in the AiFw console menu (OPNsense-style)
3. Select option **14** to install to disk (ZFS or UFS)
4. After install and reboot, the first-boot wizard runs automatically

### Write USB image

```bash
# Linux/macOS
sudo dd if=aifw-X.Y.Z-amd64.img of=/dev/sdX bs=1M status=progress

# FreeBSD
sudo dd if=aifw-X.Y.Z-amd64.img of=/dev/daX bs=1M
```

## First-boot setup wizard

The wizard walks you through everything:

1. **Root password** and SSH access
2. **Hostname**
3. **System tuning** (auto-detected based on CPU + RAM)
4. **Network interfaces** (WAN / LAN detection)
5. **Admin user + 2FA**
6. **DNS servers**
7. **Firewall policy** (Standard / Strict / Permissive)

Once done, reach the web UI at:

```
https://<lan-ip>:8080
```

## Minimum requirements

| Resource | Minimum | Recommended |
|----------|--------:|------------:|
| CPU | 1 core (amd64) | 2+ cores, AES-NI |
| RAM | 1 GB | 4 GB+ (more for IDS) |
| Disk | 4 GB | 16 GB SSD |
| NIC | 1 (single-arm) | 2+ (WAN + LAN) |

The memory cache sizing (IDS alert buffer, dashboard history) scales automatically with detected RAM.

## Update from the CLI

If the web UI breaks, the console has built-in update commands:

```bash
aifw update check      # see if an update is available
aifw update install    # download, verify, install, restart
aifw update rollback   # revert to the previous version
```

## Platform support

| Platform | Status |
|----------|--------|
| Bare metal (amd64) | Supported |
| KVM / Proxmox | Supported |
| VMware ESXi | Supported |
| bhyve | Supported |
| AWS / DigitalOcean FreeBSD images | Untested, should work |
| arm64 (Raspberry Pi, Ampere) | Planned |

## Troubleshooting

**Can't reach the web UI?**
Console → option 7 (Reset root password) → check that `aifw_api` is running:
```bash
service aifw_api status
```

**Locked yourself out with a rule change?**
Every apply triggers commit-confirm. If you don't click Confirm within 2 minutes, the config auto-reverts.

**Service died silently?**
All services run under `daemon(8)` with `-R 5` auto-restart. Check `/var/log/aifw/*.log` for crash details.

## Next steps

- [Configure WireGuard VPN →]({{ '/docs/wireguard' | relative_url }})
- [Enable IDS/IPS →]({{ '/docs/ids' | relative_url }})
- [Compare features vs pfSense/OPNsense →]({{ '/compare' | relative_url }})

</article>
</div>
