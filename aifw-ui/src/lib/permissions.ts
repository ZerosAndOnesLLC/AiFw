/**
 * Permission list matching the Rust Permission enum bit indices exactly.
 * MUST stay in sync with aifw-common/src/permission.rs ALL_PERMISSIONS.
 */
export const PERMISSION_LIST = [
  "dashboard:view",    // 0
  "rules:read",        // 1
  "rules:write",       // 2
  "nat:read",          // 3
  "nat:write",         // 4
  "vpn:read",          // 5
  "vpn:write",         // 6
  "geoip:read",        // 7
  "geoip:write",       // 8
  "ids:read",          // 9
  "ids:write",         // 10
  "dns:read",          // 11
  "dns:write",         // 12
  "dhcp:read",         // 13
  "dhcp:write",        // 14
  "aliases:read",      // 15
  "aliases:write",     // 16
  "interfaces:read",   // 17
  "interfaces:write",  // 18
  "connections:view",  // 19
  "logs:view",         // 20
  "users:read",        // 21
  "users:write",       // 22
  "settings:read",     // 23
  "settings:write",    // 24
  "plugins:read",      // 25
  "plugins:write",     // 26
  "updates:read",      // 27
  "updates:install",   // 28
  "backup:read",       // 29
  "backup:write",      // 30
  "system:reboot",     // 31
  "proxy:read",        // 32
  "proxy:write",       // 33
] as const;

export type PermissionName = (typeof PERMISSION_LIST)[number];

/** Decode a u64 bitmask (as a number) into a Set of permission strings. */
export function decodePermissions(bits: number): Set<string> {
  const perms = new Set<string>();
  for (let i = 0; i < PERMISSION_LIST.length; i++) {
    // JavaScript bitwise ops work on 32 bits, so we use Math for bits > 31
    if (i < 32) {
      if ((bits >>> 0) & (1 << i)) perms.add(PERMISSION_LIST[i]);
    } else {
      // For bits 32+, divide by 2^32 and check lower bits
      if (Math.floor(bits / 2 ** 32) & (1 << (i - 32))) perms.add(PERMISSION_LIST[i]);
    }
  }
  return perms;
}

export function hasPermission(perms: Set<string>, perm: string): boolean {
  return perms.has(perm);
}

export function canRead(perms: Set<string>, domain: string): boolean {
  return perms.has(`${domain}:read`) || perms.has(`${domain}:view`);
}

export function canWrite(perms: Set<string>, domain: string): boolean {
  return perms.has(`${domain}:write`) || perms.has(`${domain}:install`);
}

/** Permission categories for the role management UI. */
export const PERMISSION_CATEGORIES = [
  { label: "Dashboard", perms: ["dashboard:view"] },
  { label: "Firewall Rules", perms: ["rules:read", "rules:write"] },
  { label: "NAT", perms: ["nat:read", "nat:write"] },
  { label: "VPN", perms: ["vpn:read", "vpn:write"] },
  { label: "Geo-IP", perms: ["geoip:read", "geoip:write"] },
  { label: "IDS/IPS", perms: ["ids:read", "ids:write"] },
  { label: "DNS", perms: ["dns:read", "dns:write"] },
  { label: "DHCP", perms: ["dhcp:read", "dhcp:write"] },
  { label: "Aliases", perms: ["aliases:read", "aliases:write"] },
  { label: "Interfaces", perms: ["interfaces:read", "interfaces:write"] },
  { label: "Connections", perms: ["connections:view"] },
  { label: "Logs", perms: ["logs:view"] },
  { label: "Users", perms: ["users:read", "users:write"] },
  { label: "Settings", perms: ["settings:read", "settings:write"] },
  { label: "Plugins", perms: ["plugins:read", "plugins:write"] },
  { label: "Updates", perms: ["updates:read", "updates:install"] },
  { label: "Backup", perms: ["backup:read", "backup:write"] },
  { label: "System", perms: ["system:reboot"] },
  { label: "Reverse Proxy", perms: ["proxy:read", "proxy:write"] },
];
