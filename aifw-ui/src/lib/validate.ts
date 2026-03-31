/** Validate an IPv4 address (e.g. "192.168.1.1") */
export function isValidIPv4(ip: string): boolean {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

/** Validate an IPv6 address (basic check) */
export function isValidIPv6(ip: string): boolean {
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(ip.trim());
}

/** Validate an IP address (v4 or v6) */
export function isValidIP(ip: string): boolean {
  return isValidIPv4(ip.trim()) || isValidIPv6(ip.trim());
}

/** Validate CIDR notation (e.g. "192.168.1.0/24" or "10.0.0.5/32") */
export function isValidCIDR(cidr: string): boolean {
  const [ip, prefix] = cidr.trim().split("/");
  if (!ip || !prefix) return false;
  const prefixNum = parseInt(prefix, 10);
  if (isValidIPv4(ip)) return !isNaN(prefixNum) && prefixNum >= 0 && prefixNum <= 32;
  if (isValidIPv6(ip)) return !isNaN(prefixNum) && prefixNum >= 0 && prefixNum <= 128;
  return false;
}

/** Validate an address: "any", IP, CIDR, or alias (<name>) */
export function isValidAddress(addr: string): boolean {
  const s = addr.trim();
  if (!s || s.toLowerCase() === "any") return true;
  if (s.startsWith("<") && s.endsWith(">")) return true; // alias
  if (s.includes("/")) return isValidCIDR(s);
  return isValidIP(s);
}

/** Validate a port number (1-65535) */
export function isValidPort(port: string): boolean {
  const n = parseInt(port.trim(), 10);
  return !isNaN(n) && n >= 1 && n <= 65535;
}

/** Validate a port or port range (e.g. "80", "8080-8090") */
export function isValidPortRange(value: string): boolean {
  const s = value.trim();
  if (!s) return true; // empty is ok (optional)
  if (s.includes("-")) {
    const [start, end] = s.split("-");
    return isValidPort(start) && isValidPort(end) && parseInt(start, 10) <= parseInt(end, 10);
  }
  return isValidPort(s);
}

/** Validate a MAC address (e.g. "aa:bb:cc:dd:ee:ff") */
export function isValidMAC(mac: string): boolean {
  return /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(mac.trim());
}

/** Validate a hostname (e.g. "server1", "web-01") */
export function isValidHostname(name: string): boolean {
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(name.trim());
}

/** Validate a domain name (e.g. "example.com") */
export function isValidDomain(domain: string): boolean {
  return /^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(domain.trim());
}

/** Validate a URL */
export function isValidURL(url: string): boolean {
  try { new URL(url.trim()); return true; } catch { return false; }
}

/** Validate alias name (alphanumeric + _ and -, max 31 chars) */
export function isValidAliasName(name: string): boolean {
  return /^[a-zA-Z0-9_-]{1,31}$/.test(name.trim());
}

/** Return error message or null if valid */
export function validateAddress(addr: string, label = "Address"): string | null {
  if (!addr.trim()) return null; // empty handled by required check
  if (!isValidAddress(addr)) return `${label}: invalid format. Use IP, CIDR (10.0.0.0/8), "any", or <alias>.`;
  return null;
}

export function validatePort(port: string, label = "Port"): string | null {
  if (!port.trim()) return null;
  if (!isValidPortRange(port)) return `${label}: must be 1-65535 or a range like 80-443.`;
  return null;
}

export function validateIP(ip: string, label = "IP"): string | null {
  if (!ip.trim()) return null;
  if (!isValidIP(ip)) return `${label}: invalid IPv4 or IPv6 address.`;
  return null;
}

export function validateCIDR(cidr: string, label = "Network"): string | null {
  if (!cidr.trim()) return null;
  if (!isValidCIDR(cidr)) return `${label}: must be in CIDR notation (e.g. 192.168.1.0/24).`;
  return null;
}
