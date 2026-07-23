// Helpers for cross-family (NAT64/NAT46, pf af-to) rule UX (#531).
// Pure functions only — no React here.

export const WELL_KNOWN_PREFIX = "64:ff9b::/96";

export function isCrossFamily(natType: string): boolean {
  return natType === "nat64" || natType === "nat46";
}

/** Expand an IPv6 address string to its 8 groups, or null if malformed. */
function expandV6(addr: string): number[] | null {
  const parts = addr.split("::");
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 2 && missing < 0) return null;
  if (parts.length === 1 && head.length !== 8) return null;
  const groups = [...head, ...Array(Math.max(missing, 0)).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => parseInt(g || "0", 16));
  return nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? nums : null;
}

export function isV6Host(addr: string): boolean {
  return !addr.includes("/") && addr.includes(":") && expandV6(addr) !== null;
}

export function isV6Prefix96(addr: string): boolean {
  const [ip, len] = addr.split("/");
  return len === "96" && expandV6(ip) !== null;
}

export function isV6AddrOrNet(addr: string): boolean {
  if (addr === "" || addr === "any") return true;
  const [ip, len] = addr.split("/");
  if (len !== undefined && !/^\d{1,3}$/.test(len)) return false;
  return expandV6(ip) !== null;
}

function parseV4(addr: string): number[] | null {
  const octets = addr.split(".");
  if (octets.length !== 4) return null;
  const nums = octets.map((o) => (/^\d{1,3}$/.test(o) ? parseInt(o, 10) : NaN));
  return nums.every((n) => n >= 0 && n <= 255) ? nums : null;
}

export function isV4Host(addr: string): boolean {
  return !addr.includes("/") && parseV4(addr) !== null;
}

export function isV4AddrOrNet(addr: string): boolean {
  if (addr === "" || addr === "any") return true;
  const [ip, len] = addr.split("/");
  if (len !== undefined && !/^\d{1,2}$/.test(len)) return false;
  return parseV4(ip) !== null;
}

/**
 * RFC 6052 §2.2: embed an IPv4 address in the low 32 bits of an IPv6 /96
 * prefix — the address an IPv6-only client uses to reach an IPv4 host
 * through NAT64. Returns null if either input is malformed.
 */
export function embedRfc6052(prefix: string, v4: string): string | null {
  const groups = expandV6(prefix.split("/")[0]);
  const octets = parseV4(v4);
  if (!groups || !octets) return null;
  const out = [...groups.slice(0, 6), (octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
  // Compress the longest zero run (prefer the RFC 5952 canonical-ish form).
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (out[i] !== 0) continue;
    let j = i;
    while (j < 8 && out[j] === 0) j++;
    if (j - i > bestLen) {
      bestLen = j - i;
      bestStart = i;
    }
    i = j;
  }
  const hex = out.map((n) => n.toString(16));
  if (bestLen >= 2) {
    const head = hex.slice(0, bestStart).join(":");
    const tail = hex.slice(bestStart + bestLen).join(":");
    return `${head}::${tail}`;
  }
  return hex.join(":");
}

export interface FieldMeta {
  srcLabel: string;
  srcPlaceholder: string;
  dstLabel: string;
  dstPlaceholder: string;
  redirectLabel: string;
  redirectPlaceholder: string;
  redirectHelp: string;
  showRedirectPort: boolean;
}

const GENERIC_META: FieldMeta = {
  srcLabel: "Source Address",
  srcPlaceholder: "any",
  dstLabel: "Destination Address",
  dstPlaceholder: "any",
  redirectLabel: "Redirect Address",
  redirectPlaceholder: "e.g. 10.0.0.5",
  redirectHelp: "",
  showRedirectPort: true,
};

/** Contextual form labels/placeholders per NAT type. */
export function fieldMeta(natType: string): FieldMeta {
  switch (natType) {
    case "nat64":
      return {
        srcLabel: "IPv6 Source Network",
        srcPlaceholder: "any (e.g. 2001:db8:1::/64)",
        dstLabel: "NAT64 Prefix (/96)",
        dstPlaceholder: WELL_KNOWN_PREFIX,
        redirectLabel: "IPv4 Translation Source",
        redirectPlaceholder: "e.g. 203.0.113.1",
        redirectHelp:
          "IPv4 address the firewall sources translated traffic from — usually the WAN address.",
        showRedirectPort: false,
      };
    case "nat46":
      return {
        srcLabel: "IPv4 Source Network",
        srcPlaceholder: "any (e.g. 10.0.0.0/24)",
        dstLabel: "IPv4 Destination",
        dstPlaceholder: "e.g. 10.99.1.1",
        redirectLabel: "IPv6 Translation Source",
        redirectPlaceholder: "e.g. 2001:db8:2::1",
        redirectHelp:
          "IPv6 address the firewall sources translated traffic from. The translated destination is the IPv4 destination embedded in this address's /96 subnet (RFC 6052).",
        showRedirectPort: false,
      };
    default:
      return GENERIC_META;
  }
}

export interface CrossFamilyErrors {
  src?: string;
  dst?: string;
  redirect?: string;
}

/** Client-side pre-submit checks mirroring the API's family validation. */
export function validateCrossFamily(
  natType: string,
  src: string,
  dst: string,
  redirect: string,
): CrossFamilyErrors {
  const errs: CrossFamilyErrors = {};
  if (natType === "nat64") {
    if (!isV6AddrOrNet(src)) errs.src = "Must be an IPv6 address/network (the rule matches IPv6 traffic)";
    if (dst && !isV6Prefix96(dst)) errs.dst = `Must be an IPv6 /96 prefix, e.g. ${WELL_KNOWN_PREFIX}`;
    if (redirect && !isV4Host(redirect)) errs.redirect = "Must be a single IPv4 address";
  } else if (natType === "nat46") {
    if (!isV4AddrOrNet(src)) errs.src = "Must be an IPv4 address/network (the rule matches IPv4 traffic)";
    if (!dst || !isV4AddrOrNet(dst) || dst === "any") errs.dst = "A concrete IPv4 destination is required";
    if (redirect && !isV6Host(redirect)) errs.redirect = "Must be a single IPv6 address";
  }
  return errs;
}

/** "IPv6 → IPv4" style direction summary for the rules table. */
export function directionSummary(natType: string): string | null {
  if (natType === "nat64") return "IPv6 → IPv4";
  if (natType === "nat46") return "IPv4 → IPv6";
  return null;
}
