import { api } from "@/lib/api";
import { validateCIDR, validateIP, isValidIPv4 } from "@/lib/validate";

/* -- Types ---------------------------------------------------------- */

export interface DhcpOptionOverride {
  code: number;
  value_type: "ip" | "ips" | "string" | "u8" | "u16" | "u32" | "hex";
  value: string;
}

export interface DhcpSubnet {
  id: string;
  network: string;
  pool_start: string;
  pool_end: string;
  gateway: string;
  dns_servers?: string[];
  domain_name?: string;
  lease_time?: number;
  max_lease_time?: number;
  renewal_time?: number;
  rebinding_time?: number;
  preferred_time?: number;
  subnet_type: string;
  delegated_length?: number;
  enabled: boolean;
  description?: string;
  trusted_relays?: string[];
  ntp_servers?: string;
  options?: DhcpOptionOverride[];
  created_at: string;
}

export interface SubnetForm {
  network: string;
  pool_start: string;
  pool_end: string;
  gateway: string;
  dns_servers: string;
  domain_name: string;
  lease_time: string;
  max_lease_time: string;
  renewal_time: string;
  rebinding_time: string;
  preferred_time: string;
  subnet_type: string;
  delegated_length: string;
  description: string;
  enabled: boolean;
  trusted_relays: string[];
  ntp_servers: string;
  options: DhcpOptionOverride[];
}

export interface GlobalDefaults {
  dns_servers: string[];
  ntp_servers: string[];
  domain_name: string;
  default_lease_time: number;
}

/* -- Constants ------------------------------------------------------- */

// Reserved + collision codes (kept in sync with rDHCP src/config/validation.rs
// and aifw-api/src/dhcp.rs).
export const RESERVED_OPTION_CODES = [0, 1, 28, 50, 51, 53, 54, 55, 57, 58, 59, 82, 255];
export const COLLISION_OPTION_CODES = [3, 6, 15, 42];

export const OPTION_VALUE_TYPES: DhcpOptionOverride["value_type"][] = [
  "ip", "ips", "string", "u8", "u16", "u32", "hex",
];

export const defaultForm: SubnetForm = {
  network: "",
  pool_start: "",
  pool_end: "",
  gateway: "",
  dns_servers: "",
  domain_name: "",
  lease_time: "",
  max_lease_time: "",
  renewal_time: "",
  rebinding_time: "",
  preferred_time: "",
  subnet_type: "address",
  delegated_length: "",
  description: "",
  enabled: true,
  trusted_relays: [],
  ntp_servers: "",
  options: [],
};

/* -- Validation ------------------------------------------------------ */

export function validateOption(opt: DhcpOptionOverride): string | null {
  if (!Number.isInteger(opt.code) || opt.code < 0 || opt.code > 255) {
    return `Code must be 0-255`;
  }
  if (RESERVED_OPTION_CODES.includes(opt.code)) {
    return `Code ${opt.code} is reserved`;
  }
  if (COLLISION_OPTION_CODES.includes(opt.code)) {
    return `Code ${opt.code} conflicts with a typed field — use the dedicated input`;
  }
  const v = opt.value.trim();
  if (!v) return "Value cannot be empty";
  switch (opt.value_type) {
    case "ip":
      if (!isValidIPv4(v)) return `ip must be a valid IPv4`;
      return null;
    case "ips": {
      const parts = v.split(",").map((s) => s.trim()).filter(Boolean);
      if (parts.length === 0) return "ips must have at least one IPv4";
      for (const p of parts) if (!isValidIPv4(p)) return `ips: '${p}' is not a valid IPv4`;
      return null;
    }
    case "string":
      if (v.length > 255) return "string exceeds 255 bytes";
      // Printable ASCII only (graphic chars + space) — matches rDHCP validator
      if (!/^[\x20-\x7e]+$/.test(v)) return "string must be printable ASCII only";
      return null;
    case "u8": {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0 || n > 255) return "u8 must be 0-255";
      return null;
    }
    case "u16": {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0 || n > 65535) return "u16 must be 0-65535";
      return null;
    }
    case "u32": {
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0 || n > 4294967295) return "u32 must be 0-4294967295";
      return null;
    }
    case "hex":
      if (v.length % 2 !== 0) return "hex must be even-length";
      if (v.length > 510) return "hex exceeds 255 bytes (510 hex chars)";
      if (!/^[0-9a-fA-F]+$/.test(v)) return "hex contains non-hex characters";
      return null;
    default:
      return `unknown value_type`;
  }
}

/** Full client-side validation of the subnet form. Returns the list of
 *  error messages (empty = valid); required-field failures short-circuit
 *  the detailed checks, matching the original submit flow. */
export function validateSubnetForm(form: SubnetForm): string[] {
  if (!form.network.trim() || !form.pool_start.trim() || !form.pool_end.trim() || !form.gateway.trim()) {
    return ["Network, pool start, pool end, and gateway are required"];
  }

  // Client-side validation
  const errors: string[] = [];
  { const e = validateCIDR(form.network, "Network"); if (e) errors.push(e); }
  { const e = validateIP(form.pool_start, "Pool start"); if (e) errors.push(e); }
  { const e = validateIP(form.pool_end, "Pool end"); if (e) errors.push(e); }
  { const e = validateIP(form.gateway, "Gateway"); if (e) errors.push(e); }
  // DNS servers — each entry must be a valid IP
  if (form.dns_servers.trim()) {
    const bad = form.dns_servers.split(",").map((s) => s.trim()).filter(Boolean)
      .filter((ip) => !isValidIPv4(ip) && !/^[0-9a-fA-F:]+$/.test(ip));
    if (bad.length > 0) errors.push(`DNS servers: invalid ${bad.join(", ")}`);
  }
  // Trusted relays — revalidate saved chips (in case they bypassed per-chip check)
  {
    const bad = form.trusted_relays.filter((ip) => !isValidIPv4(ip) || isLoopbackV4(ip));
    if (bad.length > 0) errors.push(`Trusted relays: invalid ${bad.join(", ")}`);
  }
  // NTP servers — each entry must be a valid IP (IPv4 or IPv6)
  if (form.ntp_servers.trim()) {
    const bad = form.ntp_servers.split(",").map((s) => s.trim()).filter(Boolean)
      .filter((ip) => !isValidIPv4(ip) && !/^[0-9a-fA-F:]+$/.test(ip));
    if (bad.length > 0) errors.push(`NTP servers: invalid ${bad.join(", ")}`);
  }
  // Generic DHCP option overrides
  {
    const codes = new Set<number>();
    for (const opt of form.options) {
      const err = validateOption(opt);
      if (err) { errors.push(`Option ${opt.code}: ${err}`); continue; }
      if (codes.has(opt.code)) { errors.push(`Option ${opt.code} is duplicated`); }
      codes.add(opt.code);
    }
  }
  return errors;
}

/* -- Helpers --------------------------------------------------------- */

// Loopback: any IPv4 starting with 127.
export function isLoopbackV4(ip: string): boolean {
  return ip.trim().startsWith("127.");
}

export function fmtSeconds(s: number): string {
  if (s >= 86400 && s % 86400 === 0) return `${s / 86400}d`;
  if (s >= 3600 && s % 3600 === 0) return `${s / 3600}h`;
  if (s >= 60 && s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

export function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/** Map an existing subnet into the editable form shape. */
export function subnetToForm(subnet: DhcpSubnet): SubnetForm {
  return {
    network: subnet.network,
    pool_start: subnet.pool_start,
    pool_end: subnet.pool_end,
    gateway: subnet.gateway,
    dns_servers: Array.isArray(subnet.dns_servers) ? subnet.dns_servers.join(", ") : (subnet.dns_servers || ""),
    domain_name: subnet.domain_name || "",
    lease_time: subnet.lease_time ? String(subnet.lease_time) : "",
    max_lease_time: subnet.max_lease_time ? String(subnet.max_lease_time) : "",
    renewal_time: subnet.renewal_time ? String(subnet.renewal_time) : "",
    rebinding_time: subnet.rebinding_time ? String(subnet.rebinding_time) : "",
    preferred_time: subnet.preferred_time ? String(subnet.preferred_time) : "",
    subnet_type: subnet.subnet_type || "address",
    delegated_length: subnet.delegated_length ? String(subnet.delegated_length) : "",
    description: subnet.description || "",
    enabled: subnet.enabled,
    trusted_relays: Array.isArray(subnet.trusted_relays) ? [...subnet.trusted_relays] : [],
    ntp_servers: subnet.ntp_servers || "",
    options: Array.isArray(subnet.options) ? subnet.options.map((o) => ({ ...o })) : [],
  };
}

/** Build the create/update request body from the form (blank optional
 *  fields are omitted). */
export function buildSubnetPayload(form: SubnetForm): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    network: form.network.trim(),
    pool_start: form.pool_start.trim(),
    pool_end: form.pool_end.trim(),
    gateway: form.gateway.trim(),
    subnet_type: form.subnet_type,
    enabled: form.enabled,
    trusted_relays: form.trusted_relays,
    options: form.options,
  };
  if (form.ntp_servers.trim()) {
    payload.ntp_servers = form.ntp_servers
      .split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (form.dns_servers.trim()) {
    payload.dns_servers = form.dns_servers
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  if (form.domain_name.trim()) payload.domain_name = form.domain_name.trim();
  if (form.lease_time.trim()) payload.lease_time = Number(form.lease_time);
  if (form.max_lease_time.trim()) payload.max_lease_time = Number(form.max_lease_time);
  if (form.renewal_time.trim()) payload.renewal_time = Number(form.renewal_time);
  if (form.rebinding_time.trim()) payload.rebinding_time = Number(form.rebinding_time);
  if (form.preferred_time.trim()) payload.preferred_time = Number(form.preferred_time);
  if (form.delegated_length.trim()) payload.delegated_length = Number(form.delegated_length);
  if (form.description.trim()) payload.description = form.description.trim();
  return payload;
}

/* -- API calls ------------------------------------------------------- */

export async function listDhcpSubnets(): Promise<DhcpSubnet[]> {
  const body = await api.get<{ data?: DhcpSubnet[] }>("/api/v1/dhcp/v4/subnets");
  return body.data || [];
}

export async function fetchDhcpGlobalDefaults(): Promise<GlobalDefaults> {
  const cfg = await api.get<{
    dns_servers?: string[];
    ntp_servers?: string[];
    domain_name?: string;
    default_lease_time?: number;
  }>("/api/v1/dhcp/v4/config");
  return {
    dns_servers: Array.isArray(cfg.dns_servers) ? cfg.dns_servers : [],
    ntp_servers: Array.isArray(cfg.ntp_servers) ? cfg.ntp_servers : [],
    domain_name: cfg.domain_name || "",
    default_lease_time: cfg.default_lease_time || 86400,
  };
}

export async function createDhcpSubnet(payload: Record<string, unknown>): Promise<void> {
  await api.post("/api/v1/dhcp/v4/subnets", payload);
}

export async function updateDhcpSubnet(id: string, payload: Record<string, unknown>): Promise<void> {
  await api.put(`/api/v1/dhcp/v4/subnets/${id}`, payload);
}

export async function deleteDhcpSubnet(id: string): Promise<void> {
  await api.delete(`/api/v1/dhcp/v4/subnets/${id}`);
}
