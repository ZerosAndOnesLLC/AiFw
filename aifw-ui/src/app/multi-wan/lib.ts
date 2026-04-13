// Shared helpers for Multi-WAN UI pages.

export function authHeaders(): HeadersInit {
  const token = (typeof window !== "undefined" && localStorage.getItem("aifw_token")) || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

export async function api<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: authHeaders(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `${method} ${path} → ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface RoutingInstance {
  id: string;
  name: string;
  fib_number: number;
  mgmt_reachable: boolean;
  description?: string | null;
  status?: string;
}

export interface InstanceMember {
  instance_id: string;
  interface: string;
}

export interface Gateway {
  id: string;
  name: string;
  instance_id: string;
  interface: string;
  next_hop: string;
  state: string;
  enabled: boolean;
  weight: number;
}

export interface GatewayGroup {
  id: string;
  name: string;
  policy: string;
  preempt: boolean;
  sticky: string;
  hysteresis_ms: number;
  kill_states_on_failover: boolean;
}

export interface GroupMember {
  group_id: string;
  gateway_id: string;
  tier: number;
  weight: number;
}

export interface PolicyRule {
  id: string;
  priority: number;
  name: string;
  status: string;
  ip_version: string;
  iface_in: string | null;
  src_addr: string;
  dst_addr: string;
  src_port: string | null;
  dst_port: string | null;
  protocol: string;
  action_kind: string;
  target_id: string;
  sticky: string;
  description: string | null;
}

export interface RouteLeak {
  id: string;
  name: string;
  src_instance_id: string;
  dst_instance_id: string;
  prefix: string;
  protocol: string;
  ports: string | null;
  direction: string;
  enabled: boolean;
}

export interface FlowSummary {
  id: number;
  protocol: string;
  src: string;
  dst: string;
  iface: string | null;
  rtable: number | null;
  bytes: number;
  age_secs: number;
}

// Field-level validation helpers
export function validateName(v: string): string | null {
  if (!v.trim()) return "required";
  if (v.length > 64) return "max 64 chars";
  if (!/^[A-Za-z0-9][A-Za-z0-9_\-]*$/.test(v))
    return "letters, digits, _ and - only; must start with alphanumeric";
  return null;
}

export function validateCidr(v: string): string | null {
  if (!v.trim()) return "required";
  if (v === "any") return null;
  // Simple CIDR/IP check (v4 or v6)
  const re = /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$|^[0-9a-fA-F:]+(\/[0-9]{1,3})?$/;
  if (!re.test(v)) return "invalid IP or CIDR";
  return null;
}

export function validatePortSpec(v: string): string | null {
  if (!v.trim()) return null; // optional
  // Accept: 80, 80:443, "80,443", "!80" (negation), etc.
  if (!/^[0-9:,\s!]+$/.test(v)) return "digits, colon, comma only";
  return null;
}

export function validateIpOrHost(v: string): string | null {
  if (!v.trim()) return "required";
  if (v.length > 253) return "too long";
  return null;
}

export function validateInterface(v: string): string | null {
  if (!v.trim()) return "required";
  if (!/^[a-z][a-z0-9_.]*[0-9]*$/i.test(v)) return "invalid interface name";
  return null;
}

export function validateFib(v: number, max: number): string | null {
  if (!Number.isInteger(v)) return "integer required";
  if (v < 0) return "must be ≥ 0";
  if (v >= max) return `must be < ${max}`;
  return null;
}

export function validatePriority(v: number): string | null {
  if (!Number.isInteger(v)) return "integer required";
  if (v < 1 || v > 65535) return "1–65535";
  return null;
}

export function validateWeight(v: number): string | null {
  if (!Number.isInteger(v)) return "integer required";
  if (v < 1 || v > 255) return "1–255";
  return null;
}
