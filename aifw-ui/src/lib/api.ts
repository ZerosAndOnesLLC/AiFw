const API_BASE = "";

async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("aifw_token");
      window.location.href = "/login";
    }
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Auth
  login: (username: string, password: string) =>
    fetchApi<{ token: string }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  // Status & Apply
  status: () => fetchApi<StatusResponse>("/api/v1/status"),
  metrics: () => fetchApi<MetricsResponse>("/api/v1/metrics"),
  applyChanges: () => fetchApi<{ message: string }>("/api/v1/reload", { method: "POST" }),

  // Rules
  listRules: () => fetchApi<{ data: Rule[] }>("/api/v1/rules"),
  createRule: (rule: CreateRuleRequest) =>
    fetchApi<{ data: Rule }>("/api/v1/rules", { method: "POST", body: JSON.stringify(rule) }),
  updateRule: (id: string, rule: UpdateRuleRequest) =>
    fetchApi<{ data: Rule }>(`/api/v1/rules/${id}`, { method: "PUT", body: JSON.stringify(rule) }),
  deleteRule: (id: string) =>
    fetchApi<{ message: string }>(`/api/v1/rules/${id}`, { method: "DELETE" }),

  // Interfaces
  listInterfaces: () => fetchApi<{ data: InterfaceInfo[] }>("/api/v1/interfaces"),

  // System rules
  listSystemRules: () => fetchApi<{ data: string[] }>("/api/v1/rules/system"),

  // NAT
  listNat: () => fetchApi<{ data: NatRule[] }>("/api/v1/nat"),
  createNat: (rule: CreateNatRequest) =>
    fetchApi<{ data: NatRule }>("/api/v1/nat", { method: "POST", body: JSON.stringify(rule) }),
  updateNat: (id: string, rule: UpdateNatRequest) =>
    fetchApi<{ data: NatRule }>(`/api/v1/nat/${id}`, { method: "PUT", body: JSON.stringify(rule) }),
  deleteNat: (id: string) =>
    fetchApi<{ message: string }>(`/api/v1/nat/${id}`, { method: "DELETE" }),

  // Connections
  listConnections: () => fetchApi<{ data: Connection[] }>("/api/v1/connections"),

  // Logs
  listLogs: () => fetchApi<{ data: AuditEntry[] }>("/api/v1/logs"),

  // Schedules
  listSchedules: () => fetchApi<{ data: Schedule[] }>("/api/v1/schedules"),
  createSchedule: (schedule: CreateScheduleRequest) =>
    fetchApi<{ data: Schedule }>("/api/v1/schedules", { method: "POST", body: JSON.stringify(schedule) }),
  updateSchedule: (id: string, schedule: CreateScheduleRequest) =>
    fetchApi<{ data: Schedule }>(`/api/v1/schedules/${id}`, { method: "PUT", body: JSON.stringify(schedule) }),
  deleteSchedule: (id: string) =>
    fetchApi<{ message: string }>(`/api/v1/schedules/${id}`, { method: "DELETE" }),

  // Reload
  reload: () => fetchApi<{ message: string }>("/api/v1/reload", { method: "POST" }),
};

// Types
export interface StatusResponse {
  pf_running: boolean;
  pf_states: number;
  pf_rules: number;
  aifw_rules: number;
  aifw_active_rules: number;
  nat_rules: number;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
}

export interface MetricsResponse {
  pf_running: boolean;
  pf_states_count: number;
  pf_rules_count: number;
  pf_packets_in: number;
  pf_packets_out: number;
  pf_bytes_in: number;
  pf_bytes_out: number;
  aifw_rules_total: number;
  aifw_rules_active: number;
  aifw_nat_rules_total: number;
}

export interface Rule {
  id: string;
  priority: number;
  action: string;
  direction: string;
  protocol: string;
  ip_version?: string;
  interface?: string;
  rule_match: {
    src_addr: string;
    src_port?: { start: number; end: number };
    src_invert?: boolean;
    dst_addr: string;
    dst_port?: { start: number; end: number };
    dst_invert?: boolean;
  };
  log: boolean;
  quick: boolean;
  label?: string;
  description?: string;
  gateway?: string;
  schedule_id?: string;
  state_options: { tracking: string };
  status: string;
  created_at: string;
}

export interface InterfaceInfo {
  name: string;
  description?: string;
  status?: string;
  ipv4?: string;
  ipv6?: string;
  role?: string;
}

export interface CreateRuleRequest {
  action: string;
  direction: string;
  protocol: string;
  ip_version?: string;
  interface?: string;
  src_addr?: string;
  src_port_start?: number | null;
  src_invert?: boolean;
  dst_addr?: string;
  dst_port_start?: number | null;
  dst_invert?: boolean;
  log?: boolean;
  quick?: boolean;
  label?: string;
  description?: string;
  gateway?: string | null;
  schedule_id?: string | null;
  state_tracking?: string;
  status?: string;
}

export interface UpdateRuleRequest extends CreateRuleRequest {
  status: string;
}

export interface NatRule {
  id: string;
  nat_type: string;
  interface: string;
  protocol: string;
  src_addr: string;
  src_port: { start: number; end: number } | null;
  dst_addr: string;
  dst_port: { start: number; end: number } | null;
  redirect: { address: string; port: { start: number; end: number } | null };
  label: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CreateNatRequest {
  nat_type: string;
  interface: string;
  protocol: string;
  redirect_addr: string;
  src_addr?: string;
  src_port_start?: number;
  src_port_end?: number;
  dst_addr?: string;
  dst_port_start?: number;
  dst_port_end?: number;
  redirect_port_start?: number;
  redirect_port_end?: number;
  label?: string;
  status?: string;
}

export interface UpdateNatRequest extends CreateNatRequest {
  status: string;
}

export interface Connection {
  id: number;
  protocol: string;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  state: string;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
  age_secs: number;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  rule_id?: string;
  details: string;
  source: string;
}

export interface Schedule {
  id: string;
  name: string;
  description?: string;
  time_ranges: string[];
  days_of_week?: string[];
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface CreateScheduleRequest {
  name: string;
  description?: string;
  time_ranges: string[];
  days_of_week?: string[];
  enabled?: boolean;
}
