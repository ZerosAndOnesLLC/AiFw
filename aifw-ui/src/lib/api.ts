const API_BASE = "";
const TOKEN_KEY = "aifw_token";

/// Error thrown for any non-2xx response. `message` carries the
/// server-provided error/message body field when one exists, so call
/// sites can show it directly: `err instanceof Error ? err.message : ...`.
export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export interface RequestOptions {
  /// Skip the automatic token-clear + redirect to /login on 401.
  /// Needed by the login/TOTP flow, where 401 means "bad credentials".
  noAuthRedirect?: boolean;
  /// Extra headers merged over the defaults.
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

function authToken(): string | null {
  return typeof window !== "undefined" ? localStorage.getItem(TOKEN_KEY) : null;
}

/// Pull a human-readable message out of an error response. The API mostly
/// returns `{ "error": ... }` or `{ "message": ... }` JSON bodies.
async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.clone().json();
    if (body && typeof body === "object") {
      const m = (body as Record<string, unknown>).error ?? (body as Record<string, unknown>).message;
      if (typeof m === "string" && m) return m;
    }
  } catch {
    /* not JSON */
  }
  try {
    const text = await res.text();
    if (text && text.length <= 512) return text;
  } catch {
    /* unreadable body */
  }
  return `API ${res.status}: ${res.statusText || "request failed"}`;
}

/// Core request: attaches the Bearer token, JSON-encodes plain bodies
/// (FormData passes through untouched so the browser sets the multipart
/// boundary), centralizes the 401 → /login redirect, and throws ApiError
/// with the server's error message on any non-2xx status.
async function request(
  method: string,
  path: string,
  body?: unknown,
  opts: RequestOptions = {},
): Promise<Response> {
  const token = authToken();
  const isForm = typeof FormData !== "undefined" && body instanceof FormData;
  // Strings are passed through as-is (already-serialized JSON from legacy
  // fetchApi callers); FormData passes through so the browser sets the
  // multipart boundary; anything else is JSON-encoded.
  const rawBody: BodyInit | undefined = isForm
    ? (body as FormData)
    : typeof body === "string"
      ? body
      : body !== undefined
        ? JSON.stringify(body)
        : undefined;
  const headers: Record<string, string> = {
    ...(body !== undefined && !isForm ? { "Content-Type": "application/json" } : {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(opts.headers ?? {}),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: rawBody,
    signal: opts.signal,
  });

  if (!res.ok) {
    if (res.status === 401 && !opts.noAuthRedirect && typeof window !== "undefined") {
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = "/login";
    }
    throw new ApiError(res.status, await errorMessage(res));
  }
  return res;
}

/// Parse a JSON body, tolerating empty responses (204 / empty 200).
async function parseJson<T>(res: Response): Promise<T> {
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/// Back-compat JSON wrapper used by the named `api.*` methods below.
/// Prefer the `api.get/post/...` verbs for new code (#429).
export async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await request(options?.method ?? "GET", path, options?.body ?? undefined, {});
  return parseJson<T>(res);
}

export const api = {
  // ---- Generic verbs (#429): the one true way to call the API. ----
  get: <T>(path: string, opts?: RequestOptions) =>
    request("GET", path, undefined, opts).then((r) => parseJson<T>(r)),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    request("POST", path, body, opts).then((r) => parseJson<T>(r)),
  put: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    request("PUT", path, body, opts).then((r) => parseJson<T>(r)),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) =>
    request("PATCH", path, body, opts).then((r) => parseJson<T>(r)),
  delete: <T>(path: string, opts?: RequestOptions) =>
    request("DELETE", path, undefined, opts).then((r) => parseJson<T>(r)),
  // Raw-body variants for PEM/config exports and file downloads.
  getText: (path: string, opts?: RequestOptions) =>
    request("GET", path, undefined, opts).then((r) => r.text()),
  postText: (path: string, body?: unknown, opts?: RequestOptions) =>
    request("POST", path, body, opts).then((r) => r.text()),
  getBlob: (path: string, opts?: RequestOptions) =>
    request("GET", path, undefined, opts).then((r) => r.blob()),
  postBlob: (path: string, body?: unknown, opts?: RequestOptions) =>
    request("POST", path, body, opts).then((r) => r.blob()),
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

  // WebSocket / SSE auth: issues a 30-second single-use ticket so browser
  // WS/EventSource (neither of which supports custom headers) can avoid
  // putting the JWT itself in the URL.
  wsTicket: () =>
    fetchApi<{ ticket: string; expires_in_seconds: number }>(
      "/api/v1/auth/ws-ticket",
      { method: "POST" },
    ),
};

/// Fetch a ticket and return just the ID. Throws if the user is logged
/// out or the API rejects the request.
export async function getWsTicket(): Promise<string> {
  const { ticket } = await api.wsTicket();
  return ticket;
}

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
