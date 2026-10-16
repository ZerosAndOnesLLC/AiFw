import { api } from "@/lib/api";

/* ------------------------------- Types ---------------------------------- */

export type PluginState = "running" | "stopped" | "error";

export type HookPoint =
  | "post_rule"
  | "log_event"
  | "api_request"
  | "vpn_event"
  | "timer"
  | "ids_alert"
  | "gateway_event";

export interface PluginStats {
  events: number;
  actions: number;
  errors: number;
  timeouts: number;
  panics: number;
  last_event_at: string | null;
  avg_latency_us: number;
  last_latency_us: number;
}

export interface PluginSummary {
  name: string;
  title: string;
  version: string;
  description: string;
  author: string;
  hooks: HookPoint[];
  state: PluginState;
  enabled: boolean;
  last_error: string | null;
  started_at: string | null;
  stats: PluginStats;
}

export interface HookInfo {
  id: HookPoint;
  description: string;
}

export interface PluginsResponse {
  plugins: PluginSummary[];
  total: number;
  running: number;
  hooks: HookInfo[];
}

export interface SelectOption {
  value: string;
  label: string;
  help?: string;
}

export type ListItem = "cidr" | "url" | "text";

export type FieldKind =
  | { type: "bool" }
  | { type: "integer"; min: number; max: number }
  | { type: "text"; max_len: number }
  | { type: "url"; https_only: boolean }
  | { type: "select"; options: SelectOption[] }
  | { type: "multi_select"; options: SelectOption[] }
  | { type: "list"; item: ListItem; max_items: number };

export type SettingValue = boolean | number | string | string[] | null;

export interface SettingField {
  key: string;
  label: string;
  help?: string;
  kind: FieldKind;
  default: SettingValue;
  secret: boolean;
  group?: string;
  visible_if?: { key: string; equals: SettingValue };
}

export interface ActionInfo {
  id: string;
  label: string;
  description: string;
  args: SettingField[];
}

export interface PluginDetail extends PluginSummary {
  schema: SettingField[];
  /** Values the operator set (defaults omitted). */
  values: Record<string, SettingValue>;
  /** Operator values over defaults, secrets excluded. */
  effective: Record<string, SettingValue>;
  /** Secret keys that hold a value (values are never returned). */
  secrets_set: string[];
  actions: ActionInfo[];
  rules: string[];
}

export type LogLevel = "info" | "warn" | "error";

export interface LogEntry {
  ts: string;
  level: LogLevel;
  message: string;
}

/* ------------------------------ Helpers --------------------------------- */

export const HOOK_LABELS: Record<HookPoint, string> = {
  post_rule: "pf log",
  log_event: "Audit log",
  api_request: "API requests",
  vpn_event: "VPN state",
  timer: "Timer",
  ids_alert: "IDS alerts",
  gateway_event: "Gateway state",
};

/** "3m ago" / "in 2h" for an ISO timestamp; "—" when absent. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const diff = Math.round((t - now) / 1000);
  const abs = Math.abs(diff);
  const unit =
    abs < 60
      ? `${abs}s`
      : abs < 3600
        ? `${Math.round(abs / 60)}m`
        : abs < 86400
          ? `${Math.round(abs / 3600)}h`
          : `${Math.round(abs / 86400)}d`;
  if (abs < 5) return "just now";
  return diff < 0 ? `${unit} ago` : `in ${unit}`;
}

export function formatLatency(us: number): string {
  if (us <= 0) return "—";
  if (us < 1000) return `${us} µs`;
  return `${(us / 1000).toFixed(1)} ms`;
}

/** Whether a field's `visible_if` condition holds for the current values. */
export function isVisible(field: SettingField, values: Record<string, SettingValue>): boolean {
  if (!field.visible_if) return true;
  return values[field.visible_if.key] === field.visible_if.equals;
}

/* -------------------------------- API ----------------------------------- */

const base = (name: string) => `/api/v1/plugins/${encodeURIComponent(name)}`;

export function listPlugins(): Promise<PluginsResponse> {
  return api.get<PluginsResponse>("/api/v1/plugins");
}

export function getPlugin(name: string): Promise<PluginDetail> {
  return api.get<PluginDetail>(base(name));
}

export function setPluginEnabled(name: string, enabled: boolean): Promise<PluginSummary> {
  return api.put<PluginSummary>(`${base(name)}/enabled`, { enabled });
}

/** Partial update; `null` resets a value to its default / clears a secret. */
export function updatePluginSettings(
  name: string,
  patch: {
    values?: Record<string, SettingValue>;
    secrets?: Record<string, string | null>;
  },
): Promise<PluginDetail> {
  return api.patch<PluginDetail>(`${base(name)}/settings`, {
    values: patch.values ?? {},
    secrets: patch.secrets ?? {},
  });
}

export function resetPlugin(name: string): Promise<PluginSummary> {
  return api.post<PluginSummary>(`${base(name)}/reset`);
}

export function getPluginStatus<T = unknown>(name: string): Promise<T | null> {
  return api.get<T | null>(`${base(name)}/status`);
}

export function getPluginLogs(name: string, level: LogLevel = "info"): Promise<LogEntry[]> {
  return api
    .get<{ entries: LogEntry[] }>(`${base(name)}/logs?limit=200&level=${level}`)
    .then((r) => r.entries);
}

export function runPluginAction(
  name: string,
  action: string,
  args: Record<string, SettingValue> = {},
): Promise<unknown> {
  return api
    .post<{ result: unknown }>(`${base(name)}/actions/${encodeURIComponent(action)}`, args)
    .then((r) => r.result);
}
