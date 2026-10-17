import { api } from "@/lib/api";

/* ------------------------------- Types ---------------------------------- */

export type GeoIpAction = "block" | "allow";
export type GeoIpStatus = "active" | "disabled";

/** One rule as the API returns it (`GeoIpRuleView`). */
export interface GeoIpRule {
  id: string;
  /** ISO 3166-1 alpha-2 */
  country: string;
  action: GeoIpAction;
  label: string | null;
  status: GeoIpStatus;
  created_at: string;
  updated_at: string;
  /** pf table the rule reads */
  table: string;
  /** Networks the loaded database holds for the country; 0 until a database is loaded */
  cidr_count: number;
}

export interface GeoIpDatabase {
  loaded: boolean;
  countries: number;
  cidrs: number;
  db_path: string;
  source: "maxmind" | "upload" | null;
  updated_at: string | null;
  last_refresh_attempt: string | null;
  last_error: string | null;
  /** 0 = scheduled refresh off */
  update_interval_hours: number;
  next_refresh: string | null;
  has_license_key: boolean;
  /** MaxMind account ID paired with the key (not secret) */
  account_id: string | null;
}

export interface GeoIpLookup {
  ip: string;
  country: string | null;
  network: string | null;
}

export interface RuleInput {
  country: string;
  action: GeoIpAction;
  status?: GeoIpStatus;
  label?: string | null;
}

/** Refresh cadence choices offered in the UI (hours). */
export const REFRESH_OPTIONS: { hours: number; label: string }[] = [
  { hours: 0, label: "Off" },
  { hours: 24, label: "Daily" },
  { hours: 168, label: "Weekly" },
  { hours: 720, label: "Monthly" },
];

/* -------------------------------- API ----------------------------------- */

const BASE = "/api/v1/geoip";

export function listRules(): Promise<GeoIpRule[]> {
  return api.get<{ data: GeoIpRule[] }>(BASE).then((r) => r.data ?? []);
}

export function createRule(input: RuleInput): Promise<GeoIpRule> {
  return api
    .post<{ data: GeoIpRule }>(BASE, {
      country_code: input.country,
      action: input.action,
      status: input.status,
      label: input.label ?? undefined,
    })
    .then((r) => r.data);
}

export function updateRule(id: string, input: RuleInput): Promise<GeoIpRule> {
  return api
    .put<{ data: GeoIpRule }>(`${BASE}/${encodeURIComponent(id)}`, {
      country_code: input.country,
      action: input.action,
      status: input.status,
      label: input.label ?? undefined,
    })
    .then((r) => r.data);
}

export function deleteRule(id: string): Promise<void> {
  return api.delete(`${BASE}/${encodeURIComponent(id)}`).then(() => undefined);
}

export function lookupIp(ip: string): Promise<GeoIpLookup> {
  return api.get<GeoIpLookup>(`${BASE}/lookup/${encodeURIComponent(ip)}`);
}

export function getDatabase(): Promise<GeoIpDatabase> {
  return api.get<GeoIpDatabase>(`${BASE}/database`);
}

/** `license_key: null` / `account_id: null` clear; omit a field to leave it alone. */
export function updateDatabase(patch: {
  license_key?: string | null;
  account_id?: string | null;
  update_interval_hours?: number;
}): Promise<GeoIpDatabase> {
  return api.put<GeoIpDatabase>(`${BASE}/database`, patch);
}

export function refreshDatabase(): Promise<{ cidrs: number; status: GeoIpDatabase }> {
  return api.post(`${BASE}/database/refresh`);
}

/** The MaxMind zip, or the CSV files of a GeoLite2 Country release. */
export function uploadDatabase(files: File[]): Promise<{ cidrs: number; status: GeoIpDatabase }> {
  const form = new FormData();
  for (const f of files) form.append(f.name, f, f.name);
  return api.post(`${BASE}/database/upload`, form);
}
