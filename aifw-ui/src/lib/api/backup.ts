import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface ConfigVersion {
  version: number;
  hash: string;
  applied: boolean;
  applied_at: string | null;
  rolled_back: boolean;
  created_by: string;
  created_at: string;
  comment: string | null;
  resource_count: number;
}

export interface ConfigCheck {
  valid: boolean;
  errors: string[];
  warnings: string[];
  info: string[];
}

export interface InterfaceInfo {
  name: string;
  mac: string | null;
  ipv4: string | null;
  ipv6: string | null;
  ipv4_mode: string | null;
  status: string;
}

export interface DropSummary {
  rules: number;
  nat: number;
  wireguard: number;
  carp: number;
  queues: number;
  rate_limits: number;
  pfsync: boolean;
}

/// How the secret fields of a backup file are stored (#313).
export type SecretsState =
  | { state: "plain" }
  | { state: "redacted"; count: number }
  | { state: "passphrase"; count: number };

export interface ImportPreview {
  interfaces_found: string[];
  interfaces_missing: string[];
  interfaces_present: InterfaceInfo[];
  suggestions: Record<string, string>;
  drop_summary_if_unmapped: DropSummary;
  secrets: SecretsState;
  /// Redacted secrets this box cannot fill from its own state.
  unresolved_secrets: string[];
}

export interface DiffSummary {
  v1: number;
  v2: number;
  v1_hash: string;
  v2_hash: string;
  identical: boolean;
  rules_diff: { added: number; removed: number; v1_count: number; v2_count: number };
  nat_diff: { added: number; removed: number; v1_count: number; v2_count: number };
  total_v1: number;
  total_v2: number;
  v1_json: Record<string, unknown>;
  v2_json: Record<string, unknown>;
}

export interface CommitConfirmStatus {
  active: boolean;
  seconds_remaining: number;
  description: string;
}

export interface S3Object {
  key: string;
  size: number;
  last_modified: string | null;
}

/// Raw response of the OPNsense preview endpoint as stored in state.
export type OpnsensePreviewResponse = { interfaces_found?: string[] } & Record<string, unknown>;

/// Structured view of the OPNsense preview response as consumed by the UI.
export type OpnsensePreview = {
  valid: boolean;
  error?: string;
  kind?: string;
  version?: string;
  system?: { hostname?: string; domain?: string; dns_servers?: string[]; timezone?: string };
  counts?: Record<string, number>;
  interfaces_found?: string[];
  interfaces_system?: string[];
  interfaces_need_mapping?: boolean;
  diff?: { alias_name_collisions?: string[]; duplicate_rule_signatures?: number; nat_external_port_collisions?: string[] };
  skipped?: string[];
  plan?: {
    rules?: Array<Record<string, unknown>>;
    nat?: Array<Record<string, unknown>>;
    aliases?: Array<Record<string, unknown>>;
    routes?: Array<Record<string, unknown>>;
  };
};

/* -- Helpers --------------------------------------------------------- */

export function fmtDate(iso: string | null): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

/** Convert a user's mapping choices (UI strings) into the API shape. */
export function buildInterfaceMapForApi(
  preview: ImportPreview,
  uiMap: Record<string, string>,
): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const missing of preview.interfaces_missing) {
    const choice = uiMap[missing] ?? "";
    if (choice === "__drop__") out[missing] = null;
    else if (choice === "__keep__" || choice === "") out[missing] = missing;
    else out[missing] = choice;
  }
  return out;
}

/** Count entries in the uiMap that are set to drop. */
export function countDroppedEntries(preview: ImportPreview, uiMap: Record<string, string>): DropSummary {
  const droppedIfaces = new Set<string>();
  for (const m of preview.interfaces_missing) {
    if ((uiMap[m] ?? "") === "__drop__") droppedIfaces.add(m);
  }
  const s: DropSummary = { rules: 0, nat: 0, wireguard: 0, carp: 0, queues: 0, rate_limits: 0, pfsync: false };
  // The initial API drop_summary was "if everything were dropped". We need the per-choice number.
  // We can't recompute fully without the config; instead show the sum of drop_summary_if_unmapped
  // scaled by whether each missing interface is being dropped. Approximation good enough.
  if (droppedIfaces.size === 0) return s;
  // If ALL missing are being dropped, use the full sum (upper bound).
  if (droppedIfaces.size === preview.interfaces_missing.length) return preview.drop_summary_if_unmapped;
  // Otherwise leave the counts at 0 — the server will report final counts on apply.
  return s;
}

/* -- HTTP calls ------------------------------------------------------ */

export async function fetchConfigHistory(): Promise<ConfigVersion[]> {
  const body = await api.get<{ data?: ConfigVersion[] }>("/api/v1/config/history?limit=10000");
  return body.data || [];
}

export function saveConfigSnapshot(comment: string | null): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/config/save", { comment });
}

export function restoreConfigVersion(
  version: number,
  interface_map: Record<string, string | null>,
): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/config/restore", { version, interface_map });
}

export function fetchRestorePreview(version: number): Promise<ImportPreview> {
  return api.get<ImportPreview>(`/api/v1/config/restore-preview?version=${version}`);
}

export async function fetchConfigDiff(v1: number, v2: number): Promise<DiffSummary> {
  const body = await api.get<{ data: DiffSummary }>(`/api/v1/config/diff?v1=${v1}&v2=${v2}`);
  return body.data;
}

export async function fetchConfigCheck(): Promise<ConfigCheck> {
  const body = await api.get<{ data: ConfigCheck }>("/api/v1/config/check");
  return body.data;
}

/// Redacted export — secret fields replaced by `**REDACTED**`; restorable
/// onto this box only.
export function exportConfig(): Promise<unknown> {
  return api.get<unknown>("/api/v1/config/export");
}

/// Portable export — secret fields wrapped under `passphrase`.
export function exportConfigWithPassphrase(passphrase: string): Promise<unknown> {
  return api.post<unknown>("/api/v1/config/export", { passphrase });
}

export function fetchImportPreview(parsed: unknown): Promise<ImportPreview> {
  return api.post<ImportPreview>("/api/v1/config/import-preview", parsed);
}

/// `payload` is the parsed backup JSON spread together with `interface_map`.
export function importConfig(payload: unknown): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/config/import", payload);
}

export function previewOpnsenseConfig(
  xml: string,
  interface_map: Record<string, string>,
): Promise<OpnsensePreviewResponse> {
  return api.post<OpnsensePreviewResponse>("/api/v1/config/preview-opnsense", { xml, interface_map });
}

export function importOpnsenseConfig(
  xml: string,
  interface_map: Record<string, string>,
  import_system_settings: boolean,
): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/config/import-opnsense", {
    xml,
    interface_map,
    commit_confirm: true,
    import_system_settings,
  });
}

export function fetchCommitConfirmStatus(): Promise<CommitConfirmStatus> {
  return api.get<CommitConfirmStatus>("/api/v1/config/commit-confirm/status");
}

export function confirmCommit(): Promise<{ message: string }> {
  return api.post<{ message: string }>("/api/v1/config/commit-confirm/confirm");
}

export function listS3Archive(): Promise<S3Object[]> {
  return api.get<S3Object[]>("/api/v1/backup/s3/list?max=1000");
}

/// `passphrase` unlocks a passphrase-wrapped object; omitted ⇒ the stored
/// S3 backup passphrase is tried.
export function importS3Object(key: string, passphrase?: string): Promise<{ message?: string; version?: number }> {
  return api.post<{ message?: string; version?: number }>("/api/v1/backup/s3/import", { key, passphrase });
}
