// Typed API layer for the Settings page (#428). All resource interfaces and
// HTTP calls for the settings/system-config endpoints live here — no React.

import { api } from "@/lib/api";

// ---- DNS Configuration ----

export interface DnsConfig {
  servers?: string[];
}

export function getDnsConfig(): Promise<DnsConfig> {
  return api.get<DnsConfig>("/api/v1/dns");
}

export function saveDnsConfig(servers: string[]): Promise<unknown> {
  return api.put("/api/v1/dns", { servers });
}

// ---- Metrics Storage ----

export interface MetricsSettingsPayload {
  backend: string;
  postgres_url?: string;
  collection_interval: number;
  retention_days: number;
}

export function saveMetricsSettings(body: MetricsSettingsPayload): Promise<unknown> {
  return api.put("/api/v1/settings/metrics", body);
}

// ---- API Server ----

export interface ApiServerSettingsPayload {
  port: number;
  cors_origins: string;
  /** Proxies whose X-Forwarded-For is trusted for the client IP (#308); IPs/CIDRs, comma-separated. */
  trusted_proxies: string;
}

/** Stored under the generic `api_server` section; applied at the next aifw-api restart. */
export function saveApiServerSettings(body: ApiServerSettingsPayload): Promise<unknown> {
  return api.put("/api/v1/settings/api_server", body);
}

export function getApiServerSettings(): Promise<Partial<Record<keyof ApiServerSettingsPayload, string>>> {
  return api.get("/api/v1/settings/api_server");
}

// ---- TLS Policy ----

export interface TlsPolicy {
  min_version?: string;
  block_expired?: boolean;
  block_weak_keys?: boolean;
}

export function getTlsPolicy(): Promise<TlsPolicy> {
  return api.get<TlsPolicy>("/api/v1/settings/tls");
}

export function saveTlsPolicy(body: {
  min_version: string;
  block_expired: boolean;
  block_weak_keys: boolean;
}): Promise<unknown> {
  return api.put("/api/v1/settings/tls", body);
}

// ---- Authentication ----

export interface AuthSettings {
  access_token_expiry_mins?: number;
  require_totp?: boolean;
}

export function getAuthSettings(): Promise<AuthSettings> {
  return api.get<AuthSettings>("/api/v1/auth/settings");
}

export function saveAuthSettings(body: {
  access_token_expiry_mins: number;
  require_totp: boolean;
}): Promise<unknown> {
  return api.put("/api/v1/auth/settings", body);
}

// ---- Valkey / Metrics Persistence ----

export interface ValkeySettings {
  enabled?: boolean;
  url?: string;
  retention_minutes?: number;
  status?: string;
}

export function getValkeySettings(): Promise<ValkeySettings> {
  return api.get<ValkeySettings>("/api/v1/settings/valkey");
}

export function saveValkeySettings(body: {
  enabled: boolean;
  url: string;
  retention_minutes: number;
}): Promise<{ status?: string }> {
  return api.put<{ status?: string }>("/api/v1/settings/valkey", body);
}

// ---- Dashboard History ----

export type HistoryMode = "duration" | "ram";

export interface DashboardHistorySettings {
  mode?: string;
  history_seconds?: number;
  current_entries?: number;
  estimated_ram_mb?: number;
  ram_limit_mb?: number;
}

export type DashboardHistoryPayload =
  | { mode: "ram"; ram_limit_mb: number }
  | { mode: "duration"; history_seconds: number };

export function getDashboardHistorySettings(): Promise<DashboardHistorySettings> {
  return api.get<DashboardHistorySettings>("/api/v1/settings/dashboard-history");
}

export function saveDashboardHistorySettings(
  body: DashboardHistoryPayload,
): Promise<{ estimated_ram_mb?: number; history_seconds?: number }> {
  return api.put<{ estimated_ram_mb?: number; history_seconds?: number }>(
    "/api/v1/settings/dashboard-history",
    body,
  );
}

// ---- pf state-table tuning ----

export interface PfTuningSettings {
  configured_max_states?: number;
  live_max_states?: number;
  current_states?: number;
  min_states?: number;
  max_states?: number;
}

export function getPfTuning(): Promise<PfTuningSettings> {
  return api.get<PfTuningSettings>("/api/v1/settings/pf-tuning");
}

export function savePfTuning(
  maxStates: number,
): Promise<{ configured_max_states: number; live_max_states: number | null }> {
  return api.put<{ configured_max_states: number; live_max_states: number | null }>(
    "/api/v1/settings/pf-tuning",
    { max_states: maxStates },
  );
}

// ---- Config History (auto-snapshots) ----

export interface ConfigRetention {
  max_versions?: number;
  current_count?: number;
}

export function getConfigRetention(): Promise<ConfigRetention> {
  return api.get<ConfigRetention>("/api/v1/config/retention");
}

export function saveConfigRetention(maxVersions: number): Promise<ConfigRetention> {
  return api.put<ConfigRetention>("/api/v1/config/retention", { max_versions: maxVersions });
}

// ---- S3 Backup Sync ----

export interface S3Config {
  enabled?: boolean;
  bucket?: string;
  region?: string;
  endpoint?: string;
  prefix?: string;
  path_style?: boolean;
  access_key_id?: string;
  has_secret?: boolean;
  /// Uploads wrap secrets under a stored passphrase (#313); false ⇒ redacted.
  has_secrets_passphrase?: boolean;
}

export type S3ConfigPayload = Record<string, unknown>;

/// Shape of the UI state derived from a connectivity test.
export interface S3TestResult {
  ok: boolean;
  message: string;
  write: boolean;
  read: boolean;
  delete: boolean;
}

export interface S3TestResponse {
  ok?: boolean;
  message?: string;
  write?: boolean;
  read?: boolean;
  delete?: boolean;
}

export function getS3Config(): Promise<S3Config> {
  return api.get<S3Config>("/api/v1/backup/s3/config");
}

export function saveS3Config(
  payload: S3ConfigPayload,
): Promise<{ has_secret?: boolean; has_secrets_passphrase?: boolean }> {
  return api.put<{ has_secret?: boolean; has_secrets_passphrase?: boolean }>("/api/v1/backup/s3/config", payload);
}

export function testS3Config(payload: S3ConfigPayload): Promise<S3TestResponse> {
  return api.post<S3TestResponse>("/api/v1/backup/s3/test", payload);
}

// ---- SMTP notifications ----

export type SmtpTls = "none" | "starttls" | "implicit";

export interface SmtpConfig {
  enabled?: boolean;
  host?: string;
  port?: number | string;
  tls?: string;
  username?: string;
  has_password?: boolean;
  from_address?: string;
  recipients?: string;
  enabled_events?: string[];
}

export type SmtpConfigPayload = Record<string, unknown>;

export function getSmtpConfig(): Promise<SmtpConfig> {
  return api.get<SmtpConfig>("/api/v1/notify/smtp/config");
}

export function saveSmtpConfig(payload: SmtpConfigPayload): Promise<{ has_password?: boolean }> {
  return api.put<{ has_password?: boolean }>("/api/v1/notify/smtp/config", payload);
}

export function testSmtpConfig(payload: SmtpConfigPayload): Promise<{ ok?: boolean; message?: string }> {
  return api.post<{ ok?: boolean; message?: string }>("/api/v1/notify/smtp/test", payload);
}

// ---- IDS Alert Buffer ----

export interface IdsAlertStats {
  count: number;
  estimated_mb: number;
  max_mb: number;
  usage_pct: number;
  oldest: string | null;
  newest: string | null;
  by_classification: { classification: string; count: number }[];
}

export interface IdsAlertSettings {
  max_mb?: number;
  max_age_secs?: number;
  stats?: IdsAlertStats;
}

export function getIdsAlertSettings(): Promise<IdsAlertSettings> {
  return api.get<IdsAlertSettings>("/api/v1/settings/ids-alerts");
}

export function saveIdsAlertSettings(
  maxMb: number,
  maxAgeSecs: number,
): Promise<{ stats?: IdsAlertStats }> {
  return api.put<{ stats?: IdsAlertStats }>("/api/v1/settings/ids-alerts", {
    max_mb: maxMb,
    max_age_secs: maxAgeSecs,
  });
}

// ---- AI / LLM Providers ----

export interface AiProviderConfig {
  provider: string;
  enabled: boolean;
  api_key_set: boolean;
  endpoint: string;
  model: string;
  tls_insecure?: boolean;
}

export interface AiSettings {
  enabled?: boolean;
  active_provider?: string;
  providers?: AiProviderConfig[];
}

export interface AiTestResult {
  success: boolean;
  status_code: string;
}

export function getAiSettings(): Promise<AiSettings> {
  return api.get<AiSettings>("/api/v1/settings/ai");
}

export function saveAiSettings(body: Record<string, unknown>): Promise<unknown> {
  return api.put("/api/v1/settings/ai", body);
}

export function getAiModels(provider: string): Promise<{ models?: string[] }> {
  return api.get<{ models?: string[] }>(`/api/v1/settings/ai/models?provider=${provider}`);
}

export function testAiConnection(body: Record<string, unknown>): Promise<AiTestResult> {
  return api.post<AiTestResult>("/api/v1/settings/ai/test", body);
}

// ---- System General ----

export interface SystemGeneral {
  hostname?: string;
  domain?: string;
  timezone?: string;
}

export function getSystemGeneral(): Promise<SystemGeneral> {
  return api.get<SystemGeneral>("/api/v1/system/general");
}

export function saveSystemGeneral(body: {
  hostname: string;
  domain: string;
  timezone: string;
}): Promise<{ warning?: string }> {
  return api.put<{ warning?: string }>("/api/v1/system/general", body);
}

export function getTimezones(): Promise<string[]> {
  return api.get<string[]>("/api/v1/system/timezones");
}

// ---- System Banner ----

export interface SystemBanner {
  login_banner?: string;
  motd?: string;
}

export function getSystemBanner(): Promise<SystemBanner> {
  return api.get<SystemBanner>("/api/v1/system/banner");
}

export function saveSystemBanner(body: { login_banner: string; motd: string }): Promise<unknown> {
  return api.put("/api/v1/system/banner", body);
}

// ---- System SSH ----

export interface SystemSsh {
  enabled?: boolean;
  port?: number;
  password_auth?: boolean;
  permit_root_login?: boolean;
}

export function getSystemSsh(): Promise<SystemSsh> {
  return api.get<SystemSsh>("/api/v1/system/ssh");
}

export function saveSystemSsh(body: {
  enabled: boolean;
  port: number;
  password_auth: boolean;
  permit_root_login: boolean;
}): Promise<unknown> {
  return api.put("/api/v1/system/ssh", body);
}

// ---- System Console ----

export type ConsoleKind = "video" | "serial" | "dual";

export interface SystemConsole {
  kind?: ConsoleKind;
  baud?: number;
}

export function getSystemConsole(): Promise<SystemConsole> {
  return api.get<SystemConsole>("/api/v1/system/console");
}

export function saveSystemConsole(body: { kind: ConsoleKind; baud: number }): Promise<unknown> {
  return api.put("/api/v1/system/console", body);
}

// ---- System Actions ----

export function rebootSystem(): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/updates/reboot");
}
