import { api } from "@/lib/api";

/* ------------------------------- Types ---------------------------------- */

export type SyslogTransport = "udp" | "tcp";
export type SyslogFormat = "rfc3164" | "rfc5424";
export type SyslogAppLevel = "error" | "warn" | "info" | "debug";

export interface SyslogConfig {
  enabled: boolean;
  host: string;
  port: number;
  transport: SyslogTransport;
  format: SyslogFormat;
  facility: number;
  hostname_override: string;
  pf_enabled: boolean;
  ids_enabled: boolean;
  app_enabled: boolean;
  app_min_level: SyslogAppLevel;
  disable_local: boolean;
}

/** Delivery counters for one AiFw process (aifw-api / aifw-daemon / aifw-ids). */
export interface SyslogProcessStatus {
  process: string;
  sent: number;
  dropped: number;
  errors: number;
  connected: boolean;
  last_error: string | null;
  updated_at: string;
}

export interface SyslogTestResult {
  ok: boolean;
  message: string;
}

/* ------------------------------ Helpers --------------------------------- */

export const defaultSyslogConfig: SyslogConfig = {
  enabled: false,
  host: "",
  port: 514,
  transport: "udp",
  format: "rfc3164",
  facility: 16,
  hostname_override: "",
  pf_enabled: false,
  ids_enabled: false,
  app_enabled: false,
  app_min_level: "info",
  disable_local: false,
};

/** Facility names indexed by facility number 0-23 (same list as the API). */
export const SYSLOG_FACILITIES: string[] = [
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
  "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

/* ----------------------------- HTTP calls ------------------------------- */

export function getSyslogConfig(): Promise<SyslogConfig> {
  return api.get<SyslogConfig>("/api/v1/settings/syslog");
}

export function saveSyslogConfig(cfg: SyslogConfig): Promise<unknown> {
  return api.put("/api/v1/settings/syslog", cfg);
}

/** Sends one test message using `cfg` (which need not be saved yet). */
export function testSyslog(cfg: SyslogConfig): Promise<SyslogTestResult> {
  return api.post<SyslogTestResult>("/api/v1/settings/syslog/test", cfg);
}

export function getSyslogStatus(): Promise<SyslogProcessStatus[]> {
  return api.get<SyslogProcessStatus[]>("/api/v1/settings/syslog/status");
}
