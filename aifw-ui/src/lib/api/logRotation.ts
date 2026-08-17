import { api } from "@/lib/api";

/* ------------------------------- Types ---------------------------------- */

export type LogCompression = "none" | "gzip" | "bzip2" | "xz" | "zstd";

export interface LogRotationConfig {
  /** Rotate a log once it exceeds this many MB (1–500). */
  max_size_mb: number;
  /** Rotated generations to keep (0–50). */
  keep: number;
  compression: LogCompression;
}

/** On-disk state of one AiFw-managed log. */
export interface ManagedLogStatus {
  service: string;
  path: string;
  size_bytes: number | null;
  rotated: number;
  total_bytes: number;
}

export interface LogRotationLimits {
  min_size_mb: number;
  max_size_mb: number;
  max_keep: number;
}

export interface LogRotationView {
  config: LogRotationConfig;
  logs: ManagedLogStatus[];
  conf_path: string;
  limits: LogRotationLimits;
}

export interface RotateResult {
  ok: boolean;
  message: string;
  logs: ManagedLogStatus[];
}

/* ------------------------------ Helpers --------------------------------- */

export const defaultLogRotationConfig: LogRotationConfig = {
  max_size_mb: 5,
  keep: 7,
  compression: "gzip",
};

export const defaultLogRotationLimits: LogRotationLimits = {
  min_size_mb: 1,
  max_size_mb: 500,
  max_keep: 50,
};

export const LOG_COMPRESSIONS: { value: LogCompression; label: string }[] = [
  { value: "gzip", label: "gzip (.gz) — default, universally readable" },
  { value: "zstd", label: "zstd (.zst) — fastest, good ratio" },
  { value: "xz", label: "xz (.xz) — smallest, slowest" },
  { value: "bzip2", label: "bzip2 (.bz2)" },
  { value: "none", label: "None — keep rotated logs uncompressed" },
];

export function formatBytes(b: number | null): string {
  if (b === null) return "—";
  const KB = 1024;
  if (b >= KB * KB * KB) return `${(b / (KB * KB * KB)).toFixed(1)} GB`;
  if (b >= KB * KB) return `${(b / (KB * KB)).toFixed(1)} MB`;
  if (b >= KB) return `${Math.round(b / KB)} KB`;
  return `${b} B`;
}

/* -------------------------------- API ----------------------------------- */

export function getLogRotation(): Promise<LogRotationView> {
  return api.get<LogRotationView>("/api/v1/settings/log-rotation");
}

export function saveLogRotation(config: LogRotationConfig): Promise<LogRotationView> {
  return api.put<LogRotationView>("/api/v1/settings/log-rotation", config);
}

/** Force-rotate one log (by path) or run a normal pass over all of them. */
export function rotateLogs(path?: string): Promise<RotateResult> {
  return api.post<RotateResult>(
    "/api/v1/settings/log-rotation/rotate",
    path ? { path } : {},
  );
}
