"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import {
  LOG_COMPRESSIONS,
  LogCompression,
  LogRotationConfig,
  LogRotationLimits,
  ManagedLogStatus,
  formatBytes,
} from "@/lib/api/logRotation";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface LogRotationSectionProps {
  visible: boolean;
  config: LogRotationConfig;
  setConfig: Dispatch<SetStateAction<LogRotationConfig>>;
  limits: LogRotationLimits;
  logs: ManagedLogStatus[];
  confPath: string;
  loading: boolean;
  saving: boolean;
  rotating: string | "all" | null;
  feedback: Feedback | null;
  refresh: () => void;
  save: () => void;
  rotate: (path?: string) => void;
}

const secondaryBtnCls =
  "px-3 py-1.5 bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border)] text-[var(--text-primary)] rounded-md text-xs font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

export function LogRotationSection({
  visible,
  config,
  setConfig,
  limits,
  logs,
  confPath,
  loading,
  saving,
  rotating,
  feedback,
  refresh,
  save,
  rotate,
}: LogRotationSectionProps) {
  if (!visible) return null;

  const set = (patch: Partial<LogRotationConfig>) =>
    setConfig((c) => ({ ...c, ...patch }));

  const sizeOk =
    config.max_size_mb >= limits.min_size_mb && config.max_size_mb <= limits.max_size_mb;
  const keepOk = config.keep >= 0 && config.keep <= limits.max_keep;
  const totalBytes = logs.reduce((n, l) => n + l.total_bytes, 0);
  const overLimit = (l: ManagedLogStatus) =>
    l.size_bytes !== null && l.size_bytes > config.max_size_mb * 1024 * 1024;

  return (
    <section className={sectionCls}>
      <h2 className="text-base font-semibold mb-1">Log Rotation</h2>
      <p className="text-xs text-[var(--text-muted)] mb-4">
        One policy for every AiFw service log (API, daemon, IDS, watchdog, rDNS, rDHCP,
        rTIME, TrafficCop). Applied through FreeBSD&apos;s <code>newsyslog</code>, which
        cron runs hourly; the log is checked against the size limit on each pass.
      </p>

      <div className="space-y-4">
        <FeedbackBanner feedback={feedback} />

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className={labelCls}>Rotate above (MB)</label>
            <input
              type="number"
              min={limits.min_size_mb}
              max={limits.max_size_mb}
              value={config.max_size_mb}
              onChange={(e) => set({ max_size_mb: Number(e.target.value) || 0 })}
              className={inputCls}
              disabled={loading}
            />
            <p className="text-[11px] text-[var(--text-muted)] mt-1">
              {limits.min_size_mb}–{limits.max_size_mb} MB per live log file.
            </p>
          </div>
          <div>
            <label className={labelCls}>Keep</label>
            <input
              type="number"
              min={0}
              max={limits.max_keep}
              value={config.keep}
              onChange={(e) => set({ keep: Number(e.target.value) || 0 })}
              className={inputCls}
              disabled={loading}
            />
            <p className="text-[11px] text-[var(--text-muted)] mt-1">
              Rotated generations retained (0–{limits.max_keep}). 0 = truncate only.
            </p>
          </div>
          <div>
            <label className={labelCls}>Compression</label>
            <select
              value={config.compression}
              onChange={(e) => set({ compression: e.target.value as LogCompression })}
              className={inputCls}
              disabled={loading}
            >
              {LOG_COMPRESSIONS.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-[var(--text-muted)] mt-1">
              Worst case on disk ≈ {config.max_size_mb} MB × {config.keep + 1} × {logs.length || 8} logs
              before compression.
            </p>
          </div>
        </div>

        <div className="text-xs text-[var(--text-muted)] bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2">
          <div className="flex items-center mb-1.5">
            <span className="font-medium text-[var(--text-primary)]">
              Managed logs
              {logs.length > 0 && (
                <span className="font-normal text-[var(--text-muted)]">
                  {" "}· {formatBytes(totalBytes)} on disk
                </span>
              )}
            </span>
            <div className="ml-auto flex items-center gap-3">
              <button onClick={refresh} className="text-[var(--accent)] hover:underline">
                Refresh
              </button>
              <button
                onClick={() => rotate()}
                disabled={rotating !== null || loading}
                className={secondaryBtnCls}
                title="Run one newsyslog pass now — rotates any log currently over its limit"
              >
                {rotating === "all" ? "Rotating…" : "Rotate over-limit now"}
              </button>
            </div>
          </div>
          {logs.length === 0 ? (
            <p>{loading ? "Loading…" : "No log status available."}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  <tr>
                    <th className="text-left py-1 pr-3 font-medium">Service</th>
                    <th className="text-left py-1 pr-3 font-medium">Log</th>
                    <th className="text-right py-1 pr-3 font-medium">Size</th>
                    <th className="text-right py-1 pr-3 font-medium">Rotated</th>
                    <th className="text-right py-1 pr-3 font-medium">Total</th>
                    <th className="py-1" />
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.path} className="border-t border-[var(--border)]">
                      <td className="py-1 pr-3 text-[var(--text-primary)]">{l.service}</td>
                      <td className="py-1 pr-3 font-mono">{l.path}</td>
                      <td
                        className={`py-1 pr-3 text-right tabular-nums ${
                          overLimit(l) ? "text-yellow-400" : ""
                        }`}
                        title={overLimit(l) ? "Over the size limit — will rotate on the next pass" : undefined}
                      >
                        {formatBytes(l.size_bytes)}
                      </td>
                      <td className="py-1 pr-3 text-right tabular-nums">{l.rotated}</td>
                      <td className="py-1 pr-3 text-right tabular-nums">{formatBytes(l.total_bytes)}</td>
                      <td className="py-1 text-right">
                        <button
                          onClick={() => rotate(l.path)}
                          disabled={rotating !== null || loading || l.size_bytes === null}
                          className="text-[var(--accent)] hover:underline disabled:opacity-40 disabled:no-underline"
                          title="Force-rotate this log now, regardless of size"
                        >
                          {rotating === l.path ? "Rotating…" : "Rotate now"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {confPath && (
            <p className="text-[10px] text-[var(--text-muted)] mt-1.5">
              Rendered to <code>{confPath}</code>. TrafficCop&apos;s access log is not managed
              here — TrafficCop keeps it open itself.
            </p>
          )}
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={save}
            disabled={saving || loading || !sizeOk || !keepOk}
            className={saveBtnCls}
          >
            {saving ? "Saving..." : "Save Log Rotation"}
          </button>
          {(!sizeOk || !keepOk) && (
            <span className="text-[11px] text-red-400">
              {!sizeOk
                ? `Size must be ${limits.min_size_mb}–${limits.max_size_mb} MB.`
                : `Keep must be 0–${limits.max_keep}.`}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}
