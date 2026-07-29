"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import {
  SYSLOG_FACILITIES,
  SyslogAppLevel,
  SyslogConfig,
  SyslogFormat,
  SyslogProcessStatus,
  SyslogTransport,
} from "@/lib/api/syslog";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface SyslogSectionProps {
  visible: boolean;
  config: SyslogConfig;
  setConfig: Dispatch<SetStateAction<SyslogConfig>>;
  status: SyslogProcessStatus[] | null;
  refreshStatus: () => void;
  loading: boolean;
  saving: boolean;
  testing: boolean;
  feedback: Feedback | null;
  save: () => void;
  test: () => void;
}

function Toggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <label className="flex items-start gap-2 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 accent-[var(--accent)]"
      />
      <span className="text-sm text-[var(--text-primary)]">
        {label}
        {hint && (
          <span className="block text-[11px] text-[var(--text-muted)]">{hint}</span>
        )}
      </span>
    </label>
  );
}

export function SyslogSection({
  visible,
  config,
  setConfig,
  status,
  refreshStatus,
  loading,
  saving,
  testing,
  feedback,
  save,
  test,
}: SyslogSectionProps) {
  if (!visible) return null;

  const set = (patch: Partial<SyslogConfig>) =>
    setConfig((c) => ({ ...c, ...patch }));

  return (
    <section className={sectionCls}>
      <h2 className="text-base font-semibold mb-1">Remote Logging (Syslog)</h2>
      <p className="text-xs text-[var(--text-muted)] mb-4">
        Forward firewall, IDS, and application logs to a central syslog server / SIEM.
      </p>

      <div className="space-y-4">
        <FeedbackBanner feedback={feedback} />

        <Toggle
          checked={config.enabled}
          onChange={(v) => set({ enabled: v })}
          label="Enable remote syslog server"
          hint="Master switch — nothing is forwarded while this is off."
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>Server Host</label>
            <input
              type="text"
              value={config.host}
              onChange={(e) => set({ host: e.target.value })}
              placeholder="e.g. 192.168.1.10 or syslog.example.com"
              className={inputCls}
              disabled={loading}
            />
          </div>
          <div>
            <label className={labelCls}>Port</label>
            <input
              type="number"
              min={1}
              max={65535}
              value={config.port === 0 ? "" : config.port}
              onChange={(e) =>
                set({ port: e.target.value === "" ? 0 : Number(e.target.value) || 0 })
              }
              className={inputCls}
              disabled={loading}
            />
          </div>
          <div>
            <label className={labelCls}>Transport</label>
            <select
              value={config.transport}
              onChange={(e) => set({ transport: e.target.value as SyslogTransport })}
              className={inputCls}
            >
              <option value="udp">UDP (classic, fire-and-forget)</option>
              <option value="tcp">TCP (reliable, reconnects)</option>
            </select>
          </div>
          <div>
            <label className={labelCls}>Format</label>
            <select
              value={config.format}
              onChange={(e) => set({ format: e.target.value as SyslogFormat })}
              className={inputCls}
            >
              <option value="rfc3164">BSD (RFC 3164) — broadest compatibility</option>
              <option value="rfc5424">RFC 5424 — modern structured receivers</option>
            </select>
          </div>
          <div>
            <label className={labelCls}>Facility</label>
            <select
              value={config.facility}
              onChange={(e) => set({ facility: Number(e.target.value) })}
              className={inputCls}
            >
              {SYSLOG_FACILITIES.map((name, num) => (
                <option key={num} value={num}>
                  {name} ({num})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={labelCls}>Hostname Override</label>
            <input
              type="text"
              value={config.hostname_override}
              onChange={(e) => set({ hostname_override: e.target.value })}
              placeholder="(system hostname)"
              className={inputCls}
            />
          </div>
        </div>

        <div>
          <label className={labelCls}>Forwarded Categories</label>
          <div className="space-y-2 mt-1">
            <Toggle
              checked={config.pf_enabled}
              onChange={(v) => set({ pf_enabled: v })}
              label="Firewall (pf) packet logs"
              hint="Blocked traffic is always logged; passed traffic only for rules with the Log flag set."
            />
            <Toggle
              checked={config.ids_enabled}
              onChange={(v) => set({ ids_enabled: v })}
              label="IDS alerts"
            />
            <div className="flex flex-wrap items-center gap-3">
              <Toggle
                checked={config.app_enabled}
                onChange={(v) => set({ app_enabled: v })}
                label="Application logs (API, daemon, IDS engine)"
              />
              {config.app_enabled && (
                <select
                  value={config.app_min_level}
                  onChange={(e) => set({ app_min_level: e.target.value as SyslogAppLevel })}
                  className="px-2 py-1 text-xs bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)]"
                  aria-label="Minimum app log level"
                >
                  <option value="error">error and above</option>
                  <option value="warn">warn and above</option>
                  <option value="info">info and above</option>
                  <option value="debug">debug and above</option>
                </select>
              )}
            </div>
          </div>
        </div>

        <div className="border-t border-[var(--border)] pt-4">
          <Toggle
            checked={config.disable_local}
            onChange={(v) => set({ disable_local: v })}
            label="Stop storing logs locally while forwarding"
            hint="Only applies to categories that are actually being forwarded, so logs are never lost from both destinations: with pf forwarding on, the local pf log file stops (Blocked-page history becomes memory-only); with app-log forwarding on, the /var/log/aifw files stop growing (forwarded levels only). IDS alerts always stay in the local database for the Alerts page."
          />
        </div>

        {status && status.length > 0 && (
          <div className="space-y-1 text-xs text-[var(--text-muted)] bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2">
            <div className="flex items-center">
              <span className="font-medium text-[var(--text-primary)]">Delivery by process</span>
              <button
                onClick={refreshStatus}
                className="ml-auto text-[var(--accent)] hover:underline"
              >
                Refresh
              </button>
            </div>
            {status.map((p) => (
              <div key={p.process} className="flex flex-wrap items-center gap-x-4 gap-y-0.5">
                <span className="w-28 font-mono text-[var(--text-primary)]">{p.process}</span>
                <span>sent {p.sent}</span>
                <span>dropped {p.dropped}</span>
                <span>errors {p.errors}</span>
                <span className={p.connected ? "text-green-400" : "text-[var(--text-muted)]"}>
                  {p.connected ? "connected" : "not connected"}
                </span>
                {p.last_error && (
                  <span className="text-red-400 truncate max-w-full" title={p.last_error}>
                    last error: {p.last_error}
                  </span>
                )}
              </div>
            ))}
            <p className="text-[10px] text-[var(--text-muted)]">
              Daemon/IDS rows refresh on their 60s poll; the API row is live.
            </p>
          </div>
        )}

        <div className="flex items-center gap-3">
          <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
            {saving ? "Saving..." : "Save Syslog Settings"}
          </button>
          <button
            onClick={test}
            disabled={testing || loading}
            className="px-5 py-2 bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border)] text-[var(--text-primary)] rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            title="Sends one test message using the values in the form (works before saving)"
          >
            {testing ? "Sending..." : "Send Test Message"}
          </button>
          <span className="text-[11px] text-[var(--text-muted)]">
            Other services apply changes within 60 seconds.
          </span>
        </div>
      </div>
    </section>
  );
}
