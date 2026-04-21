"use client";

import { useState, useEffect } from "react";

interface SysInfo {
  hostname: string; domain: string;
  os_version: string; kernel: string;
  uptime_secs: number;
  load_avg: [number, number, number];
  cpu_model: string; cpu_count: number; cpu_usage_pct: number;
  mem_total_bytes: number; mem_used_bytes: number;
  disk_total_bytes: number; disk_used_bytes: number;
  temperatures_c: { core: number; celsius: number }[];
}

function authFetch(url: string): Promise<Response> {
  const token = typeof window !== "undefined" ? (localStorage.getItem("aifw_token") || "") : "";
  return fetch(url, { headers: { Authorization: `Bearer ${token}` } });
}

function fmtDuration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtBytes(b: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = b; let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

export default function SystemInfoPage() {
  const [info, setInfo] = useState<SysInfo | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      if (document.visibilityState !== "visible") return;
      try {
        const r = await authFetch("/api/v1/system/info");
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (!cancelled) { setInfo(d); setErr(null); }
      } catch (e) {
        if (!cancelled) setErr(String(e));
      }
    }
    tick();
    const id = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (err) return <div className="p-6 text-red-400">Failed: {err}</div>;
  if (!info) return <div className="p-6 text-[var(--text-muted)]">Loading…</div>;

  const memPct = info.mem_total_bytes ? (info.mem_used_bytes / info.mem_total_bytes) * 100 : 0;
  const diskPct = info.disk_total_bytes ? (info.disk_used_bytes / info.disk_total_bytes) * 100 : 0;

  const tileCls = "bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4";
  const labelCls = "text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1";
  const barCls = "h-2 bg-[var(--bg-input)] rounded mt-2 overflow-hidden";

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-bold">System Info</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className={tileCls}>
          <div className={labelCls}>Identity</div>
          <div className="text-lg font-medium">{info.hostname || "(none)"}<span className="text-[var(--text-muted)]">{info.domain ? `.${info.domain}` : ""}</span></div>
          <div className="text-xs text-[var(--text-muted)] mt-1">{info.os_version}</div>
          <div className="text-xs text-[var(--text-muted)]">{info.kernel}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Uptime</div>
          <div className="text-2xl font-semibold">{fmtDuration(info.uptime_secs)}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Load avg (1 / 5 / 15 m)</div>
          <div className="text-lg font-mono">{info.load_avg.map(n => n.toFixed(2)).join(" / ")}</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>CPU</div>
          <div className="text-sm">{info.cpu_model}</div>
          <div className="text-xs text-[var(--text-muted)] mt-1">{info.cpu_count} cores</div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Memory</div>
          <div className="text-sm">{fmtBytes(info.mem_used_bytes)} / {fmtBytes(info.mem_total_bytes)}</div>
          <div className={barCls}><div style={{ width: `${memPct}%` }} className="h-full bg-[var(--accent)]" /></div>
        </div>
        <div className={tileCls}>
          <div className={labelCls}>Root disk</div>
          <div className="text-sm">{fmtBytes(info.disk_used_bytes)} / {fmtBytes(info.disk_total_bytes)}</div>
          <div className={barCls}><div style={{ width: `${diskPct}%` }} className="h-full bg-[var(--accent)]" /></div>
        </div>
        {info.temperatures_c.length > 0 && (
          <div className={`${tileCls} md:col-span-2 lg:col-span-3`}>
            <div className={labelCls}>CPU Temperatures</div>
            <div className="grid grid-cols-4 md:grid-cols-8 gap-2 mt-2">
              {info.temperatures_c.map(t => (
                <div key={t.core} className="text-sm text-center">
                  <div className="text-xs text-[var(--text-muted)]">Core {t.core}</div>
                  <div className="font-mono">{t.celsius.toFixed(1)}°C</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
