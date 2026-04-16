"use client";

import { useEffect, useMemo, useState, useCallback } from "react";

type Range = { label: string; secs: number };
const RANGES: Range[] = [
  { label: "30m", secs: 1_800 },
  { label: "6h",  secs: 21_600 },
  { label: "24h", secs: 86_400 },
  { label: "7d",  secs: 604_800 },
  { label: "30d", secs: 2_592_000 },
];

interface SeriesPoint { t: number; v: number; min: number; max: number; }
interface SeriesResponse {
  name: string;
  tier: string;
  interval_secs: number;
  points: SeriesPoint[];
}

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Human-friendly metric value formatter. Picks units by magnitude. */
function fmtValue(v: number, name: string): string {
  if (name.includes("bps")) {
    if (v >= 1e9) return `${(v / 1e9).toFixed(2)} Gbps`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(2)} Mbps`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)} Kbps`;
    return `${v.toFixed(0)} bps`;
  }
  if (name.includes("pps")) {
    if (v >= 1e6) return `${(v / 1e6).toFixed(2)} Mpps`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)} Kpps`;
    return `${v.toFixed(0)} pps`;
  }
  if (name.includes("bytes")) {
    if (v >= 1e9) return `${(v / 1e9).toFixed(2)} GB`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(1)} MB`;
    if (v >= 1e3) return `${(v / 1e3).toFixed(1)} KB`;
    return `${v.toFixed(0)} B`;
  }
  if (Math.abs(v) >= 1_000_000) return v.toExponential(2);
  if (Number.isInteger(v)) return v.toLocaleString();
  return v.toFixed(2);
}

function fmtTimeTick(epochSec: number, rangeSecs: number): string {
  const d = new Date(epochSec * 1000);
  if (rangeSecs <= 21_600) { // ≤ 6h — HH:MM:SS
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  if (rangeSecs <= 86_400) { // ≤ 24h — HH:MM
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "2-digit" });
}

function Chart({ data, rangeSecs }: { data: SeriesResponse; rangeSecs: number }) {
  const w = 900;
  const h = 280;
  const pad = { top: 12, right: 16, bottom: 28, left: 64 };
  const plotW = w - pad.left - pad.right;
  const plotH = h - pad.top - pad.bottom;

  const pts = data.points;
  if (pts.length === 0) {
    return <div className="h-[280px] flex items-center justify-center text-sm text-gray-500">No data for this metric yet.</div>;
  }

  const tMin = pts[0].t;
  const tMax = pts[pts.length - 1].t;
  const tSpan = Math.max(1, tMax - tMin);
  // Y domain from combined mean+max so the max overlay fits
  const yMaxRaw = Math.max(...pts.map(p => Math.max(p.v, p.max)));
  const yMinRaw = Math.min(...pts.map(p => Math.min(p.v, p.min)));
  const yPad = (yMaxRaw - yMinRaw) * 0.08 || Math.max(1, yMaxRaw * 0.08);
  const yMax = yMaxRaw + yPad;
  const yMin = Math.min(0, yMinRaw - yPad * 0.3);
  const ySpan = Math.max(1e-9, yMax - yMin);

  const x = (t: number) => pad.left + ((t - tMin) / tSpan) * plotW;
  const y = (v: number) => pad.top + (1 - (v - yMin) / ySpan) * plotH;

  const meanPath = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(" ");
  const maxPath  = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${x(p.t).toFixed(1)} ${y(p.max).toFixed(1)}`).join(" ");

  // Grid: 4 y-ticks, 5 x-ticks
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(f => yMin + f * ySpan);
  const xTicks = Array.from({ length: 5 }, (_, i) => tMin + (i / 4) * tSpan);

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-auto">
      {/* Grid */}
      {yTicks.map((v, i) => (
        <g key={`yt-${i}`}>
          <line x1={pad.left} x2={w - pad.right} y1={y(v)} y2={y(v)} stroke="rgba(148,163,184,0.18)" strokeWidth={1} />
          <text x={pad.left - 6} y={y(v) + 3} fontSize={10} fill="#94a3b8" textAnchor="end">
            {fmtValue(v, data.name)}
          </text>
        </g>
      ))}
      {xTicks.map((t, i) => (
        <text key={`xt-${i}`} x={x(t)} y={h - pad.bottom + 16} fontSize={10} fill="#94a3b8" textAnchor="middle">
          {fmtTimeTick(t, rangeSecs)}
        </text>
      ))}
      {/* Max overlay (lighter, behind mean) */}
      <path d={maxPath} fill="none" stroke="rgba(14, 165, 233, 0.35)" strokeWidth={1.5} strokeDasharray="3 3" />
      {/* Mean (primary) */}
      <path d={meanPath} fill="none" stroke="#0ea5e9" strokeWidth={2} />
    </svg>
  );
}

export default function MetricsPage() {
  const [names, setNames] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [rangeSecs, setRangeSecs] = useState<number>(RANGES[0].secs);
  const [data, setData] = useState<SeriesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-refresh cadence: tight on live tier, relax on longer windows.
  const refreshMs = useMemo(() => {
    if (rangeSecs <= 1_800)   return 5_000;
    if (rangeSecs <= 21_600)  return 30_000;
    if (rangeSecs <= 86_400)  return 60_000;
    return 5 * 60_000;
  }, [rangeSecs]);

  const fetchList = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/metrics/list", { headers: authHeaders() });
      if (!r.ok) throw new Error(`list failed (${r.status})`);
      const j = await r.json();
      const n: string[] = j.names || [];
      setNames(n);
      if (!selected && n.length) setSelected(n[0]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [selected]);

  const fetchSeries = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const u = new URL(`/api/v1/metrics/series`, window.location.origin);
      u.searchParams.set("name", selected);
      u.searchParams.set("range_secs", String(rangeSecs));
      const r = await fetch(u.toString(), { headers: authHeaders() });
      if (!r.ok) throw new Error(`series failed (${r.status})`);
      const j: SeriesResponse = await r.json();
      setData(j);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [selected, rangeSecs]);

  useEffect(() => { fetchList(); }, [fetchList]);
  useEffect(() => {
    fetchSeries();
    const id = setInterval(fetchSeries, refreshMs);
    return () => clearInterval(id);
  }, [fetchSeries, refreshMs]);

  const latest = data && data.points.length > 0 ? data.points[data.points.length - 1] : null;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white">Metrics</h1>
          <p className="text-sm text-[var(--text-muted)]">
            In-memory RRD — 1 s / 30 min, 10 s / 6 h, 1 min / 7 d, 5 min / 30 d.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {RANGES.map(r => (
            <button
              key={r.label}
              onClick={() => setRangeSecs(r.secs)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                rangeSecs === r.secs
                  ? "bg-[var(--accent)] text-white"
                  : "bg-gray-800 text-gray-300 hover:bg-gray-700"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between gap-4 mb-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400">Metric</label>
            <select
              value={selected}
              onChange={e => setSelected(e.target.value)}
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-white focus:outline-none focus:border-blue-500 min-w-[260px]"
            >
              {names.length === 0 && <option value="">(no metrics registered yet)</option>}
              {names.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <div className="text-xs text-gray-400 flex items-center gap-3">
            {data && <span>tier: <span className="text-gray-200 font-mono">{data.tier}</span></span>}
            {data && <span>step: <span className="text-gray-200 font-mono">{data.interval_secs}s</span></span>}
            {data && <span>points: <span className="text-gray-200 font-mono">{data.points.length}</span></span>}
            {latest && <span>now: <span className="text-gray-200 font-mono">{fmtValue(latest.v, data!.name)}</span></span>}
            {loading && <span className="text-gray-500">loading…</span>}
          </div>
        </div>
        {error && <div className="text-xs text-red-400 mb-2">{error}</div>}
        {data ? <Chart data={data} rangeSecs={rangeSecs} /> : (
          <div className="h-[280px] flex items-center justify-center text-sm text-gray-500">
            {selected ? "Loading…" : "Pick a metric."}
          </div>
        )}
        <div className="mt-3 flex items-center gap-4 text-[11px] text-gray-500">
          <span className="inline-flex items-center gap-1"><span className="w-3 h-0.5 bg-sky-500 inline-block" /> mean</span>
          <span className="inline-flex items-center gap-1"><span className="w-3 h-0.5 inline-block border-t border-dashed border-sky-500/60" /> max</span>
        </div>
      </div>
    </div>
  );
}
