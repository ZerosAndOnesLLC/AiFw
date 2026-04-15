"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Help, { HelpBanner } from "../Help";

/* ---------- Types ---------- */

interface CacheStats {
  entries: number;
  max_entries: number;
  hits: number;
  misses: number;
  insertions: number;
  evictions: number;
  hit_rate_pct: number;
}
interface ZoneStat {
  name: string;
  rules: number;
  hits: number;
}
interface RpzStats {
  rules: number;
  zones: number;
  hits: number;
  per_zone: ZoneStat[];
}
interface StatsSnapshot {
  ts: number;
  cache: CacheStats;
  rpz: RpzStats;
}
interface BlockEvent {
  ts: number;
  qname: string;
  action: "nxdomain" | "nodata" | "redirect" | "drop" | "passthru";
  zone: string;
}

type Frame =
  | { type: "stats"; data: StatsSnapshot }
  | { type: "block"; data: BlockEvent }
  | { type: "error"; error: string };

interface TickPoint {
  ts: number;
  qps_total: number; // hits + misses delta per tick
  qps_blocked: number; // RPZ hits delta per tick
}

const HISTORY = 120; // seconds

/* ---------- Helpers ---------- */

function fmtNum(n: number): string {
  if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
  return String(n);
}
function fmtPct(n: number): string {
  return n.toFixed(1) + "%";
}
function fmtTime(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

/* ---------- Page ---------- */

export default function DashboardPage() {
  const [snapshot, setSnapshot] = useState<StatsSnapshot | null>(null);
  const [history, setHistory] = useState<TickPoint[]>([]);
  const [recentBlocks, setRecentBlocks] = useState<BlockEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [conn, setConn] = useState<"connecting" | "open" | "closed">("connecting");
  const lastSnap = useRef<StatsSnapshot | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAt = useRef<number>(0);

  // WebSocket lifecycle with backoff reconnect.
  useEffect(() => {
    let stopped = false;
    let backoff = 1000;

    function connect() {
      if (stopped) return;
      setConn("connecting");
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const token = localStorage.getItem("aifw_token") || "";
      const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/dns/stream?token=${encodeURIComponent(token)}`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConn("open");
        backoff = 1000;
      };
      ws.onerror = () => {};
      ws.onclose = () => {
        setConn("closed");
        if (!stopped) {
          reconnectAt.current = Date.now() + backoff;
          setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 15000);
        }
      };
      ws.onmessage = (e) => {
        if (paused) return;
        try {
          const f: Frame = JSON.parse(e.data);
          if (f.type === "stats") {
            setSnapshot(f.data);
            const prev = lastSnap.current;
            if (prev) {
              const dt = Math.max(1, (f.data.ts - prev.ts) / 1000);
              const dTotal = (f.data.cache.hits + f.data.cache.misses) - (prev.cache.hits + prev.cache.misses);
              const dBlocked = f.data.rpz.hits - prev.rpz.hits;
              setHistory((prev) => {
                const next = [...prev, {
                  ts: f.data.ts,
                  qps_total: Math.max(0, dTotal / dt),
                  qps_blocked: Math.max(0, dBlocked / dt),
                }];
                return next.length > HISTORY ? next.slice(next.length - HISTORY) : next;
              });
            }
            lastSnap.current = f.data;
          } else if (f.type === "block") {
            setRecentBlocks((prev) => {
              const next = [f.data, ...prev];
              return next.length > 200 ? next.slice(0, 200) : next;
            });
          }
        } catch { /* ignore malformed */ }
      };
    }

    connect();
    return () => {
      stopped = true;
      wsRef.current?.close();
    };
  }, [paused]);

  const blockRate = useMemo(() => {
    if (!snapshot) return 0;
    const total = snapshot.cache.hits + snapshot.cache.misses;
    if (total === 0) return 0;
    return (snapshot.rpz.hits / total) * 100;
  }, [snapshot]);

  const qpsAvg1m = useMemo(() => {
    const tail = history.slice(-60);
    if (!tail.length) return 0;
    const sum = tail.reduce((a, p) => a + p.qps_total, 0);
    return sum / tail.length;
  }, [history]);

  const topZones = useMemo(() => {
    if (!snapshot) return [];
    return [...snapshot.rpz.per_zone].sort((a, b) => b.hits - a.hits).slice(0, 12);
  }, [snapshot]);

  const topBlockedDomains = useMemo(() => {
    const counts = new Map<string, number>();
    for (const b of recentBlocks) {
      counts.set(b.qname, (counts.get(b.qname) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15);
  }, [recentBlocks]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          DNS Live Dashboard
          <Help title="What is this?" size="md">
            Real-time view of every query rDNS is processing. Stats stream over
            a single WebSocket — the API forwards rDNS&apos;s own control socket so
            there&apos;s no polling overhead.
          </Help>
        </h1>
        <div className="flex items-center gap-3">
          <span className={`inline-flex items-center gap-1.5 text-xs ${conn === "open" ? "text-emerald-400" : conn === "connecting" ? "text-yellow-400" : "text-red-400"}`}>
            <span className={`w-2 h-2 rounded-full ${conn === "open" ? "bg-emerald-400 animate-pulse" : conn === "connecting" ? "bg-yellow-400" : "bg-red-400"}`}></span>
            {conn}
          </span>
          <button
            onClick={() => setPaused((p) => !p)}
            className={`px-3 py-1 text-xs rounded ${paused ? "bg-yellow-600 text-white" : "bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]"}`}
          >
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </header>

      <HelpBanner title="Reading the dashboard" storageKey="dns-dashboard">
        <p>
          <b>QPS</b> = queries per second, computed from the delta between
          successive 1-second snapshots. <b>Block rate</b> = RPZ matches over
          total queries. <b>Cache hit rate</b> = cache hits over total queries
          rDNS has handled.
        </p>
        <p>
          <b>Per-list hits</b> shows which RPZ zones are doing the work — a list
          with 0 hits in steady state is a candidate to disable. Lists are
          counted separately even when sharing the same domain (whitelist passthrough wins).
        </p>
      </HelpBanner>

      {/* Tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <Tile label="QPS (1m avg)" value={qpsAvg1m.toFixed(1)} />
        <Tile label="Block rate" value={fmtPct(blockRate)} accent={blockRate > 30 ? "text-yellow-300" : "text-emerald-400"} />
        <Tile label="Cache hit rate" value={snapshot ? fmtPct(snapshot.cache.hit_rate_pct) : "—"} />
        <Tile label="Total queries" value={snapshot ? fmtNum(snapshot.cache.hits + snapshot.cache.misses) : "—"} />
        <Tile label="Total blocked" value={snapshot ? fmtNum(snapshot.rpz.hits) : "—"} />
        <Tile label="RPZ rules" value={snapshot ? fmtNum(snapshot.rpz.rules) : "—"} sub={snapshot ? `${snapshot.rpz.zones} zones` : ""} />
      </div>

      {/* QPS chart */}
      <section className="border border-[var(--border)] rounded p-3">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            Queries per second (last {HISTORY}s)
            <Help title="Stacked QPS chart" size="xs">Green = allowed, red = blocked. Stacked area shows total throughput.</Help>
          </h2>
          <Legend items={[
            { color: "#34d399", label: "allowed" },
            { color: "#f87171", label: "blocked" },
          ]} />
        </div>
        <QpsChart history={history} />
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Per-list bar chart */}
        <section className="border border-[var(--border)] rounded p-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
            Hits per blocklist
            <Help title="Per-zone counters" size="xs">Each row is one RPZ zone — built-in or custom blocklist. Counters are persistent across rDNS RPZ reloads.</Help>
          </h2>
          {topZones.length === 0 && <div className="text-sm text-[var(--text-muted)]">No data yet.</div>}
          <div className="space-y-1.5">
            {topZones.map((z) => {
              const max = topZones[0]?.hits || 1;
              const pct = max > 0 ? (z.hits / max) * 100 : 0;
              return (
                <div key={z.name} className="text-xs">
                  <div className="flex justify-between mb-0.5">
                    <span className="font-mono text-white truncate">{z.name}</span>
                    <span className="text-[var(--text-muted)] tabular-nums">{fmtNum(z.hits)} · {fmtNum(z.rules)} rules</span>
                  </div>
                  <div className="h-2 bg-[var(--bg-card-secondary)] rounded">
                    <div className="h-2 bg-blue-500 rounded" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Top blocked domains */}
        <section className="border border-[var(--border)] rounded p-3">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
            Top blocked domains (recent)
            <Help title="Recent top-N" size="xs">Aggregated over the last ~200 block events received from rDNS, not all-time.</Help>
          </h2>
          {topBlockedDomains.length === 0 && <div className="text-sm text-[var(--text-muted)]">No blocks yet.</div>}
          <table className="w-full text-xs">
            <tbody>
              {topBlockedDomains.map(([qname, hits]) => (
                <tr key={qname} className="border-t border-[var(--border)]">
                  <td className="py-1 font-mono text-white truncate max-w-xs">{qname}</td>
                  <td className="py-1 text-right tabular-nums text-[var(--text-muted)]">{hits}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>

      {/* Recent blocks tail */}
      <section className="border border-[var(--border)] rounded p-3">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            Recent block events
            <Help title="Live tail" size="xs">Latest first. Cleared on page refresh; keeps last 200.</Help>
          </h2>
          <button
            onClick={() => setRecentBlocks([])}
            className="text-xs px-2 py-0.5 rounded hover:bg-[var(--bg-hover)] text-[var(--text-muted)]"
          >Clear</button>
        </div>
        <div className="text-xs font-mono max-h-72 overflow-y-auto">
          {recentBlocks.length === 0 && <div className="text-[var(--text-muted)]">Waiting for blocks…</div>}
          {recentBlocks.map((b, i) => (
            <div key={`${b.ts}-${i}`} className="flex gap-3 border-b border-[var(--border)]/50 py-0.5">
              <span className="text-[var(--text-muted)] w-20 shrink-0">{fmtTime(b.ts)}</span>
              <span className={`w-16 shrink-0 ${b.action === "nxdomain" ? "text-red-400" : b.action === "redirect" ? "text-yellow-400" : "text-[var(--text-muted)]"}`}>{b.action}</span>
              <span className="text-white truncate">{b.qname}</span>
              <span className="text-[var(--text-muted)] truncate ml-auto">{b.zone}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

/* ---------- Bits ---------- */

function Tile({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: string }) {
  return (
    <div className="border border-[var(--border)] rounded p-3">
      <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className={`text-2xl font-bold ${accent || "text-white"}`}>{value}</div>
      {sub && <div className="text-[10px] text-[var(--text-muted)]">{sub}</div>}
    </div>
  );
}

function Legend({ items }: { items: { color: string; label: string }[] }) {
  return (
    <div className="flex gap-3 text-[10px] text-[var(--text-muted)]">
      {items.map((it) => (
        <span key={it.label} className="inline-flex items-center gap-1">
          <span className="w-2 h-2 rounded" style={{ backgroundColor: it.color }} />
          {it.label}
        </span>
      ))}
    </div>
  );
}

/* Tiny SVG stacked-area chart — no chart library so the bundle stays small. */
function QpsChart({ history }: { history: TickPoint[] }) {
  const W = 800;
  const H = 140;
  const PAD = 4;

  if (history.length < 2) {
    return <div className="text-sm text-[var(--text-muted)] py-12 text-center">Collecting data…</div>;
  }

  const max = Math.max(1, ...history.map((p) => p.qps_total));
  const stepX = (W - 2 * PAD) / Math.max(1, HISTORY - 1);

  function pathFor(values: number[]): string {
    let d = "";
    values.forEach((v, i) => {
      const x = PAD + i * stepX;
      const y = H - PAD - (v / max) * (H - 2 * PAD);
      d += `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)} `;
    });
    return d;
  }

  // Pad history to fixed width by left-aligning recent points.
  const offset = HISTORY - history.length;
  const allowed = Array<number>(HISTORY).fill(0);
  const blocked = Array<number>(HISTORY).fill(0);
  history.forEach((p, i) => {
    allowed[offset + i] = Math.max(0, p.qps_total - p.qps_blocked);
    blocked[offset + i] = p.qps_blocked;
  });

  // Build stacked area paths.
  function areaPath(stack: number[], baseline: number[]): string {
    let d = `M${PAD},${H - PAD} `;
    for (let i = 0; i < HISTORY; i++) {
      const x = PAD + i * stepX;
      const y = H - PAD - ((stack[i] + baseline[i]) / max) * (H - 2 * PAD);
      d += `L${x.toFixed(1)},${y.toFixed(1)} `;
    }
    for (let i = HISTORY - 1; i >= 0; i--) {
      const x = PAD + i * stepX;
      const y = H - PAD - (baseline[i] / max) * (H - 2 * PAD);
      d += `L${x.toFixed(1)},${y.toFixed(1)} `;
    }
    return d + "Z";
  }

  const zeros = Array<number>(HISTORY).fill(0);
  const allowedArea = areaPath(allowed, zeros);
  const blockedArea = areaPath(blocked, allowed);

  // Sum line for total qps.
  const totals = allowed.map((a, i) => a + blocked[i]);
  const totalLine = pathFor(totals);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-32">
      <path d={allowedArea} fill="rgba(52, 211, 153, 0.45)" />
      <path d={blockedArea} fill="rgba(248, 113, 113, 0.55)" />
      <path d={totalLine} fill="none" stroke="rgba(255,255,255,0.6)" strokeWidth={1} />
      <text x={PAD + 2} y={12} fontSize={10} fill="#9ca3af">peak {max.toFixed(1)} qps</text>
    </svg>
  );
}
