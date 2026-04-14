"use client";

import { useState, useEffect, useCallback } from "react";
import Help, { HelpBanner } from "../Help";
import { api, Gateway } from "../lib";

interface SlaSample {
  gateway_id: string;
  bucket_ts: string;
  samples: number;
  rtt_avg: number | null;
  rtt_p95: number | null;
  rtt_p99: number | null;
  jitter_avg: number | null;
  loss_pct: number | null;
  mos_avg: number | null;
  up_seconds: number;
}

const WINDOWS = [
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
];

export default function SlaPage() {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [selectedGw, setSelectedGw] = useState<string>("");
  const [window, setWindow] = useState<string>("24h");
  const [samples, setSamples] = useState<SlaSample[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ data: Gateway[] }>("GET", "/api/v1/multiwan/gateways")
      .then((r) => {
        setGateways(r.data);
        if (r.data.length > 0) setSelectedGw(r.data[0].id);
      })
      .catch((e) => setError(e.message));
  }, []);

  const fetchSla = useCallback(async () => {
    if (!selectedGw) return;
    setLoading(true);
    try {
      const r = await api<{ data: SlaSample[] }>(
        "GET",
        `/api/v1/multiwan/gateways/${selectedGw}/sla?window=${window}`,
      );
      setSamples(r.data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, [selectedGw, window]);

  useEffect(() => {
    fetchSla();
  }, [fetchSla]);

  const rtts = samples.map((s) => s.rtt_avg).filter((x): x is number => x != null);
  const maxRtt = rtts.length ? Math.max(...rtts) : 1;
  const avgRtt = rtts.length ? rtts.reduce((a, b) => a + b, 0) / rtts.length : 0;
  const upSecs = samples.reduce((a, b) => a + b.up_seconds, 0);
  const totalSecs = samples.length * 60;
  const uptime = totalSecs > 0 ? (upSecs / totalSecs) * 100 : 0;
  const losses = samples.map((s) => s.loss_pct).filter((x): x is number => x != null);
  const avgLoss = losses.length ? losses.reduce((a, b) => a + b, 0) / losses.length : 0;
  const moss = samples.map((s) => s.mos_avg).filter((x): x is number => x != null);
  const avgMos = moss.length ? moss.reduce((a, b) => a + b, 0) / moss.length : 0;

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          SLA Reports
          <Help title="SLA reporting" size="md">
            <p>
              Every minute, the daemon snapshots each gateway&apos;s
              rolling stats (RTT avg/p95/p99, jitter, loss %, MOS, up-seconds)
              into a DB bucket.
            </p>
            <p>
              Buckets older than 30 days are pruned automatically, so the DB
              stays bounded even with many gateways.
            </p>
            <p className="text-blue-400">
              Use the Window picker to zoom in (24h for live-ish) or out
              (30d for monthly reports).
            </p>
          </Help>
        </h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Rolling 1-minute buckets. 30-day retention.
        </p>
      </div>

      <HelpBanner title="Reading the numbers" storageKey="mwan-sla">
        <ul className="list-disc ml-5 space-y-1">
          <li>
            <b>Uptime</b> — percent of sampled minutes where the gateway was{" "}
            <i>up</i>. Not the same as link availability from the ISP — this is
            what AiFw&apos;s probes saw end-to-end.
          </li>
          <li>
            <b>Avg RTT</b> — mean of per-minute averages. Compare against your
            baseline; spikes usually indicate congestion or a problem
            upstream.
          </li>
          <li>
            <b>Avg Loss</b> — rolling packet loss %. &gt;1% for voice/video is
            noticeable, &gt;5% is broken.
          </li>
          <li>
            <b>Avg MOS</b> — 1.0–4.5 quality score. Green ≥4.0 excellent, yellow
            3.5 acceptable, red &lt;3.5 poor.
          </li>
        </ul>
      </HelpBanner>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      <div className="flex gap-3 items-center">
        <select
          value={selectedGw}
          onChange={(e) => setSelectedGw(e.target.value)}
          className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
        >
          {gateways.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
        <select
          value={window}
          onChange={(e) => setWindow(e.target.value)}
          className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
        >
          {WINDOWS.map((w) => (
            <option key={w.value} value={w.value}>
              {w.label}
            </option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Uptime" value={`${uptime.toFixed(2)}%`} color="green" />
        <Stat label="Avg RTT" value={`${avgRtt.toFixed(1)} ms`} color="blue" />
        <Stat label="Avg Loss" value={`${avgLoss.toFixed(1)}%`} color={avgLoss > 1 ? "red" : "green"} />
        <Stat
          label="Avg MOS"
          value={avgMos.toFixed(2)}
          color={avgMos >= 4.0 ? "green" : avgMos >= 3.5 ? "yellow" : "red"}
        />
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h2 className="text-sm font-semibold text-white mb-3">RTT trend</h2>
        {loading ? (
          <div className="h-32 flex items-center justify-center text-[var(--text-muted)]">
            Loading…
          </div>
        ) : samples.length === 0 ? (
          <div className="h-32 flex items-center justify-center text-[var(--text-muted)]">
            No samples in window. Probes may not have run yet.
          </div>
        ) : (
          <svg viewBox={`0 0 ${Math.max(200, samples.length * 4)} 80`} className="w-full h-32">
            <polyline
              fill="none"
              stroke="rgb(59,130,246)"
              strokeWidth="1"
              points={samples
                .map((s, i) => {
                  const x = i * 4;
                  const y = 80 - ((s.rtt_avg ?? 0) / maxRtt) * 70;
                  return `${x},${y}`;
                })
                .join(" ")}
            />
          </svg>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: "green" | "blue" | "red" | "yellow";
}) {
  const col = {
    green: "text-green-400",
    blue: "text-blue-400",
    red: "text-red-400",
    yellow: "text-yellow-400",
  }[color];
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
      <div className="text-xs text-[var(--text-muted)] uppercase mb-1">{label}</div>
      <div className={`text-2xl font-bold ${col}`}>{value}</div>
    </div>
  );
}
