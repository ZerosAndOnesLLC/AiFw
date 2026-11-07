"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchApi, getWsTicket } from "@/lib/api";
import {
  demoteCluster,
  getClusterStatus,
  getFailoverHistory,
  promoteCluster,
  runHealthChecks,
  setMaintenance,
  type ClusterStatus,
  type FailoverEvent,
  type HealthRunResult,
  type Node,
} from "@/lib/api/cluster";

type Metrics = {
  pfsync_in: number;
  pfsync_out: number;
  state_count: number;
  ts_ms: number;
};

type CarpVip = {
  id: string;
  vhid: number;
  virtual_ip: string;
  prefix: number;
  interface: string;
  status: string;
};

type HealthCheck = {
  id: string;
  name: string;
  check_type: string;
  target: string;
  enabled: boolean;
};

const ROLE_LABEL: Record<string, string> = {
  primary: "MASTER",
  secondary: "BACKUP",
  split: "SPLIT",
  init: "INITIALISING",
  standalone: "STANDALONE",
};

const STATE_CLASS: Record<string, string> = {
  master: "text-green-400",
  backup: "text-blue-300",
  init: "text-amber-300",
};

const HEALTH_CLASS: Record<string, string> = {
  healthy: "text-green-400",
  degraded: "text-amber-300",
  unreachable: "text-red-400",
};

function Sparkline({ data }: { data: number[] }) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-16 text-xs text-[var(--text-muted)]">
        No data yet — collecting samples…
      </div>
    );
  }
  const max = Math.max(...data, 1);
  const w = 600;
  const h = 60;
  const step = w / Math.max(data.length - 1, 1);
  const path = data
    .map((v, i) => `${i === 0 ? "M" : "L"} ${i * step} ${h - (v / max) * h}`)
    .join(" ");
  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      className="w-full"
      preserveAspectRatio="none"
    >
      <path
        d={path}
        fill="none"
        stroke="#60a5fa"
        strokeWidth="1.5"
      />
    </svg>
  );
}

export default function ClusterDashboard() {
  const [status, setStatus] = useState<ClusterStatus | null>(null);
  const [historyDays, setHistoryDays] = useState(1);
  const historyDaysRef = useRef(1);
  const [runResults, setRunResults] = useState<HealthRunResult[] | null>(null);
  const [confirmMaint, setConfirmMaint] = useState(false);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [history, setHistory] = useState<FailoverEvent[]>([]);
  const [vips, setVips] = useState<CarpVip[]>([]);
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [metrics, setMetrics] = useState<Metrics[]>([]);
  const [busy, setBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Auto-clear error banner after 5 s
  useEffect(() => {
    if (!errorMsg) return;
    const t = setTimeout(() => setErrorMsg(null), 5000);
    return () => clearTimeout(t);
  }, [errorMsg]);

  const refresh = useCallback(async () => {
    const days = historyDaysRef.current;
    const [s, n, h, v, c] = await Promise.all([
      getClusterStatus().catch(() => null),
      fetchApi<Node[]>("/api/v1/cluster/nodes").catch(() => [] as Node[]),
      getFailoverHistory(days).catch(() => [] as FailoverEvent[]),
      fetchApi<CarpVip[]>("/api/v1/cluster/carp").catch(() => [] as CarpVip[]),
      fetchApi<HealthCheck[]>("/api/v1/cluster/health").catch(() => [] as HealthCheck[]),
    ]);
    setStatus(s);
    setNodes(n);
    setHistory(h);
    setVips(v);
    setChecks(c);
  }, []);

  useEffect(() => {
    queueMicrotask(() => { refresh().catch(() => {}); }); // initial fetch only — WS events drive subsequent updates

    // WebSocket for live cluster.metrics + cluster.role_changed.
    // Uses a single-use ticket from POST /auth/ws-ticket so the JWT
    // is never placed in the URL (auth_middleware rejects ?token= URLs).
    let stopped = false;

    const connect = async () => {
      if (stopped) return;
      let ticket: string;
      try {
        ticket = await getWsTicket();
      } catch {
        // Not logged in or ticket fetch failed; retry after 3 s.
        if (!stopped) reconnectRef.current = setTimeout(connect, 3000);
        return;
      }
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(
        `${proto}//${window.location.host}/api/v1/ws?ticket=${ticket}`
      );
      wsRef.current = ws;
      ws.onmessage = (e) => {
        try {
          const f = JSON.parse(e.data as string) as {
            channel?: string;
            event?: { type?: string } & Metrics;
          };
          if (f.channel === "cluster" && f.event?.type === "metrics") {
            setMetrics((prev) => [...prev.slice(-29), f.event as Metrics]);
          } else if (
            f.channel === "cluster" &&
            f.event?.type === "role_changed"
          ) {
            refresh().catch(() => {});
          } else if (
            f.channel === "cluster" &&
            f.event?.type === "health_changed"
          ) {
            refresh().catch(() => {});
          }
        } catch {
          // ignore parse errors
        }
      };
      ws.onclose = () => {
        wsRef.current = null;
        if (!stopped) reconnectRef.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
    };

    connect();

    return () => {
      stopped = true;
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [refresh]);

  if (!status) {
    return (
      <div className="p-6 text-sm text-[var(--text-muted)]">
        Loading cluster status…
      </div>
    );
  }

  const isMaster = status.role === "primary";
  const peerNode = status.peer;

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e: unknown) {
      setErrorMsg(`${label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      await refresh().catch(() => {});
      setBusy(false);
    }
  };

  const forceSync = () =>
    act("Force sync", () =>
      fetchApi("/api/v1/cluster/snapshot/force", { method: "POST" }),
    );
  const demote = () => act("Demote", demoteCluster);
  const clearDemotion = () => act("Clear demotion", promoteCluster);
  const toggleMaintenance = () => {
    if (!status.demotion.maintenance && !confirmMaint) {
      setConfirmMaint(true);
      return;
    }
    setConfirmMaint(false);
    return act("Maintenance mode", () =>
      setMaintenance(!status.demotion.maintenance),
    );
  };
  const runChecks = () =>
    act("Health check run", async () => setRunResults(await runHealthChecks()));
  const changeDays = (d: number) => {
    setHistoryDays(d);
    historyDaysRef.current = d;
    refresh().catch(() => {});
  };

  const kernelVhid = (v: CarpVip) =>
    status.carp.vhids.find((k) => k.vhid === v.vhid && k.interface === v.interface);
  const heroBg = status.split_brain
    ? "bg-red-500/10 border-red-500/50"
    : status.warnings.length > 0 && status.role !== "standalone"
      ? "bg-amber-500/10 border-amber-500/40"
      : isMaster
        ? "bg-green-500/10 border-green-500/40"
        : status.role === "standalone"
          ? "bg-gray-500/10 border-gray-500/40"
          : "bg-blue-500/10 border-blue-500/40";
  const pf = status.carp.pfsync;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">HA Dashboard</h1>

      {/* Inline error banner — replaces alert() */}
      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/40 rounded p-3 text-sm text-red-300 flex justify-between items-center">
          <span>{errorMsg}</span>
          <button
            onClick={() => setErrorMsg(null)}
            className="text-xs underline ml-4"
          >
            dismiss
          </button>
        </div>
      )}

      {/* Hero */}
      <div className={`rounded-lg p-4 border ${heroBg}`}>
        <div className="text-sm opacity-70">This node</div>
        <div className="text-3xl font-bold">
          {ROLE_LABEL[status.role] ?? status.role.toUpperCase()}
        </div>
        <div className="mt-2 text-sm space-y-1">
          <div>
            Configured {status.configured_role} &middot; peer{" "}
            {peerNode?.name ?? "—"} (
            {status.peer_reachable ? (
              "answering"
            ) : (
              <span className="text-red-400 font-semibold">NOT ANSWERING</span>
            )}
            {peerNode?.peer_state && <> · reports {ROLE_LABEL[peerNode.peer_state] ?? peerNode.peer_state}</>}
            ) &middot; {status.pfsync_state_count.toLocaleString()} states
          </div>
          <div className="text-xs opacity-80">
            Demotion {status.demotion.level ?? "—"}
            {status.demotion.reasons.length > 0
              ? ` (held: ${status.demotion.reasons.join(", ")})`
              : " (none held)"}
            {" · "}preempt {status.demotion.preempt === null ? "—" : status.demotion.preempt ? "on" : "OFF"}
            {status.demotion.maintenance && " · maintenance mode"}
          </div>
        </div>
        {status.warnings.length > 0 && (
          <ul className="mt-3 text-sm list-disc pl-5 space-y-0.5">
            {status.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        )}
      </div>

      {/* pfsync link */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-sm">
        <div className="font-semibold mb-1">pfsync</div>
        {pf ? (
          <div className="text-xs space-y-0.5">
            <div>
              pfsync0 {pf.up ? "up" : <span className="text-red-400">DOWN</span>} on{" "}
              <span className="font-mono">{pf.syncdev ?? "—"}</span>
              {pf.syncpeer && <> → <span className="font-mono">{pf.syncpeer}</span></>}
              {" · "}defer {pf.defer ? "on" : "off"}
            </div>
            <div>
              Bulk sync:{" "}
              {pf.syncok === null ? "—" : pf.syncok ? (
                <span className="text-green-400">complete</span>
              ) : (
                <span className="text-amber-300">in progress</span>
              )}
            </div>
          </div>
        ) : (
          <div className="text-xs text-[var(--text-muted)]">pfsync0 not present in the kernel.</div>
        )}
      </section>

      {/* pfsync sparkline */}
      <section>
        <h2 className="text-lg font-semibold mb-2">
          pfsync throughput (last 60 s)
        </h2>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3">
          <Sparkline data={metrics.map((m) => m.pfsync_in + m.pfsync_out)} />
          {metrics.length > 0 && (
            <div className="text-[10px] text-[var(--text-muted)] mt-1">
              latest: in {metrics[metrics.length - 1].pfsync_in.toLocaleString()} pkts &middot; out {metrics[metrics.length - 1].pfsync_out.toLocaleString()} pkts &middot; {metrics[metrics.length - 1].state_count.toLocaleString()} states
            </div>
          )}
        </div>
      </section>

      {/* CARP VIPs */}
      <section>
        <h2 className="text-lg font-semibold mb-2">CARP VIPs</h2>
        {vips.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">
            No VIPs configured.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-[var(--border)] rounded">
              <thead className="bg-[var(--bg-card)]">
                <tr>
                  <th className="text-left p-2">VHID</th>
                  <th className="text-left p-2">Interface</th>
                  <th className="text-left p-2">VIP</th>
                  <th className="text-left p-2">Kernel state</th>
                  <th className="text-left p-2">advskew</th>
                </tr>
              </thead>
              <tbody>
                {vips.map((v) => (
                  <tr key={v.id} className="border-t border-[var(--border)]">
                    <td className="p-2">{v.vhid}</td>
                    <td className="p-2 font-mono">{v.interface}</td>
                    <td className="p-2 font-mono">
                      {v.virtual_ip}/{v.prefix}
                    </td>
                    <td className={`p-2 font-semibold ${STATE_CLASS[kernelVhid(v)?.state ?? ""] ?? "text-red-400"}`}>
                      {kernelVhid(v)?.state.toUpperCase() ?? "NOT IN KERNEL"}
                    </td>
                    <td className="p-2">{kernelVhid(v)?.advskew ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Per-node panels */}
      <section>
        <h2 className="text-lg font-semibold mb-2">Nodes</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {nodes.map((n) => (
            <div
              key={n.id}
              className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-sm"
            >
              <div className="flex justify-between">
                <span className="font-semibold">{n.name}</span>
                <span className="text-xs opacity-70">{n.role}</span>
              </div>
              <div className="text-xs opacity-70 mt-1">
                {n.address} &middot; last seen{" "}
                {new Date(n.last_seen).toLocaleString()}
              </div>
              <div className="text-xs">
                health:{" "}
                <span className={HEALTH_CLASS[n.health] ?? "opacity-70"}>{n.health}</span>
                {n.peer_state && (
                  <span className="opacity-70"> · reports {ROLE_LABEL[n.peer_state] ?? n.peer_state}</span>
                )}
              </div>
              {n.software_version && (
                <div className="text-xs opacity-70">
                  version: {n.software_version}
                </div>
              )}
              {n.last_pushed_cert_at && (
                <div className="text-xs opacity-70">
                  last cert push:{" "}
                  {new Date(n.last_pushed_cert_at).toLocaleString()}
                </div>
              )}
            </div>
          ))}
          {nodes.length === 0 && (
            <div className="text-sm text-[var(--text-muted)]">
              No nodes configured.
            </div>
          )}
        </div>
      </section>

      {/* Config sync widget */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-sm">
        <div className="flex justify-between items-center gap-3 flex-wrap">
          <div>
            <div className="font-semibold">Config sync</div>
            <div className="text-xs opacity-70 break-all">
              Last hash: {status.last_snapshot_hash ?? "—"}
            </div>
          </div>
          <button
            onClick={forceSync}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm"
          >
            Force sync from peer
          </button>
        </div>
      </section>

      {/* Health-check matrix */}
      <section>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-semibold">Health checks</h2>
          <button
            onClick={runChecks}
            disabled={busy || checks.length === 0}
            className="px-3 py-1 rounded bg-[var(--bg-card)] border border-[var(--border)] hover:border-blue-500 disabled:opacity-50 text-xs"
          >
            Run now
          </button>
        </div>
        {checks.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">
            No health checks configured.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-[var(--border)] rounded">
              <thead className="bg-[var(--bg-card)]">
                <tr>
                  <th className="text-left p-2">Name</th>
                  <th className="text-left p-2">Type</th>
                  <th className="text-left p-2">Target</th>
                  <th className="text-left p-2">Enabled</th>
                  <th className="text-left p-2">Last run</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((c) => (
                  <tr key={c.id} className="border-t border-[var(--border)]">
                    <td className="p-2 font-mono">{c.name}</td>
                    <td className="p-2">{c.check_type}</td>
                    <td className="p-2 font-mono break-all">{c.target}</td>
                    <td className="p-2">{c.enabled ? "yes" : "no"}</td>
                    <td className="p-2">
                      {(() => {
                        const r = runResults?.find((x) => x.name === c.name);
                        if (!r) return "—";
                        return r.healthy ? (
                          <span className="text-green-400">pass</span>
                        ) : (
                          <span className="text-red-400">FAIL</span>
                        );
                      })()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Failover timeline */}
      <section>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-semibold">Failover events</h2>
          <select
            value={historyDays}
            onChange={(e) => changeDays(Number(e.target.value))}
            className="bg-[var(--bg-card)] border border-[var(--border)] rounded px-2 py-1 text-xs"
          >
            <option value={1}>Last 24 h</option>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={365}>Last year</option>
          </select>
        </div>
        {history.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">
            No failover events recorded.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-[var(--border)] rounded">
              <thead className="bg-[var(--bg-card)]">
                <tr>
                  <th className="text-left p-2">When</th>
                  <th className="text-left p-2">From</th>
                  <th className="text-left p-2">To</th>
                  <th className="text-left p-2">Cause</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="border-t border-[var(--border)]">
                    <td className="p-2">{new Date(h.ts).toLocaleString()}</td>
                    <td className="p-2">{h.from_role}</td>
                    <td className="p-2">{h.to_role}</td>
                    <td className="p-2">
                      {h.cause}
                      {h.detail && (
                        <span className="opacity-70"> — {h.detail}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Quick actions */}
      <section className="space-y-2">
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={demote}
            disabled={busy || status.demotion.reasons.includes("manual")}
            title="Hand the VIPs to the peer until you clear it or reboot"
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-white text-sm"
          >
            Demote this node
          </button>
          <button
            onClick={clearDemotion}
            disabled={
              busy ||
              !(status.demotion.reasons.includes("manual") || status.demotion.maintenance)
            }
            title="Clear operator demotion and maintenance mode"
            className="px-3 py-1.5 rounded bg-green-700 hover:bg-green-800 disabled:opacity-50 text-white text-sm"
          >
            Clear demotion
          </button>
          <button
            onClick={toggleMaintenance}
            disabled={busy}
            className={`px-3 py-1.5 rounded disabled:opacity-50 text-white text-sm ${
              confirmMaint ? "bg-red-600 hover:bg-red-700" : "bg-slate-600 hover:bg-slate-700"
            }`}
          >
            {status.demotion.maintenance
              ? "Leave maintenance mode"
              : confirmMaint
                ? "Confirm: enter maintenance"
                : "Enter maintenance mode"}
          </button>
          <button
            onClick={forceSync}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm"
          >
            Force sync from peer
          </button>
        </div>
        <div className="text-xs text-[var(--text-muted)]">
          Demote hands the VIPs to the peer until cleared or reboot. Maintenance mode keeps this node BACKUP across reboots until you leave it.
        </div>
      </section>
    </div>
  );
}
