"use client";

import { useEffect, useRef, useState } from "react";
import { getWsTicket } from "@/lib/api";

type Metrics = {
  pfsync_in: number;
  pfsync_out: number;
  state_count: number;
  ts_ms: number;
};

type Status = {
  role: string;
  peer_reachable: boolean;
  pfsync_state_count: number;
  last_snapshot_hash: string | null;
};

type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  health: string;
  last_seen: string;
  software_version?: string;
  last_pushed_cert_at?: string;
};

type FailoverEvent = {
  id: string;
  ts: string;
  from_role: string;
  to_role: string;
  cause: string;
  detail?: string;
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
  const [status, setStatus] = useState<Status | null>(null);
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

  const authHeaders = (): Record<string, string> => {
    const token =
      typeof window !== "undefined"
        ? localStorage.getItem("aifw_token")
        : null;
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const refresh = async () => {
    const [s, n, h, v, c] = await Promise.all([
      fetch("/api/v1/cluster/status", {
        credentials: "include",
        headers: authHeaders(),
      }).then((r) => (r.ok ? r.json() : null)),
      fetch("/api/v1/cluster/nodes", {
        credentials: "include",
        headers: authHeaders(),
      }).then((r) => (r.ok ? r.json() : [])),
      fetch("/api/v1/cluster/failover-history", {
        credentials: "include",
        headers: authHeaders(),
      }).then((r) => (r.ok ? r.json() : [])),
      fetch("/api/v1/cluster/carp", {
        credentials: "include",
        headers: authHeaders(),
      }).then((r) => (r.ok ? r.json() : [])),
      fetch("/api/v1/cluster/health", {
        credentials: "include",
        headers: authHeaders(),
      }).then((r) => (r.ok ? r.json() : [])),
    ]);
    setStatus(s);
    setNodes(n);
    setHistory(h);
    setVips(v);
    setChecks(c);
  };

  useEffect(() => {
    refresh().catch(() => {});
    const id = setInterval(refresh, 5000);

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
      clearInterval(id);
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      if (wsRef.current) wsRef.current.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!status) {
    return (
      <div className="p-6 text-sm text-[var(--text-muted)]">
        Loading cluster status…
      </div>
    );
  }

  // HA is documented as active-passive (exactly 2 nodes); this picks the first
  // non-local node deterministically. If multi-node HA ever ships, surface the
  // peer count separately and render multiple node cards inline.
  const isMaster = status.role === "primary";
  const peerNode = nodes.find((n) => n.role !== status.role);

  const forceSync = async () => {
    setBusy(true);
    try {
      const r = await fetch("/api/v1/cluster/snapshot/force", {
        method: "POST",
        credentials: "include",
        headers: authHeaders(),
      });
      if (!r.ok)
        setErrorMsg(`Force sync failed: ${r.status} ${r.statusText}`);
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const demote = async () => {
    setBusy(true);
    try {
      await fetch("/api/v1/cluster/demote", {
        method: "POST",
        credentials: "include",
        headers: authHeaders(),
      });
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const heroBg = isMaster
    ? "bg-green-500/10 border-green-500/40"
    : status.role === "standalone"
    ? "bg-gray-500/10 border-gray-500/40"
    : "bg-blue-500/10 border-blue-500/40";

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
        <div className="text-3xl font-bold">{status.role.toUpperCase()}</div>
        <div className="mt-2 text-sm">
          Peer: {peerNode?.name ?? "—"} (
          {status.peer_reachable ? (
            "reachable"
          ) : (
            <span className="text-red-400 font-semibold">UNREACHABLE</span>
          )}
          ) &middot; {status.pfsync_state_count} pfsync states
        </div>
      </div>

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
                  <th className="text-left p-2">Status</th>
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
                    <td className="p-2">{v.status}</td>
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
              <div className="text-xs opacity-70">health: {n.health}</div>
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
        <h2 className="text-lg font-semibold mb-2">Health checks</h2>
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
                </tr>
              </thead>
              <tbody>
                {checks.map((c) => (
                  <tr key={c.id} className="border-t border-[var(--border)]">
                    <td className="p-2 font-mono">{c.name}</td>
                    <td className="p-2">{c.check_type}</td>
                    <td className="p-2 font-mono break-all">{c.target}</td>
                    <td className="p-2">{c.enabled ? "yes" : "no"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Failover timeline */}
      <section>
        <h2 className="text-lg font-semibold mb-2">
          Failover events (last 24 h)
        </h2>
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
      <section className="flex gap-2 flex-wrap">
        <button
          onClick={demote}
          disabled={busy}
          className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-white text-sm"
        >
          Demote this node
        </button>
        <button
          onClick={forceSync}
          disabled={busy}
          className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white text-sm"
        >
          Force sync from peer
        </button>
      </section>
    </div>
  );
}
