"use client";

import { useState, useEffect, useCallback } from "react";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface Gateway {
  id: string;
  name: string;
  instance_id: string;
  interface: string;
  next_hop: string;
  ip_version: string;
  monitor_kind: string;
  monitor_target: string | null;
  state: string;
  last_rtt_ms: number | null;
  last_jitter_ms: number | null;
  last_loss_pct: number | null;
  last_mos: number | null;
  last_probe_ts: string | null;
  enabled: boolean;
  weight: number;
}

interface RoutingInstance {
  id: string;
  name: string;
  fib_number: number;
}

const stateColor: Record<string, string> = {
  up: "bg-green-500/20 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  down: "bg-red-500/20 text-red-400 border-red-500/30",
  unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function GatewaysPage() {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [instanceId, setInstanceId] = useState("");
  const [iface, setIface] = useState("");
  const [nextHop, setNextHop] = useState("");
  const [monitorKind, setMonitorKind] = useState("icmp");
  const [monitorTarget, setMonitorTarget] = useState("");

  const fetchAll = useCallback(async () => {
    try {
      const [gRes, iRes] = await Promise.all([
        fetch(`${API}/api/v1/multiwan/gateways`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/multiwan/instances`, { headers: authHeaders() }),
      ]);
      if (!gRes.ok || !iRes.ok) throw new Error("Failed to load");
      const g = await gRes.json();
      const i = await iRes.json();
      setGateways(g.data || []);
      setInstances(i.data || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const t = setInterval(fetchAll, 5000);
    return () => clearInterval(t);
  }, [fetchAll]);

  async function createGateway(e: React.FormEvent) {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/v1/multiwan/gateways`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          name,
          instance_id: instanceId,
          interface: iface,
          next_hop: nextHop,
          monitor_kind: monitorKind,
          monitor_target: monitorTarget || nextHop,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      setName("");
      setIface("");
      setNextHop("");
      setMonitorTarget("");
      setShowForm(false);
      await fetchAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function deleteGw(id: string) {
    if (!confirm("Delete gateway?")) return;
    try {
      const res = await fetch(`${API}/api/v1/multiwan/gateways/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(await res.text());
      await fetchAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  async function probeNow(id: string, success: boolean) {
    try {
      await fetch(`${API}/api/v1/multiwan/gateways/${id}/probe-now`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          success,
          rtt_ms: success ? 10.0 : null,
          error: success ? null : "manual fail",
        }),
      });
      await fetchAll();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Probe failed");
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Gateways</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Monitored next-hops with live RTT/jitter/loss and MOS scoring.
          </p>
        </div>
        <button
          onClick={() => setShowForm((s) => !s)}
          className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
        >
          {showForm ? "Cancel" : "+ Add Gateway"}
        </button>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      {showForm && (
        <form
          onSubmit={createGateway}
          className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 grid grid-cols-1 md:grid-cols-3 gap-2"
        >
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="name (e.g. wan1-gw)"
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <select
            value={instanceId}
            onChange={(e) => setInstanceId(e.target.value)}
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          >
            <option value="">Routing instance…</option>
            {instances.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name} (FIB {i.fib_number})
              </option>
            ))}
          </select>
          <input
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            placeholder="interface (em1)"
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <input
            value={nextHop}
            onChange={(e) => setNextHop(e.target.value)}
            placeholder="next-hop IP (203.0.113.1)"
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <select
            value={monitorKind}
            onChange={(e) => setMonitorKind(e.target.value)}
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          >
            <option value="icmp">ICMP ping</option>
            <option value="tcp">TCP connect</option>
            <option value="http">HTTP GET</option>
            <option value="dns">DNS query</option>
          </select>
          <input
            value={monitorTarget}
            onChange={(e) => setMonitorTarget(e.target.value)}
            placeholder="monitor target (defaults to next-hop)"
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <button
            type="submit"
            className="md:col-span-3 px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
          >
            Create gateway
          </button>
        </form>
      )}

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : gateways.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">
            No gateways yet. Add one to start monitoring.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">State</th>
                <th className="text-left px-4 py-2">Next-Hop</th>
                <th className="text-left px-4 py-2">Monitor</th>
                <th className="text-right px-4 py-2">RTT</th>
                <th className="text-right px-4 py-2">Jitter</th>
                <th className="text-right px-4 py-2">Loss</th>
                <th className="text-right px-4 py-2">MOS</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {gateways.map((gw) => (
                <tr key={gw.id} className="border-t border-[var(--border)]">
                  <td className="px-4 py-3 text-white font-medium">{gw.name}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`text-xs px-2 py-1 rounded border ${stateColor[gw.state] || stateColor.unknown}`}
                    >
                      {gw.state}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-cyan-400 font-mono text-xs">
                    {gw.interface} → {gw.next_hop}
                  </td>
                  <td className="px-4 py-3 text-[var(--text-muted)] text-xs">
                    {gw.monitor_kind} {gw.monitor_target}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)] font-mono">
                    {gw.last_rtt_ms != null ? `${gw.last_rtt_ms.toFixed(1)}ms` : "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)] font-mono">
                    {gw.last_jitter_ms != null ? `${gw.last_jitter_ms.toFixed(1)}ms` : "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)] font-mono">
                    {gw.last_loss_pct != null ? `${gw.last_loss_pct.toFixed(0)}%` : "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)] font-mono">
                    {gw.last_mos != null ? gw.last_mos.toFixed(2) : "—"}
                  </td>
                  <td className="px-4 py-3 text-right space-x-1">
                    <button
                      onClick={() => probeNow(gw.id, true)}
                      className="text-xs px-2 py-1 rounded bg-green-600/80 hover:bg-green-700 text-white"
                      title="Inject success"
                    >
                      ✓
                    </button>
                    <button
                      onClick={() => probeNow(gw.id, false)}
                      className="text-xs px-2 py-1 rounded bg-yellow-600/80 hover:bg-yellow-700 text-white"
                      title="Inject failure"
                    >
                      ✗
                    </button>
                    <button
                      onClick={() => deleteGw(gw.id)}
                      className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                    >
                      Del
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
