"use client";

import { useEffect, useState, useCallback } from "react";
import { validateCIDR, validateIP } from "@/lib/validate";

interface StaticRoute {
  id: string;
  destination: string;
  gateway: string;
  interface: string | null;
  metric: number;
  enabled: boolean;
  description: string | null;
  created_at: string;
  fib: number;
}

interface RoutingInstance {
  id: string;
  name: string;
  fib_number: number;
  mgmt_reachable: boolean;
}

interface SystemRoute {
  destination: string;
  gateway: string;
  flags: string;
  interface: string;
}

interface InterfaceInfo {
  name: string;
  ipv4: string | null;
  ipv6: string | null;
  status: string;
  mac: string | null;
}

interface RouteForm {
  destination: string;
  gateway: string;
  interface: string;
  metric: string;
  enabled: boolean;
  description: string;
  fib: number;
}

const emptyForm: RouteForm = {
  destination: "",
  gateway: "",
  interface: "",
  metric: "100",
  enabled: true,
  description: "",
  fib: 0,
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export default function RoutesPage() {
  const [staticRoutes, setStaticRoutes] = useState<StaticRoute[]>([]);
  const [systemRoutes, setSystemRoutes] = useState<SystemRoute[]>([]);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [systemFib, setSystemFib] = useState<number>(0);
  const [form, setForm] = useState<RouteForm>({ ...emptyForm });
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStaticRoutes = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/routes", { headers: authHeaders() });
      if (!res.ok) throw new Error("Failed to fetch static routes");
      const json = await res.json();
      setStaticRoutes(json.data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch static routes");
    }
  }, []);

  const fetchSystemRoutes = useCallback(async (fib: number = systemFib) => {
    try {
      const res = await fetch(`/api/v1/routes/system?fib=${fib}`, { headers: authHeaders() });
      if (!res.ok) throw new Error("Failed to fetch system routes");
      const json = await res.json();
      setSystemRoutes(json.data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch system routes");
    }
  }, [systemFib]);

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/interfaces", { headers: authHeaders() });
      if (!res.ok) throw new Error("Failed to fetch interfaces");
      const json = await res.json();
      setInterfaces(json.data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch interfaces");
    }
  }, []);

  const fetchInstances = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/multiwan/instances", { headers: authHeaders() });
      if (!res.ok) return; // gracefully handle users without multiwan:read
      const json = await res.json();
      setInstances(json.data || []);
    } catch { /* optional */ }
  }, []);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    await Promise.all([fetchStaticRoutes(), fetchSystemRoutes(), fetchInterfaces(), fetchInstances()]);
    setLoading(false);
  }, [fetchStaticRoutes, fetchSystemRoutes, fetchInterfaces, fetchInstances]);

  // Refetch system routes when the viewer FIB changes.
  useEffect(() => { fetchSystemRoutes(systemFib); }, [systemFib, fetchSystemRoutes]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    // Client-side validation
    const errors: string[] = [];
    { const e = validateCIDR(form.destination, "Destination"); if (e) errors.push(e); }
    { const e = validateIP(form.gateway, "Gateway"); if (e) errors.push(e); }
    if (errors.length > 0) { setError(errors.join(". ")); return; }

    setSaving(true);
    setError(null);

    const body: Record<string, unknown> = {
      destination: form.destination,
      gateway: form.gateway,
      enabled: form.enabled,
      fib: form.fib,
    };
    if (form.interface) body.interface = form.interface;
    if (form.metric) body.metric = parseInt(form.metric, 10);
    if (form.description) body.description = form.description;

    try {
      const url = editingId ? `/api/v1/routes/${editingId}` : "/api/v1/routes";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(errBody?.message || `Failed to ${editingId ? "update" : "create"} route`);
      }
      setForm({ ...emptyForm });
      setEditingId(null);
      await fetchStaticRoutes();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  function startEdit(route: StaticRoute) {
    setEditingId(route.id);
    setForm({
      destination: route.destination,
      gateway: route.gateway,
      interface: route.interface || "",
      metric: String(route.metric),
      enabled: route.enabled,
      description: route.description || "",
      fib: route.fib ?? 0,
    });
  }

  function cancelEdit() {
    setEditingId(null);
    setForm({ ...emptyForm });
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this static route?")) return;
    setError(null);
    try {
      const res = await fetch(`/api/v1/routes/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error("Failed to delete route");
      await fetchStaticRoutes();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  async function toggleEnabled(route: StaticRoute) {
    setError(null);
    try {
      const res = await fetch(`/api/v1/routes/${route.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ ...route, enabled: !route.enabled }),
      });
      if (!res.ok) throw new Error("Failed to toggle route");
      await fetchStaticRoutes();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Toggle failed");
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Network Routes</h1>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* ─── Static Routes ─── */}
      <section className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Static Routes</h2>
          <span className="text-xs text-gray-400">{staticRoutes.length} route{staticRoutes.length !== 1 ? "s" : ""}</span>
        </div>

        {/* Add / Edit form */}
        <form onSubmit={handleSubmit} className="px-6 py-4 border-b border-gray-700 bg-gray-800/60">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 items-end">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Destination *</label>
              <input
                required
                value={form.destination}
                onChange={(e) => setForm({ ...form, destination: e.target.value })}
                placeholder="10.0.0.0/8"
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Gateway *</label>
              <input
                required
                value={form.gateway}
                onChange={(e) => setForm({ ...form, gateway: e.target.value })}
                placeholder="192.168.1.1"
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Interface</label>
              <select
                value={form.interface}
                onChange={(e) => setForm({ ...form, interface: e.target.value })}
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              >
                <option value="">Auto</option>
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Metric</label>
              <input
                type="number"
                min={0}
                value={form.metric}
                onChange={(e) => setForm({ ...form, metric: e.target.value })}
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">
                Routing table (FIB)
              </label>
              <select
                value={form.fib}
                onChange={(e) => setForm({ ...form, fib: parseInt(e.target.value, 10) || 0 })}
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              >
                <option value={0}>default (FIB 0 — main)</option>
                {instances
                  .filter((i) => i.fib_number !== 0)
                  .sort((a, b) => a.fib_number - b.fib_number)
                  .map((i) => (
                    <option key={i.id} value={i.fib_number}>
                      {i.name} (FIB {i.fib_number})
                    </option>
                  ))}
              </select>
              <p className="text-[10px] text-gray-500 mt-1">
                Route lives in this FreeBSD FIB. Requires a routing instance
                (Multi-WAN) for FIB &gt; 0.
              </p>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Description</label>
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="Optional note"
                className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={saving}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
              >
                {saving ? "Saving..." : editingId ? "Update" : "Add Route"}
              </button>
              {editingId && (
                <button
                  type="button"
                  onClick={cancelEdit}
                  className="bg-gray-600 hover:bg-gray-500 text-white text-sm px-3 py-2 rounded-md transition-colors"
                >
                  Cancel
                </button>
              )}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2">
            <input
              id="route-enabled"
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500"
            />
            <label htmlFor="route-enabled" className="text-xs text-gray-400">
              Enabled
            </label>
          </div>
        </form>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase bg-gray-900/40">
              <tr>
                <th className="px-6 py-3">Destination</th>
                <th className="px-6 py-3">Gateway</th>
                <th className="px-6 py-3">Interface</th>
                <th className="px-6 py-3">FIB</th>
                <th className="px-6 py-3">Metric</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Description</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {staticRoutes.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-8 text-center text-gray-500">
                    No static routes configured
                  </td>
                </tr>
              ) : (
                staticRoutes.map((route) => {
                  const inst = instances.find((i) => i.fib_number === (route.fib ?? 0));
                  return (
                  <tr key={route.id} className="hover:bg-gray-700/30 transition-colors cursor-pointer" onClick={() => startEdit(route)}>
                    <td className="px-6 py-3 font-mono text-white">{route.destination}</td>
                    <td className="px-6 py-3 font-mono text-gray-300">{route.gateway}</td>
                    <td className="px-6 py-3 text-gray-300">{route.interface || "auto"}</td>
                    <td className="px-6 py-3">
                      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                        FIB {route.fib ?? 0}
                        {inst && <span className="text-[10px] opacity-70">· {inst.name}</span>}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-300">{route.metric}</td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => toggleEnabled(route)}
                        className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full transition-colors ${
                          route.enabled
                            ? "bg-green-900/40 text-green-400 hover:bg-green-900/60"
                            : "bg-gray-700 text-gray-400 hover:bg-gray-600"
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${route.enabled ? "bg-green-400" : "bg-gray-500"}`} />
                        {route.enabled ? "Enabled" : "Disabled"}
                      </button>
                    </td>
                    <td className="px-6 py-3 text-gray-400 text-xs max-w-[200px] truncate">
                      {route.description || "--"}
                    </td>
                    <td className="px-6 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => startEdit(route)}
                          className="text-blue-400 hover:text-blue-300 text-xs transition-colors"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(route.id)}
                          className="text-red-400 hover:text-red-300 text-xs transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ─── System Routing Table ─── */}
      <section className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-lg font-semibold text-white">System Routing Table</h2>
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400">FIB:</label>
            <select
              value={systemFib}
              onChange={(e) => setSystemFib(parseInt(e.target.value, 10) || 0)}
              className="bg-gray-900 border border-gray-600 rounded text-white text-xs px-2 py-1"
            >
              <option value={0}>default (FIB 0)</option>
              {instances
                .filter((i) => i.fib_number !== 0)
                .sort((a, b) => a.fib_number - b.fib_number)
                .map((i) => (
                  <option key={i.id} value={i.fib_number}>
                    {i.name} (FIB {i.fib_number})
                  </option>
                ))}
            </select>
            <button
              onClick={() => fetchSystemRoutes(systemFib)}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-md transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Refresh
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase bg-gray-900/40">
              <tr>
                <th className="px-6 py-3">Destination</th>
                <th className="px-6 py-3">Gateway</th>
                <th className="px-6 py-3">Flags</th>
                <th className="px-6 py-3">Interface</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {systemRoutes.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-gray-500">
                    No system routes available
                  </td>
                </tr>
              ) : (
                systemRoutes.map((route, idx) => (
                  <tr key={idx} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-6 py-3 font-mono text-white">{route.destination}</td>
                    <td className="px-6 py-3 font-mono text-gray-300">{route.gateway}</td>
                    <td className="px-6 py-3">
                      <span className="font-mono text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">
                        {route.flags}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-300">{route.interface}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ─── Network Interfaces ─── */}
      <section className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Network Interfaces</h2>
          <button
            onClick={fetchInterfaces}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-md transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </button>
        </div>
        <div className="p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {interfaces.length === 0 ? (
            <p className="text-gray-500 col-span-full text-center py-4">No interfaces detected</p>
          ) : (
            interfaces.map((iface) => (
              <div
                key={iface.name}
                className="bg-gray-900 rounded-lg border border-gray-700 p-4 space-y-3"
              >
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white font-mono">{iface.name}</h3>
                  <span
                    className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full ${
                      iface.status === "up"
                        ? "bg-green-900/40 text-green-400"
                        : "bg-red-900/40 text-red-400"
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        iface.status === "up" ? "bg-green-400" : "bg-red-400"
                      }`}
                    />
                    {iface.status.toUpperCase()}
                  </span>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <span className="text-gray-400">IPv4</span>
                    <span className="text-gray-200 font-mono">{iface.ipv4 || "--"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">IPv6</span>
                    <span className="text-gray-200 font-mono text-right max-w-[180px] truncate">
                      {iface.ipv6 || "--"}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">MAC</span>
                    <span className="text-gray-200 font-mono">{iface.mac || "--"}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
