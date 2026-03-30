"use client";

import { useEffect, useState, useCallback, useRef } from "react";

interface InterfaceDetail {
  name: string;
  mac: string | null;
  ipv4: string | null;
  ipv4_netmask: string | null;
  ipv6: string | null;
  status: string;
  mtu: number;
  media: string | null;
  description: string | null;
  is_vlan: boolean;
  vlan_id: number | null;
  vlan_parent: string | null;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  errors_in: number;
  errors_out: number;
  gateway: string | null;
  ipv4_mode: string | null;
}

interface InterfaceForm {
  ipv4_mode: string;
  ipv4_address: string;
  gateway: string;
  ipv6_address: string;
  mtu: string;
  enabled: boolean;
  description: string;
}

const emptyForm: InterfaceForm = {
  ipv4_mode: "dhcp",
  ipv4_address: "",
  gateway: "",
  ipv6_address: "",
  mtu: "1500",
  enabled: true,
  description: "",
};

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(1)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export default function InterfacesPage() {
  const [interfaces, setInterfaces] = useState<InterfaceDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [editingName, setEditingName] = useState<string | null>(null);
  const [form, setForm] = useState<InterfaceForm>({ ...emptyForm });
  const [saving, setSaving] = useState(false);
  const initialLoad = useRef(true);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 8000);
  };

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/interfaces/detailed", {
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error("Failed to fetch interfaces");
      const json = await res.json();
      const filtered = (json.data || []).filter(
        (i: InterfaceDetail) => !i.name.startsWith("lo")
      );
      setInterfaces(filtered);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch interfaces");
    } finally {
      if (initialLoad.current) {
        setLoading(false);
        initialLoad.current = false;
      }
    }
  }, []);

  useEffect(() => {
    fetchInterfaces();
    const interval = setInterval(fetchInterfaces, 10000);
    return () => clearInterval(interval);
  }, [fetchInterfaces]);

  function openEdit(iface: InterfaceDetail) {
    setEditingName(iface.name);
    setForm({
      ipv4_mode: iface.ipv4_mode || (iface.ipv4 ? "static" : "dhcp"),
      ipv4_address: iface.ipv4 || "",
      gateway: iface.gateway || "",
      ipv6_address: iface.ipv6 || "",
      mtu: String(iface.mtu),
      enabled: iface.status === "up",
      description: iface.description || "",
    });
  }

  function closeEdit() {
    setEditingName(null);
    setForm({ ...emptyForm });
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!editingName) return;
    setSaving(true);
    setError(null);

    const body: Record<string, unknown> = {
      mtu: parseInt(form.mtu, 10),
      enabled: form.enabled,
      description: form.description || undefined,
      ipv4_mode: form.ipv4_mode,
    };
    if (form.ipv4_mode === "static") {
      if (form.ipv4_address) body.ipv4_address = form.ipv4_address;
      body.gateway = form.gateway || "";
    }
    if (form.ipv6_address) {
      body.ipv6_address = form.ipv6_address;
    }

    try {
      const res = await fetch(
        `/api/v1/interfaces/config/${encodeURIComponent(editingName)}`,
        {
          method: "PUT",
          headers: authHeaders(),
          body: JSON.stringify(body),
        }
      );
      const data = await res.json().catch(() => ({ message: "" }));
      if (!res.ok) {
        throw new Error(data?.message || "Failed to update interface");
      }
      showFeedback("success", data.message || `Interface ${editingName} configured`);
      closeEdit();
      // Wait briefly for changes to take effect before refreshing
      setTimeout(() => fetchInterfaces(), 1500);
    } catch (e: unknown) {
      showFeedback("error", e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
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
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Interface Management</h1>
          <p className="text-sm text-gray-400">
            {interfaces.length} interface{interfaces.length !== 1 ? "s" : ""} &middot; auto-refreshing every 10s
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-xs text-green-400 font-medium">Live</span>
          </div>
        </div>
      </div>

      {/* Feedback */}
      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success"
            ? "bg-green-500/10 border-green-500/30 text-green-400"
            : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>{feedback.msg}</div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Table */}
      <section className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase bg-gray-900/40">
              <tr>
                <th className="px-6 py-3">Name</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Mode</th>
                <th className="px-6 py-3">IPv4</th>
                <th className="px-6 py-3">Gateway</th>
                <th className="px-6 py-3">MAC</th>
                <th className="px-6 py-3">MTU</th>
                <th className="px-6 py-3">Traffic</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {interfaces.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-6 py-8 text-center text-gray-500">
                    No interfaces detected
                  </td>
                </tr>
              ) : (
                interfaces.map((iface) => (
                  <tr
                    key={iface.name}
                    className="hover:bg-gray-700/30 transition-colors cursor-pointer"
                    onClick={() => openEdit(iface)}
                  >
                    <td className="px-6 py-3 font-mono text-white font-medium">
                      {iface.name}
                    </td>
                    <td className="px-6 py-3">
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
                        {iface.status === "up" ? "UP" : "DOWN"}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${
                        iface.ipv4_mode === "dhcp"
                          ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
                          : iface.ipv4_mode === "static"
                            ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                            : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                      }`}>
                        {iface.ipv4_mode || "--"}
                      </span>
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-300 text-xs">
                      {iface.ipv4 || "--"}
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-300 text-xs">
                      {iface.gateway || "--"}
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-400 text-xs">
                      {iface.mac || "--"}
                    </td>
                    <td className="px-6 py-3 text-gray-300">{iface.mtu}</td>
                    <td className="px-6 py-3">
                      <div className="text-xs font-mono">
                        <span className="text-green-400">{formatBytes(iface.bytes_in)}</span>
                        <span className="text-gray-500"> / </span>
                        <span className="text-blue-400">{formatBytes(iface.bytes_out)}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openEdit(iface);
                        }}
                        className="text-blue-400 hover:text-blue-300 text-xs transition-colors"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Edit Modal */}
      {editingName && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg mx-4 shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">
                Configure {editingName}
              </h2>
              <button
                onClick={closeEdit}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4">
              {/* IPv4 Mode */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">IPv4 Mode</label>
                <select
                  value={form.ipv4_mode}
                  onChange={(e) =>
                    setForm({ ...form, ipv4_mode: e.target.value })
                  }
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="dhcp">DHCP</option>
                  <option value="static">Static</option>
                  <option value="none">None</option>
                </select>
              </div>

              {/* IPv4 Address (static only) */}
              {form.ipv4_mode === "static" && (
                <>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">
                      IPv4 Address (with /prefix)
                    </label>
                    <input
                      value={form.ipv4_address}
                      onChange={(e) =>
                        setForm({ ...form, ipv4_address: e.target.value })
                      }
                      placeholder="192.168.1.1/24"
                      className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">
                      Default Gateway
                    </label>
                    <input
                      value={form.gateway}
                      onChange={(e) =>
                        setForm({ ...form, gateway: e.target.value })
                      }
                      placeholder="192.168.1.254"
                      className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </>
              )}

              {/* IPv6 Address */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  IPv6 Address (optional)
                </label>
                <input
                  value={form.ipv6_address}
                  onChange={(e) =>
                    setForm({ ...form, ipv6_address: e.target.value })
                  }
                  placeholder="fe80::1/64"
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* MTU */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">MTU</label>
                <input
                  type="number"
                  min={68}
                  max={9000}
                  value={form.mtu}
                  onChange={(e) => setForm({ ...form, mtu: e.target.value })}
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Enable/Disable */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setForm({ ...form, enabled: !form.enabled })}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    form.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      form.enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
                <span className="text-sm text-gray-300">
                  {form.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>

              {/* Description */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  Description
                </label>
                <input
                  value={form.description}
                  onChange={(e) =>
                    setForm({ ...form, description: e.target.value })
                  }
                  placeholder="Optional description"
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                <button
                  type="submit"
                  disabled={saving}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
                >
                  {saving ? "Applying..." : "Apply"}
                </button>
                <button
                  type="button"
                  onClick={closeEdit}
                  className="bg-gray-600 hover:bg-gray-500 text-white text-sm px-4 py-2 rounded-md transition-colors"
                >
                  Cancel
                </button>
              </div>
              <p className="text-[10px] text-gray-500 text-center">
                Changes apply immediately and persist across reboots
              </p>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
