"use client";

import { useEffect, useState, useCallback } from "react";
import { validateCIDR, isValidIP, isValidCIDR } from "@/lib/validate";

type FieldErrors = Partial<Record<
  "vlan_id" | "parent" | "ipv4_address" | "ipv6_address" | "mtu",
  string
>>;

interface VlanConfig {
  id: string;
  vlan_id: number;
  parent: string;
  ipv4_mode: string;
  ipv4_address: string | null;
  ipv6_address: string | null;
  mtu: number;
  enabled: boolean;
  description: string | null;
  created_at: string;
}

interface InterfaceInfo {
  name: string;
  is_vlan: boolean;
}

interface VlanForm {
  vlan_id: string;
  parent: string;
  ipv4_mode: string;
  ipv4_address: string;
  ipv6_address: string;
  mtu: string;
  enabled: boolean;
  description: string;
}

const emptyForm: VlanForm = {
  vlan_id: "",
  parent: "",
  ipv4_mode: "none",
  ipv4_address: "",
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

export default function VlansPage() {
  const [vlans, setVlans] = useState<VlanConfig[]>([]);
  const [physicalInterfaces, setPhysicalInterfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<VlanForm>({ ...emptyForm });
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [saving, setSaving] = useState(false);

  const fetchVlans = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/vlans", { headers: authHeaders() });
      if (!res.ok) throw new Error("Failed to fetch VLANs");
      const json = await res.json();
      setVlans(json.data || []);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch VLANs");
    }
  }, []);

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/interfaces/detailed", {
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error("Failed to fetch interfaces");
      const json = await res.json();
      const physical = (json.data || [])
        .filter((i: InterfaceInfo) => !i.is_vlan && !i.name.startsWith("lo"))
        .map((i: InterfaceInfo) => i.name);
      setPhysicalInterfaces(physical);
    } catch (e: unknown) {
      setError(
        e instanceof Error ? e.message : "Failed to fetch interfaces"
      );
    }
  }, []);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    await Promise.all([fetchVlans(), fetchInterfaces()]);
    setLoading(false);
  }, [fetchVlans, fetchInterfaces]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  function openAdd() {
    setEditingId(null);
    setForm({ ...emptyForm });
    setFieldErrors({});
    setError(null);
    setModalOpen(true);
  }

  function openEdit(vlan: VlanConfig) {
    setEditingId(vlan.id);
    setForm({
      vlan_id: String(vlan.vlan_id),
      parent: vlan.parent,
      ipv4_mode: vlan.ipv4_mode || "none",
      ipv4_address: vlan.ipv4_address || "",
      ipv6_address: vlan.ipv6_address || "",
      mtu: String(vlan.mtu),
      enabled: vlan.enabled,
      description: vlan.description || "",
    });
    setFieldErrors({});
    setError(null);
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
    setForm({ ...emptyForm });
    setFieldErrors({});
  }

  function validateForm(): FieldErrors {
    const errs: FieldErrors = {};
    const vid = parseInt(form.vlan_id, 10);
    if (!form.vlan_id.trim() || isNaN(vid) || vid < 1 || vid > 4094) {
      errs.vlan_id = "Must be between 1 and 4094.";
    }
    if (!form.parent.trim()) {
      errs.parent = "Select a parent interface.";
    }
    if (form.ipv4_mode === "static") {
      const addr = form.ipv4_address.trim();
      if (!addr) {
        errs.ipv4_address = "Required when IPv4 mode is Static (e.g. 192.168.1.1/24).";
      } else {
        const cidrErr = validateCIDR(addr, "IPv4 address");
        if (cidrErr) errs.ipv4_address = cidrErr;
      }
    }
    const v6 = form.ipv6_address.trim();
    if (v6) {
      const v6Valid = v6.includes("/") ? isValidCIDR(v6) : isValidIP(v6);
      if (!v6Valid) errs.ipv6_address = "Invalid IPv6 address (e.g. fe80::1 or fe80::1/64).";
    }
    const mtu = parseInt(form.mtu, 10);
    if (!form.mtu.trim() || isNaN(mtu) || mtu < 68 || mtu > 9000) {
      errs.mtu = "MTU must be between 68 and 9000.";
    }
    return errs;
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();

    const errs = validateForm();
    setFieldErrors(errs);
    if (Object.keys(errs).length > 0) { setError(null); return; }

    setSaving(true);
    setError(null);

    const body: Record<string, unknown> = {
      vlan_id: parseInt(form.vlan_id, 10),
      parent: form.parent.trim(),
      ipv4_mode: form.ipv4_mode,
      mtu: parseInt(form.mtu, 10),
      enabled: form.enabled,
    };
    if (form.ipv4_mode === "static" && form.ipv4_address.trim()) {
      body.ipv4_address = form.ipv4_address.trim();
    }
    if (form.ipv6_address.trim()) {
      body.ipv6_address = form.ipv6_address.trim();
    }
    if (form.description.trim()) {
      body.description = form.description.trim();
    }

    try {
      const url = editingId ? `/api/v1/vlans/${editingId}` : "/api/v1/vlans";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(
          errBody?.message ||
            `Failed to ${editingId ? "update" : "create"} VLAN`
        );
      }
      closeModal();
      await fetchVlans();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this VLAN? This action cannot be undone.")) return;
    setError(null);
    try {
      const res = await fetch(`/api/v1/vlans/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error("Failed to delete VLAN");
      await fetchVlans();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Delete failed");
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
          <h1 className="text-2xl font-bold text-white">VLAN Management</h1>
          <p className="text-sm text-gray-400">
            {vlans.length} VLAN{vlans.length !== 1 ? "s" : ""} configured
          </p>
        </div>
        <button
          onClick={openAdd}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add VLAN
        </button>
      </div>

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
                <th className="px-6 py-3">VLAN ID</th>
                <th className="px-6 py-3">Parent Interface</th>
                <th className="px-6 py-3">IPv4</th>
                <th className="px-6 py-3">IPv6</th>
                <th className="px-6 py-3">MTU</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Description</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {vlans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-8 text-center text-gray-500">
                    No VLANs configured
                  </td>
                </tr>
              ) : (
                vlans.map((vlan) => (
                  <tr
                    key={vlan.id}
                    className="hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="px-6 py-3 font-mono text-white font-medium">
                      {vlan.vlan_id}
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-300">
                      {vlan.parent}
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-300 text-xs">
                      {vlan.ipv4_address || "--"}
                    </td>
                    <td className="px-6 py-3 font-mono text-gray-300 text-xs max-w-[180px] truncate">
                      {vlan.ipv6_address || "--"}
                    </td>
                    <td className="px-6 py-3 text-gray-300">{vlan.mtu}</td>
                    <td className="px-6 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full ${
                          vlan.enabled
                            ? "bg-green-900/40 text-green-400"
                            : "bg-gray-700 text-gray-400"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            vlan.enabled ? "bg-green-400" : "bg-gray-500"
                          }`}
                        />
                        {vlan.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-400 text-xs max-w-[200px] truncate">
                      {vlan.description || "--"}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => openEdit(vlan)}
                          className="text-blue-400 hover:text-blue-300 text-xs transition-colors"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(vlan.id)}
                          className="text-red-400 hover:text-red-300 text-xs transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Add / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg mx-4 shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">
                {editingId ? "Edit VLAN" : "Add VLAN"}
              </h2>
              <button
                onClick={closeModal}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleSave} className="p-6 space-y-4">
              {/* VLAN ID */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  VLAN ID (1-4094) *
                </label>
                <input
                  type="number"
                  required
                  min={1}
                  max={4094}
                  value={form.vlan_id}
                  onChange={(e) =>
                    setForm({ ...form, vlan_id: e.target.value })
                  }
                  placeholder="100"
                  className={`w-full bg-gray-900 border rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none ${
                    fieldErrors.vlan_id ? "border-red-600 focus:border-red-500" : "border-gray-600 focus:border-blue-500"
                  }`}
                />
                {fieldErrors.vlan_id && (
                  <p className="mt-1 text-xs text-red-400">{fieldErrors.vlan_id}</p>
                )}
              </div>

              {/* Parent Interface */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  Parent Interface *
                </label>
                <select
                  required
                  value={form.parent}
                  onChange={(e) =>
                    setForm({ ...form, parent: e.target.value })
                  }
                  className={`w-full bg-gray-900 border rounded-md px-3 py-2 text-sm text-white focus:outline-none ${
                    fieldErrors.parent ? "border-red-600 focus:border-red-500" : "border-gray-600 focus:border-blue-500"
                  }`}
                >
                  <option value="">Select interface...</option>
                  {physicalInterfaces.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </select>
                {fieldErrors.parent && (
                  <p className="mt-1 text-xs text-red-400">{fieldErrors.parent}</p>
                )}
              </div>

              {/* IPv4 Mode */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  IPv4 Mode
                </label>
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
                <div>
                  <label className="block text-xs text-gray-400 mb-1">
                    IPv4 Address (with /prefix)
                  </label>
                  <input
                    value={form.ipv4_address}
                    onChange={(e) =>
                      setForm({ ...form, ipv4_address: e.target.value })
                    }
                    placeholder="192.168.100.1/24"
                    className={`w-full bg-gray-900 border rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none ${
                      fieldErrors.ipv4_address ? "border-red-600 focus:border-red-500" : "border-gray-600 focus:border-blue-500"
                    }`}
                  />
                  {fieldErrors.ipv4_address && (
                    <p className="mt-1 text-xs text-red-400">{fieldErrors.ipv4_address}</p>
                  )}
                </div>
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
                  className={`w-full bg-gray-900 border rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none ${
                    fieldErrors.ipv6_address ? "border-red-600 focus:border-red-500" : "border-gray-600 focus:border-blue-500"
                  }`}
                />
                {fieldErrors.ipv6_address && (
                  <p className="mt-1 text-xs text-red-400">{fieldErrors.ipv6_address}</p>
                )}
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
                  className={`w-full bg-gray-900 border rounded-md px-3 py-2 text-sm text-white focus:outline-none ${
                    fieldErrors.mtu ? "border-red-600 focus:border-red-500" : "border-gray-600 focus:border-blue-500"
                  }`}
                />
                {fieldErrors.mtu && (
                  <p className="mt-1 text-xs text-red-400">{fieldErrors.mtu}</p>
                )}
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

              {/* Enable toggle */}
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

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                <button
                  type="submit"
                  disabled={saving}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
                >
                  {saving
                    ? "Saving..."
                    : editingId
                    ? "Update VLAN"
                    : "Create VLAN"}
                </button>
                <button
                  type="button"
                  onClick={closeModal}
                  className="bg-gray-600 hover:bg-gray-500 text-white text-sm px-4 py-2 rounded-md transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
