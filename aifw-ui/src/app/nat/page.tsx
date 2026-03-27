"use client";

import { useState, useEffect, useCallback } from "react";
import { api, NatRule, CreateNatRequest, UpdateNatRequest } from "@/lib/api";

const defaultForm = {
  nat_type: "dnat",
  interface: "em0",
  protocol: "tcp",
  src_addr: "",
  src_port_start: "",
  src_port_end: "",
  dst_addr: "",
  dst_port_start: "",
  dst_port_end: "",
  redirect_addr: "",
  redirect_port_start: "",
  redirect_port_end: "",
  label: "",
  status: "active",
};

type FormState = typeof defaultForm;

function natTypeBadge(natType: string) {
  const colors: Record<string, string> = {
    rdr: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    dnat: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    nat: "bg-green-500/20 text-green-400 border-green-500/30",
    snat: "bg-green-500/20 text-green-400 border-green-500/30",
    masquerade: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    binat: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  };
  const cls = colors[natType.toLowerCase()] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`inline-flex items-center rounded border text-[10px] px-1.5 py-0.5 font-medium uppercase tracking-wider ${cls}`}>
      {natType}
    </span>
  );
}

function formatPort(port: { start: number; end: number } | null | undefined): string {
  if (!port) return "";
  if (port.start === port.end) return String(port.start);
  return `${port.start}-${port.end}`;
}

function formatAddrPort(addr: string, port: { start: number; end: number } | null | undefined): string {
  const portStr = formatPort(port);
  if (!portStr) return addr;
  return `${addr}:${portStr}`;
}

export default function NatPage() {
  const [natRules, setNatRules] = useState<NatRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);

  const fetchRules = useCallback(async () => {
    try {
      setError(null);
      const res = await api.listNat();
      setNatRules(res.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load NAT rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const resetForm = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (rule: NatRule) => {
    setForm({
      nat_type: rule.nat_type,
      interface: rule.interface,
      protocol: rule.protocol,
      src_addr: rule.src_addr || "",
      src_port_start: rule.src_port?.start?.toString() || "",
      src_port_end: rule.src_port?.end?.toString() || "",
      dst_addr: rule.dst_addr || "",
      dst_port_start: rule.dst_port?.start?.toString() || "",
      dst_port_end: rule.dst_port?.end?.toString() || "",
      redirect_addr: rule.redirect?.address || "",
      redirect_port_start: rule.redirect?.port?.start?.toString() || "",
      redirect_port_end: rule.redirect?.port?.end?.toString() || "",
      label: rule.label || "",
      status: rule.status,
    });
    setEditingId(rule.id);
    setShowForm(true);
  };

  const buildRequestBody = (): CreateNatRequest | UpdateNatRequest => {
    const body: Record<string, unknown> = {
      nat_type: form.nat_type,
      interface: form.interface,
      protocol: form.protocol,
      src_addr: form.src_addr || "any",
      dst_addr: form.dst_addr || "any",
      redirect_addr: form.redirect_addr,
    };

    if (form.src_port_start) body.src_port_start = parseInt(form.src_port_start, 10);
    if (form.dst_port_start) body.dst_port_start = parseInt(form.dst_port_start, 10);
    if (form.redirect_port_start) body.redirect_port_start = parseInt(form.redirect_port_start, 10);
    if (form.label.trim()) body.label = form.label.trim();
    body.status = form.status;

    return body as unknown as CreateNatRequest | UpdateNatRequest;
  };

  const handleSubmit = async () => {
    if (!form.redirect_addr.trim()) return;
    setSubmitting(true);
    try {
      if (editingId) {
        await api.updateNat(editingId, buildRequestBody() as UpdateNatRequest);
      } else {
        await api.createNat(buildRequestBody() as CreateNatRequest);
      }
      await fetchRules();
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save NAT rule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (rule: NatRule) => {
    try {
      await api.deleteNat(rule.id);
      setNatRules((prev) => prev.filter((r) => r.id !== rule.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete NAT rule");
    }
  };

  const handleToggleStatus = async (rule: NatRule) => {
    const newStatus = rule.status === "active" ? "disabled" : "active";
    setTogglingId(rule.id);
    try {
      await api.updateNat(rule.id, {
        nat_type: rule.nat_type,
        interface: rule.interface,
        protocol: rule.protocol,
        src_addr: rule.src_addr,
        dst_addr: rule.dst_addr,
        redirect_addr: rule.redirect?.address || "",
        redirect_port_start: rule.redirect?.port?.start,
        label: rule.label || undefined,
        status: newStatus,
      } as UpdateNatRequest);
      setNatRules((prev) =>
        prev.map((r) => (r.id === rule.id ? { ...r, status: newStatus } : r))
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle status");
    } finally {
      setTogglingId(null);
    }
  };

  const updateField = (field: keyof FormState, value: string) => {
    setForm((f) => ({ ...f, [field]: value }));
  };

  const inputCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 transition-colors";
  const selectCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors";
  const labelCls = "block text-xs text-gray-400 mb-1";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">NAT Rules</h1>
          <p className="text-sm text-gray-500">
            {natRules.length} rules &middot;{" "}
            {natRules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <button
          onClick={() => {
            if (showForm && !editingId) {
              resetForm();
            } else {
              setForm(defaultForm);
              setEditingId(null);
              setShowForm(true);
            }
          }}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add NAT Rule
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Form */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-medium text-white mb-3">
            {editingId ? "Edit NAT Rule" : "New NAT Rule"}
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Type */}
            <div>
              <label className={labelCls}>Type</label>
              <select value={form.nat_type} onChange={(e) => updateField("nat_type", e.target.value)} className={selectCls}>
                <option value="dnat">dnat (Redirect)</option>
                <option value="snat">snat (Source NAT)</option>
                <option value="masquerade">masquerade</option>
                <option value="binat">binat (Bidirectional)</option>
              </select>
            </div>
            {/* Interface */}
            <div>
              <label className={labelCls}>Interface</label>
              <select value={form.interface} onChange={(e) => updateField("interface", e.target.value)} className={selectCls}>
                <option value="em0">em0</option>
                <option value="em1">em1</option>
                <option value="em2">em2</option>
                <option value="wg0">wg0</option>
                <option value="lo0">lo0</option>
              </select>
            </div>
            {/* Protocol */}
            <div>
              <label className={labelCls}>Protocol</label>
              <select value={form.protocol} onChange={(e) => updateField("protocol", e.target.value)} className={selectCls}>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="any">any</option>
              </select>
            </div>
            {/* Status (edit mode) */}
            {editingId && (
              <div>
                <label className={labelCls}>Status</label>
                <select value={form.status} onChange={(e) => updateField("status", e.target.value)} className={selectCls}>
                  <option value="active">active</option>
                  <option value="disabled">disabled</option>
                </select>
              </div>
            )}
            {/* Source Address */}
            <div>
              <label className={labelCls}>Source Address</label>
              <input
                type="text"
                value={form.src_addr}
                onChange={(e) => updateField("src_addr", e.target.value)}
                placeholder="any"
                className={inputCls}
              />
            </div>
            {/* Source Port */}
            <div>
              <label className={labelCls}>Source Port</label>
              <input
                type="text"
                value={form.src_port_start}
                onChange={(e) => updateField("src_port_start", e.target.value)}
                placeholder="e.g. 1024"
                className={inputCls}
              />
            </div>
            {/* Destination Address */}
            <div>
              <label className={labelCls}>Destination Address</label>
              <input
                type="text"
                value={form.dst_addr}
                onChange={(e) => updateField("dst_addr", e.target.value)}
                placeholder="any"
                className={inputCls}
              />
            </div>
            {/* Destination Port */}
            <div>
              <label className={labelCls}>Destination Port</label>
              <input
                type="text"
                value={form.dst_port_start}
                onChange={(e) => updateField("dst_port_start", e.target.value)}
                placeholder="e.g. 80"
                className={inputCls}
              />
            </div>
            {/* Redirect Address */}
            <div>
              <label className={labelCls}>Redirect Address</label>
              <input
                type="text"
                value={form.redirect_addr}
                onChange={(e) => updateField("redirect_addr", e.target.value)}
                placeholder="e.g. 10.0.0.5"
                className={inputCls}
              />
            </div>
            {/* Redirect Port */}
            <div>
              <label className={labelCls}>Redirect Port</label>
              <input
                type="text"
                value={form.redirect_port_start}
                onChange={(e) => updateField("redirect_port_start", e.target.value)}
                placeholder="e.g. 8080"
                className={inputCls}
              />
            </div>
            {/* Label */}
            <div className="md:col-span-2">
              <label className={labelCls}>Label</label>
              <input
                type="text"
                value={form.label}
                onChange={(e) => updateField("label", e.target.value)}
                placeholder="Rule description"
                className={inputCls}
              />
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleSubmit}
              disabled={submitting || !form.redirect_addr.trim()}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
            >
              {submitting ? "Saving..." : editingId ? "Update" : "Add"}
            </button>
            <button
              onClick={resetForm}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-gray-800 border border-gray-700 text-gray-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="text-center py-12 text-gray-500">Loading NAT rules...</div>
      )}

      {/* NAT Rules Table */}
      {!loading && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">Type</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">Interface</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-20">Protocol</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Redirect To</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Label</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-20">Status</th>
                  <th className="w-24"></th>
                </tr>
              </thead>
              <tbody>
                {natRules.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="text-center py-12 text-gray-500">
                      No NAT rules configured
                    </td>
                  </tr>
                ) : (
                  natRules.map((rule) => (
                    <tr
                      key={rule.id}
                      className="border-b border-gray-700 hover:bg-gray-750 transition-colors"
                    >
                      {/* Type */}
                      <td className="py-2.5 px-3">{natTypeBadge(rule.nat_type)}</td>
                      {/* Interface */}
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-gray-400">{rule.interface}</span>
                      </td>
                      {/* Protocol */}
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-gray-400">{rule.protocol}</span>
                      </td>
                      {/* Source */}
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-white">
                          {formatAddrPort(rule.src_addr, rule.src_port)}
                        </span>
                      </td>
                      {/* Destination */}
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-white">
                          {formatAddrPort(rule.dst_addr, rule.dst_port)}
                        </span>
                      </td>
                      {/* Redirect To */}
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-green-400">
                          {rule.redirect
                            ? formatAddrPort(rule.redirect.address, rule.redirect.port)
                            : "-"}
                        </span>
                      </td>
                      {/* Label */}
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-gray-400">{rule.label || "-"}</span>
                      </td>
                      {/* Status toggle */}
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => handleToggleStatus(rule)}
                          disabled={togglingId === rule.id}
                          className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50"
                          style={{
                            backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563",
                          }}
                          title={rule.status === "active" ? "Disable" : "Enable"}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                              rule.status === "active" ? "translate-x-[18px]" : "translate-x-[3px]"
                            }`}
                          />
                        </button>
                      </td>
                      {/* Actions */}
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1">
                          {/* Edit button */}
                          <button
                            onClick={() => handleEdit(rule)}
                            className="text-gray-500 hover:text-blue-400 transition-colors p-1"
                            title="Edit"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                            </svg>
                          </button>
                          {/* Delete button */}
                          <button
                            onClick={() => handleDelete(rule)}
                            className="text-gray-500 hover:text-red-400 transition-colors p-1"
                            title="Delete"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
