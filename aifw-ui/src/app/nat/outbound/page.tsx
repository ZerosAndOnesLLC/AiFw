"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { api, NatRule, InterfaceInfo, CreateNatRequest, UpdateNatRequest } from "@/lib/api";

const defaultForm = {
  interface: "",
  protocol: "tcp",
  src_addr: "",
  src_port: "",
  dst_addr: "",
  dst_port: "",
  translation_addr: "",
  static_port: false,
  label: "",
  enabled: true,
};

type FormState = typeof defaultForm;

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

const showPortFields = (protocol: string) =>
  protocol === "tcp" || protocol === "udp" || protocol === "tcp/udp";

export default function OutboundNatPage() {
  const [rules, setRules] = useState<NatRule[]>([]);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const dragItem = useRef<number|null>(null);
  const dragOverItem = useRef<number|null>(null);
  const handleDragStart = (i: number) => { dragItem.current = i; };
  const handleDragOver = (e: React.DragEvent, i: number) => { e.preventDefault(); dragOverItem.current = i; };
  const handleDrop = async () => {
    if (dragItem.current===null||dragOverItem.current===null||dragItem.current===dragOverItem.current) return;
    const r = [...rules]; const [m] = r.splice(dragItem.current,1); r.splice(dragOverItem.current,0,m);
    setRules(r); dragItem.current=null; dragOverItem.current=null;
    try { const t=localStorage.getItem("aifw_token"); await fetch("/api/v1/nat/reorder",{method:"PUT",headers:{Authorization:`Bearer ${t}`,"Content-Type":"application/json"},body:JSON.stringify({rule_ids:r.map(x=>x.id)})}); } catch { setError("Failed to save order"); }
  };

  const fetchRules = useCallback(async () => {
    try {
      setPendingChanges(false); setError(null);
      const res = await api.listNat();
      setRules(res.data.filter((r) => r.nat_type === "snat" || r.nat_type === "masquerade"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load outbound NAT rules");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await api.listInterfaces();
      setInterfaces(res.data);
    } catch {
      // interfaces will remain empty
    }
  }, []);

  useEffect(() => {
    fetchRules();
    fetchInterfaces();
  }, [fetchRules, fetchInterfaces]);

  // Set default interface once loaded
  useEffect(() => {
    if (interfaces.length > 0 && !form.interface && !editingId) {
      setForm((f) => ({ ...f, interface: interfaces[0].name }));
    }
  }, [interfaces, form.interface, editingId]);

  const resetForm = () => {
    setForm({
      ...defaultForm,
      interface: interfaces.length > 0 ? interfaces[0].name : "",
    });
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (rule: NatRule) => {
    const isInterfaceAddr =
      rule.redirect?.address === "interface" || rule.redirect?.address === "interface address";
    setForm({
      interface: rule.interface,
      protocol: rule.protocol,
      src_addr: rule.src_addr || "",
      src_port: formatPort(rule.src_port),
      dst_addr: rule.dst_addr || "",
      dst_port: formatPort(rule.dst_port),
      translation_addr: isInterfaceAddr ? "interface address" : rule.redirect?.address || "",
      static_port: false,
      label: rule.label || "",
      enabled: rule.status === "active",
    });
    setEditingId(rule.id);
    setShowForm(true);
  };

  const handleSubmit = async () => {
    if (!form.translation_addr.trim()) return;
    setSubmitting(true);
    setPendingChanges(false); setError(null);
    try {
      const isInterfaceAddr = form.translation_addr.toLowerCase() === "interface address";
      const natType = isInterfaceAddr ? "masquerade" : "snat";

      const body: Record<string, unknown> = {
        nat_type: natType,
        interface: form.interface,
        protocol: form.protocol,
        src_addr: form.src_addr || "any",
        dst_addr: form.dst_addr || "any",
        redirect_addr: form.translation_addr,
        status: form.enabled ? "active" : "disabled",
      };

      if (showPortFields(form.protocol)) {
        if (form.src_port) body.src_port_start = parseInt(form.src_port, 10);
        if (form.dst_port) body.dst_port_start = parseInt(form.dst_port, 10);
      }
      if (form.label.trim()) body.label = form.label.trim();

      if (editingId) {
        await api.updateNat(editingId, body as unknown as UpdateNatRequest);
      } else {
        await api.createNat(body as unknown as CreateNatRequest);
      }
      await fetchRules();
      setPendingChanges(true);
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (rule: NatRule) => {
    setPendingChanges(false); setError(null);
    try {
      await api.deleteNat(rule.id);
      setRules((prev) => prev.filter((r) => r.id !== rule.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule");
    }
  };

  const handleToggleStatus = async (rule: NatRule) => {
    const newStatus = rule.status === "active" ? "disabled" : "active";
    setTogglingId(rule.id);
    setPendingChanges(false); setError(null);
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
      setRules((prev) =>
        prev.map((r) => (r.id === rule.id ? { ...r, status: newStatus } : r)),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle status");
    } finally {
      setTogglingId(null);
    }
  };

  const updateField = <K extends keyof FormState>(field: K, value: FormState[K]) => {
    setForm((f) => ({ ...f, [field]: value }));
  };

  const inputCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const selectCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const labelCls = "block text-xs text-gray-400 mb-1";

  const formatTranslation = (rule: NatRule): string => {
    if (rule.nat_type === "masquerade") return "Interface address";
    if (!rule.redirect) return "-";
    return formatAddrPort(rule.redirect.address, rule.redirect.port);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Outbound NAT</h1>
          <p className="text-sm text-gray-400">
            Source NAT for traffic leaving the firewall &middot;{" "}
            {rules.length} rules &middot;{" "}
            {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <div className="flex items-center gap-2">
          {pendingChanges && (
            <button
              onClick={async () => {
                try {
                  const token = localStorage.getItem("aifw_token");
                  await fetch("/api/v1/reload", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
                  setPendingChanges(false); setError(null);
                } catch { setError("Failed to apply changes"); }
              }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-green-600 hover:bg-green-700 text-white transition-colors animate-pulse"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              Apply Changes
            </button>
          )}
          {!showForm && (
            <button
              onClick={() => {
                setForm({
                  ...defaultForm,
                  interface: interfaces.length > 0 ? interfaces[0].name : "",
                });
                setEditingId(null);
                setShowForm(true);
              }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add Rule
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Inline Form */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">
            {editingId ? "Edit Outbound NAT Rule" : "New Outbound NAT Rule"}
          </h3>

          {/* Row 1: Interface, Protocol, Enable */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelCls}>Interface</label>
              <select
                value={form.interface}
                onChange={(e) => updateField("interface", e.target.value)}
                className={selectCls}
              >
                {interfaces.length === 0 && (
                  <option value="">Loading...</option>
                )}
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name}
                    {iface.description ? ` (${iface.description})` : ""}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Protocol</label>
              <select
                value={form.protocol}
                onChange={(e) => updateField("protocol", e.target.value)}
                className={selectCls}
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="tcp/udp">TCP/UDP</option>
                <option value="any">Any</option>
              </select>
            </div>
            <div className="flex items-end pb-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => updateField("enabled", e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Enabled</span>
              </label>
            </div>
          </div>

          {/* Row 2: Source */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelCls}>Source Network (CIDR)</label>
              <input
                type="text"
                value={form.src_addr}
                onChange={(e) => updateField("src_addr", e.target.value)}
                placeholder="e.g. 192.168.1.0/24"
                className={inputCls}
              />
            </div>
            {showPortFields(form.protocol) && (
              <div>
                <label className={labelCls}>Source Port (optional)</label>
                <input
                  type="text"
                  value={form.src_port}
                  onChange={(e) => updateField("src_port", e.target.value)}
                  placeholder="e.g. 1024"
                  className={inputCls}
                />
              </div>
            )}
          </div>

          {/* Row 3: Destination */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelCls}>Destination Network</label>
              <input
                type="text"
                value={form.dst_addr}
                onChange={(e) => updateField("dst_addr", e.target.value)}
                placeholder="any or CIDR"
                className={inputCls}
              />
            </div>
            {showPortFields(form.protocol) && (
              <div>
                <label className={labelCls}>Destination Port (optional)</label>
                <input
                  type="text"
                  value={form.dst_port}
                  onChange={(e) => updateField("dst_port", e.target.value)}
                  placeholder="e.g. 443"
                  className={inputCls}
                />
              </div>
            )}
          </div>

          {/* Row 4: Translation */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelCls}>Translation Address</label>
              <input
                type="text"
                value={form.translation_addr}
                onChange={(e) => updateField("translation_addr", e.target.value)}
                placeholder='IP or "interface address"'
                className={inputCls}
              />
              <p className="text-[10px] text-gray-500 mt-1">
                Use &quot;interface address&quot; for masquerade
              </p>
            </div>
            <div className="flex items-end pb-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={form.static_port}
                  onChange={(e) => updateField("static_port", e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Static port</span>
              </label>
            </div>
          </div>

          {/* Row 5: Label */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div className="md:col-span-2">
              <label className={labelCls}>Description / Label</label>
              <input
                type="text"
                value={form.label}
                onChange={(e) => updateField("label", e.target.value)}
                placeholder="Rule description"
                className={inputCls}
              />
            </div>
          </div>

          {/* Buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleSubmit}
              disabled={submitting || !form.translation_addr.trim()}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
            >
              {submitting ? "Saving..." : editingId ? "Update Rule" : "Add Rule"}
            </button>
            <button
              onClick={resetForm}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="text-center py-12 text-gray-500">Loading outbound NAT rules...</div>
      )}

      {/* Table */}
      {!loading && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Interface</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Protocol</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Translation</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Description</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Status</th>
                  <th className="w-24"></th>
                </tr>
              </thead>
              <tbody>
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-12 text-gray-500">
                      No outbound NAT rules configured
                    </td>
                  </tr>
                ) : (
                  rules.map((rule, idx) => (
                    <tr
                      key={rule.id}
                      draggable onDragStart={()=>handleDragStart(idx)} onDragOver={(e)=>handleDragOver(e,idx)} onDrop={handleDrop}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors cursor-grab active:cursor-grabbing"
                    >
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-gray-400">{rule.interface}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-gray-400 uppercase">{rule.protocol}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-white">
                          {formatAddrPort(rule.src_addr, rule.src_port)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-white">
                          {formatAddrPort(rule.dst_addr, rule.dst_port)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs text-green-400">
                          {formatTranslation(rule)}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-gray-400">{rule.label || "-"}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => handleToggleStatus(rule)}
                          disabled={togglingId === rule.id}
                          className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50"
                          style={{
                            backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563",
                          }}
                          title={rule.status === "active" ? "Disable" : "Enable"}
                        >
                          <span
                            className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                            style={{
                              transform: rule.status === "active" ? "translateX(16px)" : "translateX(0)",
                            }}
                          />
                        </button>
                      </td>
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleEdit(rule)}
                            className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
                            title="Edit"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                            </svg>
                          </button>
                          <button
                            onClick={() => handleDelete(rule)}
                            className="p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700"
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
