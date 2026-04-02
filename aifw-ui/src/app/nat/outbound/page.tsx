"use client";

import { useState, useEffect, useCallback } from "react";
import { api, NatRule, InterfaceInfo, CreateNatRequest, UpdateNatRequest } from "@/lib/api";
import { parsePortField } from "@/lib/ports";
import { validateAddress, validatePort, validateIP } from "@/lib/validate";

type AddrMode = "any" | "network";
type TransMode = "interface" | "address";

const defaultForm = {
  interface: "",
  protocol: "any",
  src_mode: "any" as AddrMode,
  src_addr: "",
  src_port: "",
  dst_mode: "any" as AddrMode,
  dst_addr: "",
  dst_port: "",
  trans_mode: "interface" as TransMode,
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
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const moveRule = async (ruleId: string, direction: "up" | "down") => {
    const idx = rules.findIndex(r => r.id === ruleId);
    if (idx < 0) return;
    const targetIdx = direction === "up" ? idx - 1 : idx + 1;
    if (targetIdx < 0 || targetIdx >= rules.length) return;
    const reordered = [...rules];
    [reordered[idx], reordered[targetIdx]] = [reordered[targetIdx], reordered[idx]];
    setRules(reordered);
    try {
      const t = localStorage.getItem("aifw_token");
      await fetch("/api/v1/nat/reorder", { method: "PUT", headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" }, body: JSON.stringify({ rule_ids: reordered.map(x => x.id) }) });
    } catch { setError("Failed to save order"); }
  };

  const fetchRules = useCallback(async () => {
    try {
      setError(null);
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
    } catch { /* interfaces will remain empty */ }
  }, []);

  useEffect(() => {
    fetchRules();
    fetchInterfaces();
  }, [fetchRules, fetchInterfaces]);

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
      rule.nat_type === "masquerade" ||
      rule.redirect?.address === "interface" ||
      rule.redirect?.address === "interface address";
    const srcIsAny = !rule.src_addr || rule.src_addr === "any";
    const dstIsAny = !rule.dst_addr || rule.dst_addr === "any";

    setForm({
      interface: rule.interface,
      protocol: rule.protocol,
      src_mode: srcIsAny ? "any" : "network",
      src_addr: srcIsAny ? "" : rule.src_addr || "",
      src_port: formatPort(rule.src_port),
      dst_mode: dstIsAny ? "any" : "network",
      dst_addr: dstIsAny ? "" : rule.dst_addr || "",
      dst_port: formatPort(rule.dst_port),
      trans_mode: isInterfaceAddr ? "interface" : "address",
      translation_addr: isInterfaceAddr ? "" : rule.redirect?.address || "",
      static_port: false,
      label: rule.label || "",
      enabled: rule.status === "active",
    });
    setEditingId(rule.id);
    setShowForm(true);
  };

  const handleSubmit = async () => {
    if (form.trans_mode === "address" && !form.translation_addr.trim()) return;
    if (form.src_mode === "network" && !form.src_addr.trim()) return;
    if (form.dst_mode === "network" && !form.dst_addr.trim()) return;

    // Client-side validation
    const errors: string[] = [];
    if (form.src_mode === "network" && form.src_addr) { const e = validateAddress(form.src_addr, "Source address"); if (e) errors.push(e); }
    if (form.dst_mode === "network" && form.dst_addr) { const e = validateAddress(form.dst_addr, "Destination address"); if (e) errors.push(e); }
    if (form.trans_mode === "address" && form.translation_addr) { const e = validateIP(form.translation_addr, "Translation address"); if (e) errors.push(e); }
    if (form.src_port) { const e = validatePort(form.src_port, "Source port"); if (e) errors.push(e); }
    if (form.dst_port) { const e = validatePort(form.dst_port, "Destination port"); if (e) errors.push(e); }
    if (errors.length > 0) { setError(errors.join(". ")); return; }

    setSubmitting(true);
    setError(null);
    try {
      const isInterface = form.trans_mode === "interface";
      const natType = isInterface ? "masquerade" : "snat";

      const body: Record<string, unknown> = {
        nat_type: natType,
        interface: form.interface,
        protocol: form.protocol,
        src_addr: form.src_mode === "any" ? "any" : form.src_addr,
        dst_addr: form.dst_mode === "any" ? "any" : form.dst_addr,
        redirect_addr: isInterface ? "interface" : form.translation_addr,
        status: form.enabled ? "active" : "disabled",
      };

      if (showPortFields(form.protocol)) {
        const sp = parsePortField(form.src_port);
        if (sp.start !== undefined) { body.src_port_start = sp.start; if (sp.end !== undefined) body.src_port_end = sp.end; }
        const dp = parsePortField(form.dst_port);
        if (dp.start !== undefined) { body.dst_port_start = dp.start; if (dp.end !== undefined) body.dst_port_end = dp.end; }
      }
      if (form.label.trim()) body.label = form.label.trim();

      if (editingId) {
        await api.updateNat(editingId, body as unknown as UpdateNatRequest);
      } else {
        await api.createNat(body as unknown as CreateNatRequest);
      }
      await fetchRules();
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (rule: NatRule) => {
    setError(null);
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
    setError(null);
    try {
      await api.updateNat(rule.id, {
        nat_type: rule.nat_type,
        interface: rule.interface,
        protocol: rule.protocol,
        src_addr: rule.src_addr,
        dst_addr: rule.dst_addr,
        redirect_addr: rule.redirect?.address || "interface",
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

  const selectCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const inputCls =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const labelCls = "block text-xs font-medium text-gray-400 mb-1";
  const hintCls = "text-[10px] text-gray-500 mt-0.5";

  const formatTranslation = (rule: NatRule): string => {
    if (rule.nat_type === "masquerade") return "Interface address";
    if (!rule.redirect) return "-";
    return formatAddrPort(rule.redirect.address, rule.redirect.port);
  };

  const canSubmit =
    !submitting &&
    form.interface &&
    (form.trans_mode === "interface" || form.translation_addr.trim()) &&
    (form.src_mode === "any" || form.src_addr.trim()) &&
    (form.dst_mode === "any" || form.dst_addr.trim());

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Outbound NAT</h1>
          <p className="text-sm text-gray-400">
            Source NAT for traffic leaving the firewall &middot;{" "}
            {rules.length} rule{rules.length !== 1 ? "s" : ""} &middot;{" "}
            {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        {!showForm && (
          <button
            onClick={() => {
              setForm({ ...defaultForm, interface: interfaces.length > 0 ? interfaces[0].name : "" });
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

      {/* Form */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white">
            {editingId ? "Edit Outbound NAT Rule" : "New Outbound NAT Rule"}
          </h3>

          {/* Flow diagram */}
          <div className="flex items-center gap-2 px-3 py-2 bg-gray-900/60 rounded-md text-xs text-gray-400 border border-gray-700/50">
            <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 font-medium">Source</span>
            <svg className="w-4 h-4 text-gray-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" /></svg>
            <span className="px-2 py-0.5 rounded bg-gray-700 text-gray-300 font-medium">{form.interface || "Interface"}</span>
            <svg className="w-4 h-4 text-gray-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" /></svg>
            <span className="px-2 py-0.5 rounded bg-green-500/15 text-green-400 font-medium">
              {form.trans_mode === "interface" ? "Interface IP" : form.translation_addr || "NAT IP"}
            </span>
            <svg className="w-4 h-4 text-gray-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" /></svg>
            <span className="px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 font-medium">Destination</span>
            <span className="ml-auto text-[10px] text-gray-500 italic">Source address is rewritten to translation address</span>
          </div>

          {/* Row 1: Interface, Protocol, Enabled */}
          <div className="grid grid-cols-3 md:grid-cols-4 gap-3">
            <div>
              <label className={labelCls}>Interface</label>
              <select value={form.interface} onChange={(e) => updateField("interface", e.target.value)} className={selectCls}>
                {interfaces.length === 0 && <option value="">Loading...</option>}
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name}{iface.description ? ` (${iface.description})` : ""}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Protocol</label>
              <select value={form.protocol} onChange={(e) => updateField("protocol", e.target.value)} className={selectCls}>
                <option value="any">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="tcp/udp">TCP + UDP</option>
                <option value="icmp">ICMP</option>
              </select>
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.enabled} onChange={(e) => updateField("enabled", e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0" />
                <span className="text-sm text-gray-300">Enabled</span>
              </label>
            </div>
          </div>

          {/* Row 2: Source */}
          <div>
            <label className={labelCls}>Source</label>
            <div className="grid grid-cols-[auto_1fr_auto] gap-2 items-end">
              <select value={form.src_mode} onChange={(e) => updateField("src_mode", e.target.value as AddrMode)}
                className={`${selectCls} !w-40`}>
                <option value="any">Any</option>
                <option value="network">Network / Host</option>
              </select>
              <div>
                {form.src_mode === "network" ? (
                  <input type="text" value={form.src_addr} onChange={(e) => updateField("src_addr", e.target.value)}
                    placeholder="192.168.1.0/24 or 10.0.0.5" className={inputCls} />
                ) : (
                  <div className={`${inputCls} !text-gray-500 !cursor-default`}>All addresses</div>
                )}
              </div>
              <div className="w-28">
                {form.src_mode === "network" && showPortFields(form.protocol) ? (
                  <input type="text" value={form.src_port} onChange={(e) => updateField("src_port", e.target.value)}
                    placeholder="Port" className={inputCls} />
                ) : showPortFields(form.protocol) ? (
                  <div className={`${inputCls} !text-gray-500 !cursor-default`}>Any port</div>
                ) : null}
              </div>
            </div>
          </div>

          {/* Row 3: Destination */}
          <div>
            <label className={labelCls}>Destination</label>
            <div className="grid grid-cols-[auto_1fr_auto] gap-2 items-end">
              <select value={form.dst_mode} onChange={(e) => updateField("dst_mode", e.target.value as AddrMode)}
                className={`${selectCls} !w-40`}>
                <option value="any">Any</option>
                <option value="network">Network / Host</option>
              </select>
              <div>
                {form.dst_mode === "network" ? (
                  <input type="text" value={form.dst_addr} onChange={(e) => updateField("dst_addr", e.target.value)}
                    placeholder="0.0.0.0/0 or 203.0.113.0/24" className={inputCls} />
                ) : (
                  <div className={`${inputCls} !text-gray-500 !cursor-default`}>All addresses</div>
                )}
              </div>
              <div className="w-28">
                {form.dst_mode === "network" && showPortFields(form.protocol) ? (
                  <input type="text" value={form.dst_port} onChange={(e) => updateField("dst_port", e.target.value)}
                    placeholder="Port" className={inputCls} />
                ) : showPortFields(form.protocol) ? (
                  <div className={`${inputCls} !text-gray-500 !cursor-default`}>Any port</div>
                ) : null}
              </div>
            </div>
          </div>

          {/* Row 4: Translation */}
          <div>
            <label className={labelCls}>Translation</label>
            <div className="grid grid-cols-[auto_1fr] gap-2 items-end">
              <select value={form.trans_mode} onChange={(e) => updateField("trans_mode", e.target.value as TransMode)}
                className={`${selectCls} !w-52`}>
                <option value="interface">Interface Address (masquerade)</option>
                <option value="address">Specific IP Address</option>
              </select>
              <div>
                {form.trans_mode === "address" ? (
                  <input type="text" value={form.translation_addr} onChange={(e) => updateField("translation_addr", e.target.value)}
                    placeholder="203.0.113.1" className={inputCls} />
                ) : (
                  <div className={`${inputCls} !text-gray-500 !cursor-default`}>Uses the outgoing interface IP</div>
                )}
              </div>
            </div>
          </div>

          {/* Row 5: Description + Static Port */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="md:col-span-2">
              <label className={labelCls}>Description</label>
              <input type="text" value={form.label} onChange={(e) => updateField("label", e.target.value)}
                placeholder="e.g. Default LAN outbound" className={inputCls} />
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.static_port} onChange={(e) => updateField("static_port", e.target.checked)}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0" />
                <span className="text-sm text-gray-300">Static port</span>
              </label>
            </div>
          </div>

          {/* Buttons */}
          <div className="flex gap-2 pt-1">
            <button onClick={handleSubmit} disabled={!canSubmit}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors">
              {submitting ? "Saving..." : editingId ? "Update Rule" : "Add Rule"}
            </button>
            <button onClick={resetForm}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors">
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
                  <th className="w-6"></th>
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
                    <tr key={rule.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors cursor-pointer" onClick={() => handleEdit(rule)}>
                      <td className="py-1 px-1 w-8">
                        <div className="flex flex-col items-center gap-0">
                          <button onClick={() => moveRule(rule.id, "up")} disabled={idx === 0}
                            className="text-gray-600 hover:text-white disabled:opacity-20 p-0.5"><svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" /></svg></button>
                          <span className="text-[9px] text-gray-600">{idx + 1}</span>
                          <button onClick={() => moveRule(rule.id, "down")} disabled={idx === rules.length - 1}
                            className="text-gray-600 hover:text-white disabled:opacity-20 p-0.5"><svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" /></svg></button>
                        </div>
                      </td>
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
                      <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleToggleStatus(rule)}
                          disabled={togglingId === rule.id}
                          className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-50"
                          style={{ backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563" }}
                          title={rule.status === "active" ? "Disable" : "Enable"}
                        >
                          <span
                            className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                            style={{ transform: rule.status === "active" ? "translateX(16px)" : "translateX(0)" }}
                          />
                        </button>
                      </td>
                      <td className="py-2.5 px-2" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
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

      {/* pf NAT output */}
      <PfNatOutput />
    </div>
  );
}

function PfNatOutput() {
  const [output, setOutput] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("aifw_token") || "";
    fetch("/api/v1/rules/system", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => {
        // Also fetch NAT rules from pf anchor
        return fetch("/api/v1/status", { headers: { Authorization: `Bearer ${token}` } })
          .then(r => r.json())
          .then(() => d);
      })
      .then(() => {
        // Fetch pf nat rules directly
        fetch("/api/v1/nat/pf-output", { headers: { Authorization: `Bearer ${token}` } })
          .then(r => r.ok ? r.json() : { data: [] })
          .then(d => setOutput(d.data || []))
          .catch(() => {});
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-700">
        <h3 className="text-sm font-medium text-gray-400">pf NAT Rules (live)</h3>
      </div>
      <div className="p-4">
        {loading ? (
          <div className="text-gray-500 text-xs">Loading...</div>
        ) : output.length === 0 ? (
          <div className="text-gray-500 text-xs font-mono">No NAT rules loaded in pf. Click Apply to load.</div>
        ) : (
          <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">{output.join("\n")}</pre>
        )}
      </div>
    </div>
  );
}
