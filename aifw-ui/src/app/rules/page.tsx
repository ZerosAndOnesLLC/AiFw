"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { api, Rule, InterfaceInfo, Schedule } from "@/lib/api";
import StatusBadge from "@/components/StatusBadge";

/* ─── Subnet masks ──────────────────────────────────────────────── */

const SUBNET_MASKS = [
  "/32", "/31", "/30", "/29", "/28", "/27", "/26", "/25",
  "/24", "/23", "/22", "/21", "/20", "/19", "/18", "/17",
  "/16", "/15", "/14", "/13", "/12", "/11", "/10", "/9", "/8",
];

/* ─── Form state ─────────────────────────────────────────────────── */

interface RuleForm {
  action: string;
  disabled: boolean;
  interface: string;
  direction: string;
  ip_version: string;
  protocol: string;
  src_type: "any" | "address";
  src_addr: string;
  src_mask: string;
  src_invert: boolean;
  src_port: string;
  dst_type: "any" | "address";
  dst_addr: string;
  dst_mask: string;
  dst_invert: boolean;
  dst_port: string;
  log: boolean;
  description: string;
  gateway: string;
  state_tracking: string;
  label: string;
  schedule_id: string;
}

const defaultForm: RuleForm = {
  action: "pass",
  disabled: false,
  interface: "any",
  direction: "in",
  ip_version: "inet",
  protocol: "tcp",
  src_type: "any",
  src_addr: "",
  src_mask: "/32",
  src_invert: false,
  src_port: "",
  dst_type: "any",
  dst_addr: "",
  dst_mask: "/32",
  dst_invert: false,
  dst_port: "",
  log: false,
  description: "",
  gateway: "",
  state_tracking: "keep_state",
  label: "",
  schedule_id: "",
};

const PROTOCOLS = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "tcp/udp", label: "TCP/UDP" },
  { value: "icmp", label: "ICMP" },
  { value: "icmp6", label: "ICMPv6" },
  { value: "esp", label: "ESP" },
  { value: "ah", label: "AH" },
  { value: "gre", label: "GRE" },
  { value: "any", label: "Any" },
];

const ACTIONS = [
  { value: "pass", label: "Pass" },
  { value: "block", label: "Block" },
  { value: "block_drop", label: "Block (drop)" },
  { value: "block_return", label: "Block (return)" },
];

const IP_VERSIONS = [
  { value: "inet", label: "IPv4" },
  { value: "inet6", label: "IPv6" },
  { value: "inet46", label: "IPv4+IPv6" },
];

const STATE_TYPES = [
  { value: "keep_state", label: "Keep state" },
  { value: "modulate_state", label: "Modulate state" },
  { value: "synproxy_state", label: "Synproxy state" },
  { value: "none", label: "None" },
];

function protocolShowsPorts(proto: string): boolean {
  return proto === "tcp" || proto === "udp" || proto === "tcp/udp";
}

/** Split "192.168.1.0/24" into ["192.168.1.0", "/24"] */
function splitCidr(addr: string): { ip: string; mask: string } {
  if (!addr || addr === "any") return { ip: "", mask: "/32" };
  const idx = addr.indexOf("/");
  if (idx === -1) return { ip: addr, mask: "/32" };
  return { ip: addr.substring(0, idx), mask: addr.substring(idx) };
}

/* ─── Component ──────────────────────────────────────────────────── */

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [systemRules, setSystemRules] = useState<string[]>([]);
  const [showSystem, setShowSystem] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<RuleForm>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [interfaceFilter, setInterfaceFilter] = useState<string>("all");
  const dragItem = useRef<number | null>(null);
  const dragOverItem = useRef<number | null>(null);

  const handleDragStart = (idx: number) => { dragItem.current = idx; };
  const handleDragOver = (e: React.DragEvent, idx: number) => { e.preventDefault(); dragOverItem.current = idx; };
  const handleDrop = async () => {
    if (dragItem.current === null || dragOverItem.current === null || dragItem.current === dragOverItem.current) return;
    const reordered = [...rules];
    const [moved] = reordered.splice(dragItem.current, 1);
    reordered.splice(dragOverItem.current, 0, moved);
    setRules(reordered);
    dragItem.current = null;
    dragOverItem.current = null;
    try {
      const token = localStorage.getItem("aifw_token");
      await fetch("/api/v1/rules/reorder", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ rule_ids: reordered.map(r => r.id) }),
      });
      setPendingChanges(true);
    } catch { setError("Failed to save rule order"); }
  };

  /* ── Fetch helpers ─────────────────────────────────────────────── */

  const fetchRules = useCallback(async () => {
    try {
      setError(null);
      const res = await api.listRules();
      setRules(res.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();

    api.listSystemRules()
      .then((d) => setSystemRules(d.data || []))
      .catch(() => {});

    api.listInterfaces()
      .then((d) => setInterfaces(d.data || []))
      .catch(() => {});

    api.listSchedules()
      .then((d) => setSchedules(d.data || []))
      .catch(() => {});
  }, [fetchRules]);

  /* ── Form submit ───────────────────────────────────────────────── */

  const handleSubmit = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError(null);

    try {
      const srcAddr = form.src_type === "any" ? "any" : (form.src_addr ? `${form.src_addr}${form.src_mask}` : "any");
      const dstAddr = form.dst_type === "any" ? "any" : (form.dst_addr ? `${form.dst_addr}${form.dst_mask}` : "any");
      const showPorts = protocolShowsPorts(form.protocol);

      const body = {
        action: form.action,
        direction: form.direction,
        protocol: form.protocol,
        ip_version: form.ip_version,
        interface: form.interface === "any" ? undefined : form.interface,
        src_addr: srcAddr,
        src_port_start: showPorts && form.src_port ? parseInt(form.src_port, 10) : null,
        src_invert: form.src_invert,
        dst_addr: dstAddr,
        dst_port_start: showPorts && form.dst_port ? parseInt(form.dst_port, 10) : null,
        dst_invert: form.dst_invert,
        log: form.log,
        quick: true,
        label: form.label || undefined,
        description: form.description || undefined,
        gateway: form.gateway || null,
        schedule_id: form.schedule_id || null,
        state_tracking: form.state_tracking,
        status: form.disabled ? "disabled" : "active",
      };

      if (editingId) {
        await api.updateRule(editingId, { ...body, status: body.status });
      } else {
        await api.createRule(body);
      }

      setForm(defaultForm);
      setEditingId(null);
      setShowModal(false);
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSubmitting(false);
    }
  };

  /* ── Edit existing rule ────────────────────────────────────────── */

  const handleEdit = (rule: Rule) => {
    const srcIsAny = !rule.rule_match.src_addr || rule.rule_match.src_addr === "any";
    const dstIsAny = !rule.rule_match.dst_addr || rule.rule_match.dst_addr === "any";
    const srcParts = splitCidr(rule.rule_match.src_addr);
    const dstParts = splitCidr(rule.rule_match.dst_addr);

    setForm({
      action: rule.action,
      disabled: rule.status === "disabled",
      interface: rule.interface || "any",
      direction: rule.direction,
      ip_version: rule.ip_version || "inet",
      protocol: rule.protocol,
      src_type: srcIsAny ? "any" : "address",
      src_addr: srcIsAny ? "" : srcParts.ip,
      src_mask: srcIsAny ? "/32" : srcParts.mask,
      src_invert: rule.rule_match.src_invert || false,
      src_port: rule.rule_match.src_port ? String(rule.rule_match.src_port.start) : "",
      dst_type: dstIsAny ? "any" : "address",
      dst_addr: dstIsAny ? "" : dstParts.ip,
      dst_mask: dstIsAny ? "/32" : dstParts.mask,
      dst_invert: rule.rule_match.dst_invert || false,
      dst_port: rule.rule_match.dst_port ? String(rule.rule_match.dst_port.start) : "",
      log: rule.log,
      description: rule.description || "",
      gateway: rule.gateway || "",
      state_tracking: rule.state_options.tracking,
      label: rule.label || "",
      schedule_id: rule.schedule_id || "",
    });
    setEditingId(rule.id);
    setShowModal(true);
  };

  /* ── Delete ────────────────────────────────────────────────────── */

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this firewall rule?")) return;
    setError(null);
    try {
      await api.deleteRule(id);
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule");
    }
  };

  /* ── Toggle enable/disable ─────────────────────────────────────── */

  const handleToggleStatus = async (rule: Rule) => {
    setError(null);
    const newStatus = rule.status === "active" ? "disabled" : "active";
    try {
      await api.updateRule(rule.id, {
        action: rule.action,
        direction: rule.direction,
        protocol: rule.protocol,
        ip_version: rule.ip_version || "inet",
        interface: rule.interface || undefined,
        src_addr: rule.rule_match.src_addr,
        src_port_start: rule.rule_match.src_port ? rule.rule_match.src_port.start : null,
        src_invert: rule.rule_match.src_invert || false,
        dst_addr: rule.rule_match.dst_addr,
        dst_port_start: rule.rule_match.dst_port ? rule.rule_match.dst_port.start : null,
        dst_invert: rule.rule_match.dst_invert || false,
        log: rule.log,
        label: rule.label || undefined,
        description: rule.description || undefined,
        gateway: rule.gateway || null,
        schedule_id: rule.schedule_id || null,
        state_tracking: rule.state_options.tracking,
        status: newStatus,
      });
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle rule status");
    }
  };

  /* ── Cancel form ───────────────────────────────────────────────── */

  const handleCancel = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowModal(false);
  };

  /* ── Helpers ───────────────────────────────────────────────────── */

  const formatPort = (port: { start: number; end: number } | null | undefined): string => {
    if (!port) return "*";
    if (port.start === port.end) return String(port.start);
    return `${port.start}-${port.end}`;
  };

  const formatAddrPort = (
    addr: string,
    port: { start: number; end: number } | null | undefined,
    invert?: boolean,
  ): string => {
    const prefix = invert ? "! " : "";
    const portStr = port ? `:${formatPort(port)}` : "";
    return `${prefix}${addr}${portStr}`;
  };

  const ipVersionLabel = (v?: string): string => {
    if (v === "inet6") return "IPv6";
    if (v === "inet46") return "IPv4+6";
    return "IPv4";
  };

  const actionLabel = (a: string): string => {
    if (a === "block_drop") return "block";
    if (a === "block_return") return "block";
    return a;
  };

  const getScheduleName = (scheduleId?: string): string | null => {
    if (!scheduleId) return null;
    const sched = schedules.find((s) => s.id === scheduleId);
    return sched ? sched.name : null;
  };

  /* ── Filtered rules ───────────────────────────────────────────── */

  const filteredRules = interfaceFilter === "all"
    ? rules
    : rules.filter((r) => (r.interface || "any") === interfaceFilter);

  /* ── Tailwind helpers ──────────────────────────────────────────── */

  const inputClass =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
  const selectClass =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
  const labelClass = "block text-xs font-medium text-gray-400 mb-1";
  const sectionTitle = "text-xs font-semibold text-gray-300 uppercase tracking-wider mb-2";
  const checkboxLabel = "flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none";

  /* ── Render ────────────────────────────────────────────────────── */

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Firewall Rules</h1>
          <p className="text-sm text-gray-400">
            {rules.length} rule{rules.length !== 1 ? "s" : ""} &middot;{" "}
            {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <div className="flex items-center gap-2">
          {pendingChanges && (
            <button
              onClick={async () => {
                try { await api.applyChanges(); setPendingChanges(false); setError(null); }
                catch { setError("Failed to apply changes"); }
              }}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-green-600 hover:bg-green-700 text-white transition-colors animate-pulse"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              Apply Changes
            </button>
          )}
          <button
            onClick={() => {
              setForm(defaultForm);
              setEditingId(null);
              setShowModal(true);
            }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Rule
          </button>
        </div>
      </div>

      {/* Error Banner */}
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

      {/* ─── Interface Filter Tabs ─────────────────────────────────── */}
      <div className="flex items-center gap-1 flex-wrap">
        <button
          onClick={() => setInterfaceFilter("all")}
          className={`px-3 py-1.5 text-xs font-medium rounded-full transition-colors ${
            interfaceFilter === "all"
              ? "bg-blue-600 text-white"
              : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700"
          }`}
        >
          All
        </button>
        {interfaces.map((iface) => (
          <button
            key={iface.name}
            onClick={() => setInterfaceFilter(iface.name)}
            className={`px-3 py-1.5 text-xs font-medium rounded-full transition-colors ${
              interfaceFilter === iface.name
                ? "bg-blue-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700"
            }`}
          >
            {iface.name}
            {iface.description ? ` (${iface.description})` : ""}
          </button>
        ))}
      </div>

      {/* ─── Rules Table ──────────────────────────────────────────── */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        {loading ? (
          <div className="text-center py-12 text-gray-400">Loading rules...</div>
        ) : filteredRules.length === 0 ? (
          <div className="text-center py-12 text-gray-400">
            {interfaceFilter === "all" ? "No firewall rules configured" : `No rules for interface "${interfaceFilter}"`}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-800/80">
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">On</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">#</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Action</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">Dir</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">IP Ver</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Interface</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Proto</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Schedule</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Label</th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule, idx) => (
                  <tr
                    key={rule.id}
                    draggable
                    onDragStart={() => handleDragStart(idx)}
                    onDragOver={(e) => handleDragOver(e, idx)}
                    onDrop={handleDrop}
                    className={`border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors cursor-grab active:cursor-grabbing ${
                      rule.status === "disabled" ? "opacity-50" : ""
                    }`}
                  >
                    {/* Enable toggle */}
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleToggleStatus(rule)}
                        className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                        style={{ backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563" }}
                        title={rule.status === "active" ? "Disable rule" : "Enable rule"}
                      >
                        <span
                          className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                          style={{ transform: rule.status === "active" ? "translateX(16px)" : "translateX(0)" }}
                        />
                      </button>
                    </td>
                    {/* Priority */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-gray-300">{rule.priority}</span>
                    </td>
                    {/* Action */}
                    <td className="py-2.5 px-3">
                      <StatusBadge status={actionLabel(rule.action)} />
                    </td>
                    {/* Direction */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs font-mono text-gray-400 uppercase">{rule.direction}</span>
                    </td>
                    {/* IP Version */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{ipVersionLabel(rule.ip_version)}</span>
                    </td>
                    {/* Interface */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-400">{rule.interface || "*"}</span>
                    </td>
                    {/* Protocol */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-400 uppercase">{rule.protocol}</span>
                    </td>
                    {/* Source */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {formatAddrPort(rule.rule_match.src_addr, rule.rule_match.src_port, rule.rule_match.src_invert)}
                      </span>
                    </td>
                    {/* Destination */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {formatAddrPort(rule.rule_match.dst_addr, rule.rule_match.dst_port, rule.rule_match.dst_invert)}
                      </span>
                    </td>
                    {/* Schedule */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{getScheduleName(rule.schedule_id) || "-"}</span>
                    </td>
                    {/* Label */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{rule.label || "-"}</span>
                    </td>
                    {/* Actions */}
                    <td className="py-2.5 px-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handleEdit(rule)}
                          className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
                          title="Edit rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleDelete(rule.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700"
                          title="Delete rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ─── Modal Overlay ─────────────────────────────────────────── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={handleCancel}
          />
          {/* Modal content */}
          <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-gray-800 border border-gray-700 rounded-xl shadow-2xl m-4">
            <div className="sticky top-0 bg-gray-800 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
              <h3 className="text-lg font-semibold text-white">
                {editingId ? "Edit Rule" : "Add Rule"}
              </h3>
              <button
                onClick={handleCancel}
                className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-5">
              {/* Row 1: Action, Disabled, Interface, Direction, IP Version, Protocol */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                <div>
                  <label className={labelClass}>Action</label>
                  <select
                    value={form.action}
                    onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
                    className={selectClass}
                  >
                    {ACTIONS.map((a) => (
                      <option key={a.value} value={a.value}>{a.label}</option>
                    ))}
                  </select>
                </div>
                <div className="flex items-end pb-1">
                  <label className={checkboxLabel}>
                    <input
                      type="checkbox"
                      checked={form.disabled}
                      onChange={(e) => setForm((f) => ({ ...f, disabled: e.target.checked }))}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                    />
                    Disabled
                  </label>
                </div>
                <div>
                  <label className={labelClass}>Interface</label>
                  <select
                    value={form.interface}
                    onChange={(e) => setForm((f) => ({ ...f, interface: e.target.value }))}
                    className={selectClass}
                  >
                    <option value="any">any</option>
                    {interfaces.map((iface) => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name}{iface.description ? ` (${iface.description})` : ""}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelClass}>Direction</label>
                  <select
                    value={form.direction}
                    onChange={(e) => setForm((f) => ({ ...f, direction: e.target.value }))}
                    className={selectClass}
                  >
                    <option value="in">In</option>
                    <option value="out">Out</option>
                  </select>
                </div>
                <div>
                  <label className={labelClass}>IP Version</label>
                  <select
                    value={form.ip_version}
                    onChange={(e) => setForm((f) => ({ ...f, ip_version: e.target.value }))}
                    className={selectClass}
                  >
                    {IP_VERSIONS.map((v) => (
                      <option key={v.value} value={v.value}>{v.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelClass}>Protocol</label>
                  <select
                    value={form.protocol}
                    onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
                    className={selectClass}
                  >
                    {PROTOCOLS.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Source / Destination — side-by-side 2-column grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* ── Source ────────────────────────────────────────────── */}
                <div className="bg-gray-900/60 border border-gray-700/60 rounded-lg p-4">
                  <h4 className={sectionTitle}>Source</h4>
                  <div className="space-y-3">
                    <div>
                      <label className={labelClass}>Type</label>
                      <select
                        value={form.src_type}
                        onChange={(e) =>
                          setForm((f) => ({
                            ...f,
                            src_type: e.target.value as "any" | "address",
                            src_addr: e.target.value === "any" ? "" : f.src_addr,
                          }))
                        }
                        className={selectClass}
                      >
                        <option value="any">Any</option>
                        <option value="address">Address / Network</option>
                      </select>
                    </div>
                    {form.src_type === "address" && (
                      <div className="grid grid-cols-3 gap-3">
                        <div className="col-span-2">
                          <label className={labelClass}>IP Address</label>
                          <input
                            type="text"
                            value={form.src_addr}
                            onChange={(e) => setForm((f) => ({ ...f, src_addr: e.target.value }))}
                            placeholder="192.168.1.0"
                            className={inputClass}
                          />
                        </div>
                        <div>
                          <label className={labelClass}>Mask</label>
                          <select
                            value={form.src_mask}
                            onChange={(e) => setForm((f) => ({ ...f, src_mask: e.target.value }))}
                            className={selectClass}
                          >
                            {SUBNET_MASKS.map((m) => (
                              <option key={m} value={m}>{m}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    )}
                    <div className="flex items-center gap-4">
                      <label className={checkboxLabel}>
                        <input
                          type="checkbox"
                          checked={form.src_invert}
                          onChange={(e) => setForm((f) => ({ ...f, src_invert: e.target.checked }))}
                          className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                        />
                        NOT (invert match)
                      </label>
                    </div>
                    {protocolShowsPorts(form.protocol) && (
                      <div>
                        <label className={labelClass}>Port / Range</label>
                        <input
                          type="text"
                          value={form.src_port}
                          onChange={(e) => setForm((f) => ({ ...f, src_port: e.target.value }))}
                          placeholder="e.g. 1024 or 1024-65535"
                          className={inputClass}
                        />
                      </div>
                    )}
                  </div>
                </div>

                {/* ── Destination ──────────────────────────────────────── */}
                <div className="bg-gray-900/60 border border-gray-700/60 rounded-lg p-4">
                  <h4 className={sectionTitle}>Destination</h4>
                  <div className="space-y-3">
                    <div>
                      <label className={labelClass}>Type</label>
                      <select
                        value={form.dst_type}
                        onChange={(e) =>
                          setForm((f) => ({
                            ...f,
                            dst_type: e.target.value as "any" | "address",
                            dst_addr: e.target.value === "any" ? "" : f.dst_addr,
                          }))
                        }
                        className={selectClass}
                      >
                        <option value="any">Any</option>
                        <option value="address">Address / Network</option>
                      </select>
                    </div>
                    {form.dst_type === "address" && (
                      <div className="grid grid-cols-3 gap-3">
                        <div className="col-span-2">
                          <label className={labelClass}>IP Address</label>
                          <input
                            type="text"
                            value={form.dst_addr}
                            onChange={(e) => setForm((f) => ({ ...f, dst_addr: e.target.value }))}
                            placeholder="10.0.0.0"
                            className={inputClass}
                          />
                        </div>
                        <div>
                          <label className={labelClass}>Mask</label>
                          <select
                            value={form.dst_mask}
                            onChange={(e) => setForm((f) => ({ ...f, dst_mask: e.target.value }))}
                            className={selectClass}
                          >
                            {SUBNET_MASKS.map((m) => (
                              <option key={m} value={m}>{m}</option>
                            ))}
                          </select>
                        </div>
                      </div>
                    )}
                    <div className="flex items-center gap-4">
                      <label className={checkboxLabel}>
                        <input
                          type="checkbox"
                          checked={form.dst_invert}
                          onChange={(e) => setForm((f) => ({ ...f, dst_invert: e.target.checked }))}
                          className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                        />
                        NOT (invert match)
                      </label>
                    </div>
                    {protocolShowsPorts(form.protocol) && (
                      <div>
                        <label className={labelClass}>Port / Range</label>
                        <input
                          type="text"
                          value={form.dst_port}
                          onChange={(e) => setForm((f) => ({ ...f, dst_port: e.target.value }))}
                          placeholder="e.g. 443 or 80-443"
                          className={inputClass}
                        />
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Row 3: Label, Description, Gateway, State, Schedule */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <div>
                  <label className={labelClass}>Label</label>
                  <input
                    type="text"
                    value={form.label}
                    onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                    placeholder="Rule label"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>Description</label>
                  <input
                    type="text"
                    value={form.description}
                    onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                    placeholder="Optional description"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>Gateway</label>
                  <input
                    type="text"
                    value={form.gateway}
                    onChange={(e) => setForm((f) => ({ ...f, gateway: e.target.value }))}
                    placeholder="Policy routing gateway"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>State Type</label>
                  <select
                    value={form.state_tracking}
                    onChange={(e) => setForm((f) => ({ ...f, state_tracking: e.target.value }))}
                    className={selectClass}
                  >
                    {STATE_TYPES.map((s) => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelClass}>Schedule</label>
                  <select
                    value={form.schedule_id}
                    onChange={(e) => setForm((f) => ({ ...f, schedule_id: e.target.value }))}
                    className={selectClass}
                  >
                    <option value="">None</option>
                    {schedules.map((s) => (
                      <option key={s.id} value={s.id}>{s.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Log checkbox */}
              <div className="pt-2">
                <label className={checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={form.log}
                    onChange={(e) => setForm((f) => ({ ...f, log: e.target.checked }))}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  Log packets matching this rule
                </label>
              </div>
            </div>

            {/* Modal footer */}
            <div className="sticky bottom-0 bg-gray-800 border-t border-gray-700 px-6 py-4 flex items-center justify-end gap-3">
              <button
                onClick={handleCancel}
                className="px-4 py-2 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="px-5 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
              >
                {submitting ? "Saving..." : editingId ? "Save Changes" : "Add Rule"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── System Rules (collapsible) ───────────────────────────── */}
      {systemRules.length > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setShowSystem(!showSystem)}
            className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-700/40 transition-colors"
          >
            <h3 className="text-sm font-medium text-white">
              System Rules (pfctl -sr) &mdash; {systemRules.length} rules
            </h3>
            <svg
              className={`w-4 h-4 text-gray-400 transition-transform ${showSystem ? "rotate-180" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showSystem && (
            <div className="border-t border-gray-700 p-4">
              <p className="text-xs text-gray-500 mb-3">
                These are the active rules loaded in the pf kernel state. They are managed by the
                system configuration and cannot be edited here.
              </p>
              <div className="bg-gray-900 rounded-lg p-4 font-mono text-xs space-y-0.5 overflow-x-auto max-h-96 overflow-y-auto">
                {systemRules.map((rule, i) => {
                  const isBlock = rule.startsWith("block");
                  const isPass = rule.startsWith("pass");
                  const isAnchor = rule.startsWith("anchor");
                  const color = isBlock
                    ? "text-red-400"
                    : isPass
                      ? "text-green-400"
                      : isAnchor
                        ? "text-blue-400"
                        : "text-gray-400";
                  return (
                    <div key={i} className={`${color} whitespace-nowrap`}>
                      <span className="text-gray-600 mr-3 select-none">
                        {String(i + 1).padStart(3, " ")}.
                      </span>
                      {rule}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
