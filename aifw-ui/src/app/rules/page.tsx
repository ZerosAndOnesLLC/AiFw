"use client";

import { useEffect, useState, useCallback } from "react";
import { api, Rule } from "@/lib/api";
import StatusBadge from "@/components/StatusBadge";

interface RuleForm {
  action: string;
  direction: string;
  protocol: string;
  src_addr: string;
  src_port: string;
  dst_addr: string;
  dst_port: string;
  label: string;
  state_tracking: string;
  status: string;
}

const defaultForm: RuleForm = {
  action: "pass",
  direction: "in",
  protocol: "tcp",
  src_addr: "any",
  src_port: "",
  dst_addr: "any",
  dst_port: "",
  label: "",
  state_tracking: "keep_state",
  status: "active",
};

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<RuleForm>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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
  }, [fetchRules]);

  const handleSubmit = async () => {
    if (submitting) return;
    setSubmitting(true);
    setError(null);

    try {
      const body = {
        action: form.action,
        direction: form.direction,
        protocol: form.protocol,
        src_addr: form.src_addr || "any",
        src_port_start: form.src_port ? parseInt(form.src_port, 10) : null,
        dst_addr: form.dst_addr || "any",
        dst_port_start: form.dst_port ? parseInt(form.dst_port, 10) : null,
        label: form.label || undefined,
        state_tracking: form.state_tracking,
        status: form.status,
      };

      if (editingId) {
        await api.updateRule(editingId, { ...body, status: form.status });
      } else {
        await api.createRule(body);
      }

      setForm(defaultForm);
      setEditingId(null);
      setShowForm(false);
      await fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleEdit = (rule: Rule) => {
    setForm({
      action: rule.action,
      direction: rule.direction,
      protocol: rule.protocol,
      src_addr: rule.rule_match.src_addr,
      src_port: rule.rule_match.src_port ? String(rule.rule_match.src_port.start) : "",
      dst_addr: rule.rule_match.dst_addr,
      dst_port: rule.rule_match.dst_port ? String(rule.rule_match.dst_port.start) : "",
      label: rule.label || "",
      state_tracking: rule.state_options.tracking,
      status: rule.status,
    });
    setEditingId(rule.id);
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    setError(null);
    try {
      await api.deleteRule(id);
      await fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule");
    }
  };

  const handleToggleStatus = async (rule: Rule) => {
    setError(null);
    const newStatus = rule.status === "active" ? "disabled" : "active";
    try {
      await api.updateRule(rule.id, {
        action: rule.action,
        direction: rule.direction,
        protocol: rule.protocol,
        src_addr: rule.rule_match.src_addr,
        src_port_start: rule.rule_match.src_port ? rule.rule_match.src_port.start : null,
        dst_addr: rule.rule_match.dst_addr,
        dst_port_start: rule.rule_match.dst_port ? rule.rule_match.dst_port.start : null,
        label: rule.label || undefined,
        state_tracking: rule.state_options.tracking,
        status: newStatus,
      });
      await fetchRules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle rule status");
    }
  };

  const handleCancel = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowForm(false);
  };

  const formatPort = (port: { start: number; end: number } | null | undefined): string => {
    if (!port) return "*";
    if (port.start === port.end) return String(port.start);
    return `${port.start}-${port.end}`;
  };

  const inputClass =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
  const selectClass =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
  const labelClass = "block text-xs text-gray-400 mb-1";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Firewall Rules</h1>
          <p className="text-sm text-gray-400">
            {rules.length} rules &middot; {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        {!showForm && (
          <button
            onClick={() => {
              setForm(defaultForm);
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

      {/* Add/Edit Form */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">
            {editingId ? "Edit Rule" : "New Rule"}
          </h3>

          {/* Row 1: Action, Direction, Protocol, State Tracking */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelClass}>Action</label>
              <select
                value={form.action}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
                className={selectClass}
              >
                <option value="pass">pass</option>
                <option value="block">block</option>
              </select>
            </div>
            <div>
              <label className={labelClass}>Direction</label>
              <select
                value={form.direction}
                onChange={(e) => setForm((f) => ({ ...f, direction: e.target.value }))}
                className={selectClass}
              >
                <option value="in">in</option>
                <option value="out">out</option>
                <option value="any">any</option>
              </select>
            </div>
            <div>
              <label className={labelClass}>Protocol</label>
              <select
                value={form.protocol}
                onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
                className={selectClass}
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
                <option value="any">any</option>
              </select>
            </div>
            <div>
              <label className={labelClass}>State Tracking</label>
              <select
                value={form.state_tracking}
                onChange={(e) => setForm((f) => ({ ...f, state_tracking: e.target.value }))}
                className={selectClass}
              >
                <option value="keep_state">keep state</option>
                <option value="no_state">no state</option>
                <option value="modulate_state">modulate state</option>
                <option value="synproxy_state">synproxy state</option>
              </select>
            </div>
          </div>

          {/* Row 2: Source Address, Source Port, Dest Address, Dest Port */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
            <div>
              <label className={labelClass}>Source Address</label>
              <input
                type="text"
                value={form.src_addr}
                onChange={(e) => setForm((f) => ({ ...f, src_addr: e.target.value }))}
                placeholder="any or CIDR"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Source Port</label>
              <input
                type="text"
                value={form.src_port}
                onChange={(e) => setForm((f) => ({ ...f, src_port: e.target.value }))}
                placeholder="e.g. 1024"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Dest Address</label>
              <input
                type="text"
                value={form.dst_addr}
                onChange={(e) => setForm((f) => ({ ...f, dst_addr: e.target.value }))}
                placeholder="any or CIDR"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Dest Port</label>
              <input
                type="text"
                value={form.dst_port}
                onChange={(e) => setForm((f) => ({ ...f, dst_port: e.target.value }))}
                placeholder="e.g. 443"
                className={inputClass}
              />
            </div>
          </div>

          {/* Row 3: Label, Status */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div className="md:col-span-2">
              <label className={labelClass}>Label</label>
              <input
                type="text"
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                placeholder="Rule description"
                className={inputClass}
              />
            </div>
            {editingId && (
              <div>
                <label className={labelClass}>Status</label>
                <select
                  value={form.status}
                  onChange={(e) => setForm((f) => ({ ...f, status: e.target.value }))}
                  className={selectClass}
                >
                  <option value="active">active</option>
                  <option value="disabled">disabled</option>
                </select>
              </div>
            )}
          </div>

          {/* Buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleSubmit}
              disabled={submitting}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
            >
              {submitting
                ? "Saving..."
                : editingId
                ? "Update Rule"
                : "Add Rule"}
            </button>
            <button
              onClick={handleCancel}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Rules Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        {loading ? (
          <div className="text-center py-12 text-gray-400">Loading rules...</div>
        ) : rules.length === 0 ? (
          <div className="text-center py-12 text-gray-400">No firewall rules configured</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Priority</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Action</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">Dir</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Protocol</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-28">State</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Label</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Status</th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-28">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr
                    key={rule.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                  >
                    {/* Priority */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-gray-300">{rule.priority}</span>
                    </td>
                    {/* Action */}
                    <td className="py-2.5 px-3">
                      <StatusBadge status={rule.action} />
                    </td>
                    {/* Direction */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs font-mono text-gray-400 uppercase">{rule.direction}</span>
                    </td>
                    {/* Protocol */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-400">{rule.protocol}</span>
                    </td>
                    {/* Source */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {rule.rule_match.src_addr}
                        {rule.rule_match.src_port && (
                          <span className="text-gray-500">:{formatPort(rule.rule_match.src_port)}</span>
                        )}
                      </span>
                    </td>
                    {/* Destination */}
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {rule.rule_match.dst_addr}
                        {rule.rule_match.dst_port && (
                          <span className="text-gray-500">:{formatPort(rule.rule_match.dst_port)}</span>
                        )}
                      </span>
                    </td>
                    {/* State */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-500">{rule.state_options.tracking}</span>
                    </td>
                    {/* Label */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{rule.label || "-"}</span>
                    </td>
                    {/* Status Toggle */}
                    <td className="py-2.5 px-3">
                      <button
                        onClick={() => handleToggleStatus(rule)}
                        className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                        style={{
                          backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563",
                        }}
                        title={rule.status === "active" ? "Disable rule" : "Enable rule"}
                      >
                        <span
                          className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                          style={{
                            transform: rule.status === "active" ? "translateX(16px)" : "translateX(0)",
                          }}
                        />
                      </button>
                    </td>
                    {/* Actions */}
                    <td className="py-2.5 px-3">
                      <div className="flex items-center justify-end gap-1">
                        {/* Edit Button */}
                        <button
                          onClick={() => handleEdit(rule)}
                          className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
                          title="Edit rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        {/* Delete Button */}
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
    </div>
  );
}
