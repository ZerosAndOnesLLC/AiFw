"use client";

import { useState } from "react";
import DataTable from "@/components/DataTable";
import StatusBadge from "@/components/StatusBadge";

interface Rule {
  id: string;
  priority: number;
  action: string;
  direction: string;
  protocol: string;
  src_addr: string;
  src_port: string;
  dst_addr: string;
  dst_port: string;
  state_tracking: string;
  label: string;
  status: string;
}

const initialRules: Rule[] = [
  { id: "r-001", priority: 10, action: "block", direction: "in", protocol: "any", src_addr: "any", src_port: "*", dst_addr: "any", dst_port: "*", state_tracking: "no state", label: "Default deny inbound", status: "active" },
  { id: "r-002", priority: 20, action: "pass", direction: "in", protocol: "tcp", src_addr: "any", src_port: "*", dst_addr: "10.0.0.5", dst_port: "22", state_tracking: "keep state", label: "SSH access", status: "active" },
  { id: "r-003", priority: 30, action: "pass", direction: "in", protocol: "tcp", src_addr: "any", src_port: "*", dst_addr: "10.0.0.5", dst_port: "80,443", state_tracking: "keep state", label: "Web traffic", status: "active" },
  { id: "r-004", priority: 40, action: "pass", direction: "out", protocol: "any", src_addr: "10.0.0.0/24", src_port: "*", dst_addr: "any", dst_port: "*", state_tracking: "keep state", label: "LAN outbound", status: "active" },
  { id: "r-005", priority: 50, action: "block", direction: "in", protocol: "tcp", src_addr: "192.168.100.0/24", src_port: "*", dst_addr: "any", dst_port: "*", state_tracking: "no state", label: "Block suspicious subnet", status: "active" },
  { id: "r-006", priority: 60, action: "pass", direction: "in", protocol: "udp", src_addr: "any", src_port: "*", dst_addr: "10.0.0.5", dst_port: "53", state_tracking: "keep state", label: "DNS", status: "active" },
  { id: "r-007", priority: 70, action: "pass", direction: "in", protocol: "icmp", src_addr: "any", src_port: "*", dst_addr: "10.0.0.5", dst_port: "*", state_tracking: "keep state", label: "Ping", status: "disabled" },
  { id: "r-008", priority: 80, action: "block", direction: "in", protocol: "tcp", src_addr: "any", src_port: "*", dst_addr: "10.0.0.5", dst_port: "3306", state_tracking: "no state", label: "Block MySQL external", status: "active" },
];

const defaultForm = {
  action: "pass",
  direction: "in",
  protocol: "tcp",
  dst_port: "",
  label: "",
};

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>(initialRules);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(defaultForm);

  const handleDelete = (row: Rule) => {
    setRules((prev) => prev.filter((r) => r.id !== row.id));
  };

  const handleAdd = () => {
    if (!form.label.trim()) return;
    const maxPriority = rules.reduce((max, r) => Math.max(max, r.priority), 0);
    const newRule: Rule = {
      id: `r-${String(Date.now()).slice(-6)}`,
      priority: maxPriority + 10,
      action: form.action,
      direction: form.direction,
      protocol: form.protocol,
      src_addr: "any",
      src_port: "*",
      dst_addr: "any",
      dst_port: form.dst_port || "*",
      state_tracking: form.action === "pass" ? "keep state" : "no state",
      label: form.label,
      status: "active",
    };
    setRules((prev) => [...prev, newRule]);
    setForm(defaultForm);
    setShowForm(false);
  };

  const columns = [
    {
      key: "priority",
      label: "Priority",
      className: "w-20",
      render: (row: Rule) => (
        <span className="font-mono text-[var(--text-secondary)]">{row.priority}</span>
      ),
    },
    {
      key: "action",
      label: "Action",
      className: "w-24",
      render: (row: Rule) => <StatusBadge status={row.action} />,
    },
    {
      key: "direction",
      label: "Dir",
      className: "w-16",
      render: (row: Rule) => (
        <span className="text-xs font-mono text-[var(--text-secondary)] uppercase">{row.direction}</span>
      ),
    },
    {
      key: "protocol",
      label: "Protocol",
      className: "w-20",
      render: (row: Rule) => (
        <span className="font-mono text-xs text-[var(--text-secondary)]">{row.protocol}</span>
      ),
    },
    {
      key: "src_addr",
      label: "Source",
      render: (row: Rule) => (
        <span className="font-mono text-xs">
          {row.src_addr}
          {row.src_port !== "*" && <span className="text-[var(--text-muted)]">:{row.src_port}</span>}
        </span>
      ),
    },
    {
      key: "dst_addr",
      label: "Destination",
      render: (row: Rule) => (
        <span className="font-mono text-xs">
          {row.dst_addr}
          {row.dst_port !== "*" && <span className="text-[var(--text-muted)]">:{row.dst_port}</span>}
        </span>
      ),
    },
    {
      key: "state_tracking",
      label: "State",
      className: "w-28",
      render: (row: Rule) => (
        <span className="text-xs text-[var(--text-muted)]">{row.state_tracking}</span>
      ),
    },
    {
      key: "label",
      label: "Label",
      render: (row: Rule) => (
        <span className="text-xs text-[var(--text-secondary)]">{row.label}</span>
      ),
    },
    {
      key: "status",
      label: "Status",
      className: "w-24",
      render: (row: Rule) => <StatusBadge status={row.status} />,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Firewall Rules</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {rules.length} rules &middot; {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Rule
        </button>
      </div>

      {/* Inline Add Form */}
      {showForm && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">New Rule</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Action</label>
              <select
                value={form.action}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="pass">pass</option>
                <option value="block">block</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Direction</label>
              <select
                value={form.direction}
                onChange={(e) => setForm((f) => ({ ...f, direction: e.target.value }))}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="in">in</option>
                <option value="out">out</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Protocol</label>
              <select
                value={form.protocol}
                onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
                <option value="any">any</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Dest Port</label>
              <input
                type="text"
                value={form.dst_port}
                onChange={(e) => setForm((f) => ({ ...f, dst_port: e.target.value }))}
                placeholder="e.g. 443"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Label</label>
              <input
                type="text"
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                placeholder="Rule description"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
          </div>
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleAdd}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white transition-colors"
            >
              Add
            </button>
            <button
              onClick={() => { setShowForm(false); setForm(defaultForm); }}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Rules Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <DataTable<Record<string, unknown>>
          columns={columns as { key: string; label: string; render?: (row: Record<string, unknown>) => React.ReactNode; className?: string }[]}
          data={rules as unknown as Record<string, unknown>[]}
          keyField="id"
          onDelete={(row) => handleDelete(row as unknown as Rule)}
          emptyMessage="No firewall rules configured"
        />
      </div>
    </div>
  );
}
