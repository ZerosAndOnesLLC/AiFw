"use client";

import { useState } from "react";
import DataTable from "@/components/DataTable";
import StatusBadge from "@/components/StatusBadge";

interface NatRule {
  id: string;
  nat_type: string;
  interface: string;
  protocol: string;
  src_addr: string;
  dst_addr: string;
  redirect: string;
  label: string;
  status: string;
}

const initialNatRules: NatRule[] = [
  { id: "n-001", nat_type: "rdr", interface: "em0", protocol: "tcp", src_addr: "any", dst_addr: "203.0.113.5", redirect: "10.0.0.10:80", label: "HTTP redirect", status: "active" },
  { id: "n-002", nat_type: "rdr", interface: "em0", protocol: "tcp", src_addr: "any", dst_addr: "203.0.113.5", redirect: "10.0.0.10:443", label: "HTTPS redirect", status: "active" },
  { id: "n-003", nat_type: "nat", interface: "em0", protocol: "any", src_addr: "10.0.0.0/24", dst_addr: "any", redirect: "203.0.113.5", label: "LAN masquerade", status: "active" },
  { id: "n-004", nat_type: "rdr", interface: "em0", protocol: "tcp", src_addr: "any", dst_addr: "203.0.113.5", redirect: "10.0.0.15:22", label: "SSH to internal", status: "active" },
  { id: "n-005", nat_type: "rdr", interface: "em0", protocol: "udp", src_addr: "any", dst_addr: "203.0.113.5", redirect: "10.0.0.5:53", label: "DNS redirect", status: "active" },
  { id: "n-006", nat_type: "nat", interface: "wg0", protocol: "any", src_addr: "10.10.0.0/24", dst_addr: "any", redirect: "10.0.0.1", label: "VPN NAT", status: "disabled" },
];

const defaultForm = {
  nat_type: "rdr",
  interface: "em0",
  protocol: "tcp",
  dst_addr: "",
  redirect_addr: "",
  redirect_port: "",
  label: "",
};

export default function NatPage() {
  const [natRules, setNatRules] = useState<NatRule[]>(initialNatRules);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(defaultForm);

  const handleDelete = (row: NatRule) => {
    setNatRules((prev) => prev.filter((r) => r.id !== row.id));
  };

  const handleAdd = () => {
    if (!form.label.trim() || !form.redirect_addr.trim()) return;
    const redirect = form.redirect_port
      ? `${form.redirect_addr}:${form.redirect_port}`
      : form.redirect_addr;
    const newRule: NatRule = {
      id: `n-${String(Date.now()).slice(-6)}`,
      nat_type: form.nat_type,
      interface: form.interface,
      protocol: form.protocol,
      src_addr: "any",
      dst_addr: form.dst_addr || "any",
      redirect,
      label: form.label,
      status: "active",
    };
    setNatRules((prev) => [...prev, newRule]);
    setForm(defaultForm);
    setShowForm(false);
  };

  const columns = [
    {
      key: "nat_type",
      label: "Type",
      className: "w-20",
      render: (row: NatRule) => (
        <span className={`text-xs font-mono font-medium uppercase ${
          row.nat_type === "rdr" ? "text-cyan-400" : "text-purple-400"
        }`}>
          {row.nat_type}
        </span>
      ),
    },
    {
      key: "interface",
      label: "Interface",
      className: "w-24",
      render: (row: NatRule) => (
        <span className="font-mono text-xs text-[var(--text-secondary)]">{row.interface}</span>
      ),
    },
    {
      key: "protocol",
      label: "Protocol",
      className: "w-24",
      render: (row: NatRule) => (
        <span className="font-mono text-xs text-[var(--text-secondary)]">{row.protocol}</span>
      ),
    },
    {
      key: "src_addr",
      label: "Source",
      render: (row: NatRule) => (
        <span className="font-mono text-xs">{row.src_addr}</span>
      ),
    },
    {
      key: "dst_addr",
      label: "Destination",
      render: (row: NatRule) => (
        <span className="font-mono text-xs">{row.dst_addr}</span>
      ),
    },
    {
      key: "redirect",
      label: "Redirect To",
      render: (row: NatRule) => (
        <span className="font-mono text-xs text-green-400">{row.redirect}</span>
      ),
    },
    {
      key: "label",
      label: "Label",
      render: (row: NatRule) => (
        <span className="text-xs text-[var(--text-secondary)]">{row.label}</span>
      ),
    },
    {
      key: "status",
      label: "Status",
      className: "w-24",
      render: (row: NatRule) => <StatusBadge status={row.status} />,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NAT Rules</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {natRules.length} rules &middot; {natRules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add NAT Rule
        </button>
      </div>

      {/* Inline Add Form */}
      {showForm && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">New NAT Rule</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Type</label>
              <select
                value={form.nat_type}
                onChange={(e) => setForm((f) => ({ ...f, nat_type: e.target.value }))}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="rdr">rdr (Redirect)</option>
                <option value="nat">nat (Masquerade)</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Interface</label>
              <select
                value={form.interface}
                onChange={(e) => setForm((f) => ({ ...f, interface: e.target.value }))}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              >
                <option value="em0">em0</option>
                <option value="em1">em1</option>
                <option value="wg0">wg0</option>
                <option value="lo0">lo0</option>
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
                <option value="any">any</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Destination</label>
              <input
                type="text"
                value={form.dst_addr}
                onChange={(e) => setForm((f) => ({ ...f, dst_addr: e.target.value }))}
                placeholder="e.g. 203.0.113.5"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Redirect Address</label>
              <input
                type="text"
                value={form.redirect_addr}
                onChange={(e) => setForm((f) => ({ ...f, redirect_addr: e.target.value }))}
                placeholder="e.g. 10.0.0.10"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Redirect Port</label>
              <input
                type="text"
                value={form.redirect_port}
                onChange={(e) => setForm((f) => ({ ...f, redirect_port: e.target.value }))}
                placeholder="e.g. 80"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <div className="md:col-span-2">
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

      {/* NAT Rules Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <DataTable<Record<string, unknown>>
          columns={columns as { key: string; label: string; render?: (row: Record<string, unknown>) => React.ReactNode; className?: string }[]}
          data={natRules as unknown as Record<string, unknown>[]}
          keyField="id"
          onDelete={(row) => handleDelete(row as unknown as NatRule)}
          emptyMessage="No NAT rules configured"
        />
      </div>
    </div>
  );
}
