"use client";

import { useState, useEffect, useCallback } from "react";
import { isValidHostname, isValidIPv4, isValidIPv6, isValidDomain } from "@/lib/validate";

/* -- Types ---------------------------------------------------------- */

interface HostOverride {
  id: string;
  hostname: string;
  domain: string;
  record_type: string;
  value: string;
  mx_priority?: number;
  description?: string;
  enabled: boolean;
  created_at: string;
}

interface HostForm {
  hostname: string;
  domain: string;
  record_type: string;
  value: string;
  mx_priority: string;
  description: string;
  enabled: boolean;
}

const defaultForm: HostForm = {
  hostname: "",
  domain: "",
  record_type: "A",
  value: "",
  mx_priority: "",
  description: "",
  enabled: true,
};

const RECORD_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT"];

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    A: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    AAAA: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    MX: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    CNAME: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    TXT: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  const cls = map[type] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} font-mono`}>{type}</span>
  );
}

/* -- Page ------------------------------------------------------------ */

export default function DnsHostsPage() {
  const [hosts, setHosts] = useState<HostOverride[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<HostForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchHosts = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/hosts", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setHosts(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load host overrides");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchHosts();
      setLoading(false);
    })();
  }, [fetchHosts]);

  /* -- Modal -------------------------------------------------------- */

  const openCreate = () => {
    setEditingId(null);
    setForm(defaultForm);
    setModalOpen(true);
  };

  const openEdit = (host: HostOverride) => {
    setEditingId(host.id);
    setForm({
      hostname: host.hostname,
      domain: host.domain,
      record_type: host.record_type,
      value: host.value,
      mx_priority: host.mx_priority != null ? String(host.mx_priority) : "",
      description: host.description || "",
      enabled: host.enabled,
    });
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setForm(defaultForm);
  };

  const handleSubmit = async () => {
    if (!form.hostname.trim() || !form.domain.trim() || !form.value.trim()) {
      showFeedback("error", "Hostname, domain, and value are required");
      return;
    }

    // Client-side validation
    const errors: string[] = [];
    if (!isValidHostname(form.hostname)) errors.push("Hostname: must be alphanumeric (hyphens allowed, no dots)");
    if (!isValidDomain(form.domain)) errors.push("Domain: invalid format (e.g. example.com)");
    if (form.record_type === "A" && !isValidIPv4(form.value)) errors.push("Value: must be a valid IPv4 address for A records");
    if (form.record_type === "AAAA" && !isValidIPv6(form.value)) errors.push("Value: must be a valid IPv6 address for AAAA records");
    if (form.record_type === "CNAME" && !isValidDomain(form.value)) errors.push("Value: must be a valid domain for CNAME records");
    if (form.record_type === "MX" && !isValidDomain(form.value)) errors.push("Value: must be a valid domain for MX records");
    if (errors.length > 0) { showFeedback("error", errors.join(". ")); return; }

    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        hostname: form.hostname.trim(),
        domain: form.domain.trim(),
        record_type: form.record_type,
        value: form.value.trim(),
        enabled: form.enabled,
      };
      if (form.record_type === "MX" && form.mx_priority.trim()) {
        payload.mx_priority = Number(form.mx_priority);
      }
      if (form.description.trim()) payload.description = form.description.trim();

      const url = editingId
        ? `/api/v1/dns/resolver/hosts/${editingId}`
        : "/api/v1/dns/resolver/hosts";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      showFeedback("success", editingId ? "Host override updated" : "Host override created");
      closeModal();
      await fetchHosts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save host override");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/dns/resolver/hosts/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Host override deleted");
      setDeleteId(null);
      await fetchHosts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete host override");
    }
  };

  const toggleEnabled = async (host: HostOverride) => {
    try {
      const res = await fetch(`/api/v1/dns/resolver/hosts/${host.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ ...host, enabled: !host.enabled }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await fetchHosts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to toggle host override");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading host overrides...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Host Overrides</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Override DNS records for specific hostnames
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Host Override
        </button>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* -- Table --------------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {hosts.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No host overrides configured. Click &quot;Add Host Override&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">FQDN</th>
                  <th className="px-6 py-3">Type</th>
                  <th className="px-6 py-3">Value</th>
                  <th className="px-6 py-3">Description</th>
                  <th className="px-6 py-3">Enabled</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((host) => (
                  <tr
                    key={host.id}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                    onClick={() => openEdit(host)}
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {host.hostname}.{host.domain}
                    </td>
                    <td className="px-6 py-3">
                      <TypeBadge type={host.record_type} />
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {host.record_type === "MX" && host.mx_priority != null
                        ? `${host.mx_priority} ${host.value}`
                        : host.value}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {host.description || "-"}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => toggleEnabled(host)}
                        className={`relative w-9 h-5 rounded-full transition-colors ${
                          host.enabled ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${
                            host.enabled ? "translate-x-4" : ""
                          }`}
                        />
                      </button>
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {fmtDate(host.created_at)}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setDeleteId(host.id)}
                          title="Delete"
                          className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
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

      {/* -- Create/Edit Modal --------------------------------------- */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-lg w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">
              {editingId ? "Edit Host Override" : "Add Host Override"}
            </h3>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Hostname</label>
                  <input
                    type="text"
                    value={form.hostname}
                    onChange={(e) => setForm((p) => ({ ...p, hostname: e.target.value }))}
                    placeholder="e.g. www"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Domain</label>
                  <input
                    type="text"
                    value={form.domain}
                    onChange={(e) => setForm((p) => ({ ...p, domain: e.target.value }))}
                    placeholder="e.g. home.lan"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Record Type</label>
                <select
                  value={form.record_type}
                  onChange={(e) => setForm((p) => ({ ...p, record_type: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  {RECORD_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  Value {form.record_type === "A" || form.record_type === "AAAA" ? "(IP Address)" : form.record_type === "CNAME" ? "(Target hostname)" : form.record_type === "MX" ? "(Mail server)" : "(Text value)"}
                </label>
                <input
                  type="text"
                  value={form.value}
                  onChange={(e) => setForm((p) => ({ ...p, value: e.target.value }))}
                  placeholder={
                    form.record_type === "A" ? "e.g. 192.168.1.100"
                    : form.record_type === "AAAA" ? "e.g. ::1"
                    : form.record_type === "CNAME" ? "e.g. other.home.lan"
                    : form.record_type === "MX" ? "e.g. mail.home.lan"
                    : "e.g. v=spf1 ..."
                  }
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {form.record_type === "MX" && (
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">MX Priority</label>
                  <input
                    type="number"
                    value={form.mx_priority}
                    onChange={(e) => setForm((p) => ({ ...p, mx_priority: e.target.value }))}
                    placeholder="e.g. 10"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
                  placeholder="Optional description"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Enable toggle */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setForm((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    form.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      form.enabled ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">Enabled</span>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {submitting ? "Saving..." : editingId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -- Delete Confirm Modal ------------------------------------ */}
      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Delete Host Override</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this host override? DNS queries for this hostname will
              no longer be overridden.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
