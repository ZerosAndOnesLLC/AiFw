"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface DomainOverride {
  id: string;
  domain: string;
  server: string;
  description?: string;
  enabled: boolean;
  created_at: string;
}

interface DomainForm {
  domain: string;
  server: string;
  description: string;
  enabled: boolean;
}

const defaultForm: DomainForm = {
  domain: "",
  server: "",
  description: "",
  enabled: true,
};

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

/* -- Page ------------------------------------------------------------ */

export default function DnsDomainsPage() {
  const [domains, setDomains] = useState<DomainOverride[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<DomainForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchDomains = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/domains", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setDomains(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load domain overrides");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchDomains();
      setLoading(false);
    })();
  }, [fetchDomains]);

  /* -- Modal -------------------------------------------------------- */

  const openCreate = () => {
    setEditingId(null);
    setForm(defaultForm);
    setModalOpen(true);
  };

  const openEdit = (d: DomainOverride) => {
    setEditingId(d.id);
    setForm({
      domain: d.domain,
      server: d.server,
      description: d.description || "",
      enabled: d.enabled,
    });
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setForm(defaultForm);
  };

  const handleSubmit = async () => {
    if (!form.domain.trim() || !form.server.trim()) {
      showFeedback("error", "Domain and DNS server are required");
      return;
    }
    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        domain: form.domain.trim(),
        server: form.server.trim(),
        enabled: form.enabled,
      };
      if (form.description.trim()) payload.description = form.description.trim();

      const url = editingId
        ? `/api/v1/dns/resolver/domains/${editingId}`
        : "/api/v1/dns/resolver/domains";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      showFeedback("success", editingId ? "Domain override updated" : "Domain override created");
      closeModal();
      await fetchDomains();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save domain override");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/dns/resolver/domains/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Domain override deleted");
      setDeleteId(null);
      await fetchDomains();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete domain override");
    }
  };

  const toggleEnabled = async (d: DomainOverride) => {
    try {
      const res = await fetch(`/api/v1/dns/resolver/domains/${d.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ ...d, enabled: !d.enabled }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await fetchDomains();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to toggle domain override");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading domain overrides...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Domain Overrides</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Forward specific domains to designated DNS servers
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Domain Override
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
        {domains.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No domain overrides configured. Click &quot;Add Domain Override&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Domain</th>
                  <th className="px-6 py-3">DNS Server</th>
                  <th className="px-6 py-3">Description</th>
                  <th className="px-6 py-3">Enabled</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => (
                  <tr
                    key={d.id}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                    onClick={() => openEdit(d)}
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {d.domain}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {d.server}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {d.description || "-"}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => toggleEnabled(d)}
                        className={`relative w-9 h-5 rounded-full transition-colors ${
                          d.enabled ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${
                            d.enabled ? "translate-x-4" : ""
                          }`}
                        />
                      </button>
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {fmtDate(d.created_at)}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEdit(d)}
                          title="Edit"
                          className="p-1.5 text-[var(--text-muted)] hover:text-blue-400 rounded hover:bg-blue-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => setDeleteId(d.id)}
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
              {editingId ? "Edit Domain Override" : "Add Domain Override"}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Domain</label>
                <input
                  type="text"
                  value={form.domain}
                  onChange={(e) => setForm((p) => ({ ...p, domain: e.target.value }))}
                  placeholder="e.g. corp.local"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">DNS Server (IP:port)</label>
                <input
                  type="text"
                  value={form.server}
                  onChange={(e) => setForm((p) => ({ ...p, server: e.target.value }))}
                  placeholder="e.g. 10.0.0.1:53"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-[var(--text-muted)] mt-1">IP address and optional port of the DNS server for this domain</p>
              </div>

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
            <h3 className="text-lg font-semibold text-white">Delete Domain Override</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this domain override? Queries for this domain will
              use the default resolver.
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
