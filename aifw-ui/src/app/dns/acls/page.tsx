"use client";

import { useState, useEffect, useCallback } from "react";
import { validateCIDR } from "@/lib/validate";

/* -- Types ---------------------------------------------------------- */

interface AccessListEntry {
  id: string;
  network: string;
  action: string;
  description?: string;
  created_at: string;
}

interface AclForm {
  network: string;
  action: string;
  description: string;
}

const defaultForm: AclForm = {
  network: "",
  action: "allow",
  description: "",
};

const ACL_ACTIONS = ["allow", "deny", "refuse", "allow_snoop"];

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

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    allow: "bg-green-500/20 text-green-400 border-green-500/30",
    deny: "bg-red-500/20 text-red-400 border-red-500/30",
    refuse: "bg-red-500/20 text-red-400 border-red-500/30",
    allow_snoop: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  };
  const cls = map[action] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls}`}>{action}</span>
  );
}

/* -- Page ------------------------------------------------------------ */

export default function DnsAclsPage() {
  const [acls, setAcls] = useState<AccessListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Form state (inline, no modal needed for simple entries)
  const [form, setForm] = useState<AclForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchAcls = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/acls", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setAcls(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load access lists");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchAcls();
      setLoading(false);
    })();
  }, [fetchAcls]);

  /* -- Actions ------------------------------------------------------ */

  const handleSubmit = async () => {
    if (!form.network.trim()) {
      showFeedback("error", "Network (CIDR) is required");
      return;
    }

    // Client-side validation
    const e = validateCIDR(form.network, "Network");
    if (e) { showFeedback("error", e); return; }

    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        network: form.network.trim(),
        action: form.action,
      };
      if (form.description.trim()) payload.description = form.description.trim();

      const res = await fetch("/api/v1/dns/resolver/acls", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      showFeedback("success", "Access list entry created");
      setForm(defaultForm);
      await fetchAcls();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to create access list entry");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/dns/resolver/acls/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Access list entry deleted");
      setDeleteId(null);
      await fetchAcls();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete access list entry");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading access lists...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">Access Lists</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Control which networks can query the DNS resolver
        </p>
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

      {/* -- Add Form ------------------------------------------------ */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-sm font-semibold mb-4">Add Access List Entry</h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Network (CIDR)</label>
            <input
              type="text"
              value={form.network}
              onChange={(e) => setForm((p) => ({ ...p, network: e.target.value }))}
              placeholder="e.g. 192.168.1.0/24"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Action</label>
            <select
              value={form.action}
              onChange={(e) => setForm((p) => ({ ...p, action: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
            >
              {ACL_ACTIONS.map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Description</label>
            <input
              type="text"
              value={form.description}
              onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
              placeholder="Optional"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <button
              onClick={handleSubmit}
              disabled={submitting}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              {submitting ? "Adding..." : "Add"}
            </button>
          </div>
        </div>
      </div>

      {/* -- Table --------------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {acls.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No access list entries configured. Add one above.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Network</th>
                  <th className="px-6 py-3">Action</th>
                  <th className="px-6 py-3">Description</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {acls.map((acl) => (
                  <tr
                    key={acl.id}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02]"
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {acl.network}
                    </td>
                    <td className="px-6 py-3">
                      <ActionBadge action={acl.action} />
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {acl.description || "-"}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {fmtDate(acl.created_at)}
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex items-center justify-end">
                        <button
                          onClick={() => setDeleteId(acl.id)}
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

      {/* -- Delete Confirm Modal ------------------------------------ */}
      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Delete Access List Entry</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this access list entry? The affected network will
              lose its current access policy.
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
