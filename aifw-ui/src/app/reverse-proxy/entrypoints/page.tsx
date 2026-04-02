"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface EntryPoint {
  id: string;
  name: string;
  address: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

interface EntryPointForm {
  name: string;
  address: string;
  asDefault: boolean;
  enabled: boolean;
  redirectTo: string;
  redirectScheme: string;
  redirectPermanent: boolean;
  certResolver: string;
  tlsOptions: string;
  trustedIps: string;
  forwardInsecure: boolean;
  readTimeout: string;
  writeTimeout: string;
  idleTimeout: string;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

const defaultForm: EntryPointForm = {
  name: "",
  address: "",
  asDefault: false,
  enabled: true,
  redirectTo: "",
  redirectScheme: "https",
  redirectPermanent: true,
  certResolver: "",
  tlsOptions: "",
  trustedIps: "",
  forwardInsecure: false,
  readTimeout: "",
  writeTimeout: "",
  idleTimeout: "",
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

/** Build config_json from form fields, only including non-empty sections. */
function buildConfigJson(form: EntryPointForm): string {
  const cfg: Record<string, unknown> = {};

  if (form.asDefault) cfg.asDefault = true;

  // HTTP redirect section
  if (form.redirectTo.trim()) {
    cfg.http = {
      redirections: {
        entryPoint: {
          to: form.redirectTo.trim(),
          scheme: form.redirectScheme,
          permanent: form.redirectPermanent,
        },
      },
    };
  }

  // TLS section — merge into http if it already exists
  if (form.certResolver.trim() || form.tlsOptions.trim()) {
    const tls: Record<string, string> = {};
    if (form.certResolver.trim()) tls.certResolver = form.certResolver.trim();
    if (form.tlsOptions.trim()) tls.options = form.tlsOptions.trim();
    if (cfg.http && typeof cfg.http === "object") {
      (cfg.http as Record<string, unknown>).tls = tls;
    } else {
      cfg.http = { tls };
    }
  }

  // Forwarded headers
  if (form.trustedIps.trim() || form.forwardInsecure) {
    const fh: Record<string, unknown> = {};
    if (form.trustedIps.trim()) {
      fh.trustedIps = form.trustedIps.split(",").map((s) => s.trim()).filter(Boolean);
    }
    if (form.forwardInsecure) fh.insecure = true;
    cfg.forwardedHeaders = fh;
  }

  // Transport timeouts
  if (form.readTimeout.trim() || form.writeTimeout.trim() || form.idleTimeout.trim()) {
    const timeouts: Record<string, string> = {};
    if (form.readTimeout.trim()) timeouts.readTimeout = form.readTimeout.trim();
    if (form.writeTimeout.trim()) timeouts.writeTimeout = form.writeTimeout.trim();
    if (form.idleTimeout.trim()) timeouts.idleTimeout = form.idleTimeout.trim();
    cfg.transport = { respondingTimeouts: timeouts };
  }

  return JSON.stringify(cfg);
}

/** Parse config_json string into form fields. */
function parseConfigJson(raw: string): Partial<EntryPointForm> {
  try {
    const cfg = JSON.parse(raw || "{}");
    const partial: Partial<EntryPointForm> = {};

    if (cfg.asDefault) partial.asDefault = true;

    // HTTP redirect
    const redir = cfg.http?.redirections?.entryPoint;
    if (redir) {
      if (redir.to) partial.redirectTo = redir.to;
      if (redir.scheme) partial.redirectScheme = redir.scheme;
      if (redir.permanent !== undefined) partial.redirectPermanent = redir.permanent;
    }

    // TLS
    const tls = cfg.http?.tls;
    if (tls) {
      if (tls.certResolver) partial.certResolver = tls.certResolver;
      if (tls.options) partial.tlsOptions = tls.options;
    }

    // Forwarded headers
    const fh = cfg.forwardedHeaders;
    if (fh) {
      if (Array.isArray(fh.trustedIps)) partial.trustedIps = fh.trustedIps.join(", ");
      if (fh.insecure) partial.forwardInsecure = true;
    }

    // Transport timeouts
    const t = cfg.transport?.respondingTimeouts;
    if (t) {
      if (t.readTimeout) partial.readTimeout = t.readTimeout;
      if (t.writeTimeout) partial.writeTimeout = t.writeTimeout;
      if (t.idleTimeout) partial.idleTimeout = t.idleTimeout;
    }

    return partial;
  } catch {
    return {};
  }
}

/** Derive display values from config_json for table cells. */
function parseConfigDisplay(raw: string): { isDefault: boolean; redirect: string; tls: string } {
  try {
    const cfg = JSON.parse(raw || "{}");
    const isDefault = !!cfg.asDefault;
    const redir = cfg.http?.redirections?.entryPoint;
    const redirect = redir?.to ? `${redir.to} (${redir.scheme || "https"})` : "-";
    const tls = cfg.http?.tls?.certResolver || cfg.http?.tls?.options || "-";
    return { isDefault, redirect, tls };
  } catch {
    return { isDefault: false, redirect: "-", tls: "-" };
  }
}

/* -- Page ------------------------------------------------------------ */

export default function EntrypointsPage() {
  const [entrypoints, setEntrypoints] = useState<EntryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<EntryPointForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);

  // Collapsible sections
  const [showRedirect, setShowRedirect] = useState(false);
  const [showTls, setShowTls] = useState(false);
  const [showTransport, setShowTransport] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchEntrypoints = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/entrypoints", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setEntrypoints(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load entrypoints");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchEntrypoints();
      setLoading(false);
    })();
  }, [fetchEntrypoints]);

  /* -- Modal -------------------------------------------------------- */

  const openCreate = () => {
    setEditingId(null);
    setForm(defaultForm);
    setShowRedirect(false);
    setShowTls(false);
    setShowTransport(false);
    setModalOpen(true);
  };

  const openEdit = (ep: EntryPoint) => {
    const parsed = parseConfigJson(ep.config_json);
    const merged: EntryPointForm = { ...defaultForm, ...parsed, name: ep.name, address: ep.address, enabled: ep.enabled };
    setEditingId(ep.id);
    setForm(merged);
    // Auto-expand sections that have values
    setShowRedirect(!!parsed.redirectTo);
    setShowTls(!!parsed.certResolver || !!parsed.tlsOptions);
    setShowTransport(!!parsed.readTimeout || !!parsed.writeTimeout || !!parsed.idleTimeout);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setForm(defaultForm);
  };

  const handleSubmit = async () => {
    if (!form.name.trim() || !form.address.trim()) {
      showFeedback("error", "Name and address are required");
      return;
    }
    setSubmitting(true);
    try {
      const payload = {
        name: form.name.trim(),
        address: form.address.trim(),
        config_json: buildConfigJson(form),
        enabled: form.enabled,
      };

      const url = editingId
        ? `/api/v1/reverse-proxy/entrypoints/${editingId}`
        : "/api/v1/reverse-proxy/entrypoints";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }

      showFeedback("success", editingId ? "Entrypoint updated" : "Entrypoint created");
      closeModal();
      await fetchEntrypoints();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save entrypoint");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/reverse-proxy/entrypoints/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Entrypoint deleted");
      setDeleteId(null);
      await fetchEntrypoints();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete entrypoint");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading entrypoints...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Entrypoints</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Configure listen addresses for the reverse proxy
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Entrypoint
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
        {entrypoints.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No entrypoints configured. Click &quot;Add Entrypoint&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Address</th>
                  <th className="px-6 py-3">Default</th>
                  <th className="px-6 py-3">Redirect</th>
                  <th className="px-6 py-3">TLS</th>
                  <th className="px-6 py-3">Enabled</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {entrypoints.map((ep) => {
                  const display = parseConfigDisplay(ep.config_json);
                  return (
                    <tr
                      key={ep.id}
                      className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                      onClick={() => openEdit(ep)}
                    >
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">
                        {ep.name}
                      </td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                        {ep.address}
                      </td>
                      <td className="px-6 py-3">
                        {display.isDefault ? (
                          <span className="text-xs px-2 py-0.5 rounded-full border bg-blue-500/20 text-blue-400 border-blue-500/30">
                            Yes
                          </span>
                        ) : (
                          <span className="text-[var(--text-muted)]">-</span>
                        )}
                      </td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">
                        {display.redirect}
                      </td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">
                        {display.tls}
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full border ${
                            ep.enabled
                              ? "bg-green-500/20 text-green-400 border-green-500/30"
                              : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                          }`}
                        >
                          {ep.enabled ? "Active" : "Disabled"}
                        </span>
                      </td>
                      <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => openEdit(ep)}
                            title="Edit"
                            className="p-1.5 text-[var(--text-muted)] hover:text-blue-400 rounded hover:bg-blue-500/10"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                          <button
                            onClick={() => setDeleteId(ep.id)}
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
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* -- Create/Edit Modal --------------------------------------- */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingId ? "Edit Entrypoint" : "Add Entrypoint"}
            </h3>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. web, websecure"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* Address */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Address</label>
                <input
                  type="text"
                  value={form.address}
                  onChange={(e) => setForm((p) => ({ ...p, address: e.target.value }))}
                  placeholder=":80 or :443"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* As Default toggle */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">As Default</label>
                <button
                  type="button"
                  onClick={() => setForm((p) => ({ ...p, asDefault: !p.asDefault }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    form.asDefault ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      form.asDefault ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* Enabled toggle */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enabled</label>
                <button
                  type="button"
                  onClick={() => setForm((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    form.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      form.enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* -- HTTP Redirect Section (collapsible) -------------- */}
              <div className="border border-[var(--border)] rounded-md">
                <button
                  type="button"
                  onClick={() => setShowRedirect((p) => !p)}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  <span>HTTP Redirect</span>
                  <svg
                    className={`w-4 h-4 transition-transform ${showRedirect ? "rotate-180" : ""}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {showRedirect && (
                  <div className="px-4 pb-4 space-y-3">
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Redirect To</label>
                      <input
                        type="text"
                        value={form.redirectTo}
                        onChange={(e) => setForm((p) => ({ ...p, redirectTo: e.target.value }))}
                        placeholder="e.g. websecure"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Scheme</label>
                      <select
                        value={form.redirectScheme}
                        onChange={(e) => setForm((p) => ({ ...p, redirectScheme: e.target.value }))}
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                      >
                        <option value="https">https</option>
                        <option value="http">http</option>
                      </select>
                    </div>
                    <div className="flex items-center justify-between">
                      <label className="text-sm text-[var(--text-secondary)]">Permanent (301 vs 302)</label>
                      <button
                        type="button"
                        onClick={() => setForm((p) => ({ ...p, redirectPermanent: !p.redirectPermanent }))}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          form.redirectPermanent ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            form.redirectPermanent ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* -- TLS Section (collapsible) ------------------------ */}
              <div className="border border-[var(--border)] rounded-md">
                <button
                  type="button"
                  onClick={() => setShowTls((p) => !p)}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  <span>TLS</span>
                  <svg
                    className={`w-4 h-4 transition-transform ${showTls ? "rotate-180" : ""}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {showTls && (
                  <div className="px-4 pb-4 space-y-3">
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Cert Resolver</label>
                      <input
                        type="text"
                        value={form.certResolver}
                        onChange={(e) => setForm((p) => ({ ...p, certResolver: e.target.value }))}
                        placeholder="e.g. letsencrypt"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">TLS Options</label>
                      <input
                        type="text"
                        value={form.tlsOptions}
                        onChange={(e) => setForm((p) => ({ ...p, tlsOptions: e.target.value }))}
                        placeholder="e.g. modern"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* -- Forwarded Headers Section (inside Transport) ------ */}
              {/* -- Transport Section (collapsible) ------------------- */}
              <div className="border border-[var(--border)] rounded-md">
                <button
                  type="button"
                  onClick={() => setShowTransport((p) => !p)}
                  className="w-full flex items-center justify-between px-4 py-2.5 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                >
                  <span>Transport</span>
                  <svg
                    className={`w-4 h-4 transition-transform ${showTransport ? "rotate-180" : ""}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {showTransport && (
                  <div className="px-4 pb-4 space-y-3">
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Trusted IPs (comma-separated)</label>
                      <input
                        type="text"
                        value={form.trustedIps}
                        onChange={(e) => setForm((p) => ({ ...p, trustedIps: e.target.value }))}
                        placeholder="e.g. 10.0.0.0/8, 172.16.0.0/12"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                    <div className="flex items-center justify-between">
                      <label className="text-sm text-[var(--text-secondary)]">Insecure Forwarded Headers</label>
                      <button
                        type="button"
                        onClick={() => setForm((p) => ({ ...p, forwardInsecure: !p.forwardInsecure }))}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          form.forwardInsecure ? "bg-blue-600" : "bg-gray-600"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            form.forwardInsecure ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                    </div>
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Read Timeout</label>
                      <input
                        type="text"
                        value={form.readTimeout}
                        onChange={(e) => setForm((p) => ({ ...p, readTimeout: e.target.value }))}
                        placeholder="e.g. 60s"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Write Timeout</label>
                      <input
                        type="text"
                        value={form.writeTimeout}
                        onChange={(e) => setForm((p) => ({ ...p, writeTimeout: e.target.value }))}
                        placeholder="e.g. 60s"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-[var(--text-muted)] mb-1">Idle Timeout</label>
                      <input
                        type="text"
                        value={form.idleTimeout}
                        onChange={(e) => setForm((p) => ({ ...p, idleTimeout: e.target.value }))}
                        placeholder="e.g. 180s"
                        className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
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
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">Delete Entrypoint</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this entrypoint? Any routers referencing it will stop working.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
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
