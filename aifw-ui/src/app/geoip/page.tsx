"use client";

import { useState, useEffect, useCallback } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface GeoIpRule {
  id: string;
  country_code: string;
  action: string;
  cidr_count: number;
  status: string;
  created_at: string;
}

interface LookupResult {
  ip: string;
  country_code: string;
  country_name: string;
  found: boolean;
}

interface SectionFeedback {
  type: "success" | "error";
  message: string;
}

function FeedbackBanner({ feedback }: { feedback: SectionFeedback | null }) {
  if (!feedback) return null;
  const isError = feedback.type === "error";
  return (
    <div
      className={`p-3 text-sm rounded-md border ${
        isError
          ? "text-red-400 bg-red-500/10 border-red-500/20"
          : "text-green-400 bg-green-500/10 border-green-500/20"
      }`}
    >
      {feedback.message}
    </div>
  );
}

export default function GeoIpPage() {
  const [rules, setRules] = useState<GeoIpRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);

  // Add form
  const [newCountryCode, setNewCountryCode] = useState("");
  const [newAction, setNewAction] = useState<"block" | "allow">("block");
  const [adding, setAdding] = useState(false);

  // Edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editCountryCode, setEditCountryCode] = useState("");
  const [editAction, setEditAction] = useState<"block" | "allow">("block");
  const [editStatus, setEditStatus] = useState<"active" | "disabled">("active");
  const [saving, setSaving] = useState(false);

  // Lookup
  const [lookupIp, setLookupIp] = useState("");
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookupError, setLookupError] = useState("");
  const [lookupLoading, setLookupLoading] = useState(false);

  // Toggling / deleting
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  // ── Fetch all rules ──
  const fetchRules = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/geoip`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`Failed to fetch rules: ${res.status}`);
      const json = await res.json();
      setRules(json.data || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load rules";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [clearFeedback]);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  // ── Create rule ──
  async function handleAddRule() {
    const code = newCountryCode.trim().toUpperCase();
    if (!code || code.length !== 2) return;

    setAdding(true);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/geoip`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ country_code: code, action: newAction }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Create failed: ${res.status}`);
      }
      setNewCountryCode("");
      setFeedback({ type: "success", message: `Rule for ${code} created` });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create rule";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setAdding(false);
    }
  }

  // ── Update rule ──
  async function handleUpdateRule(id: string) {
    setSaving(true);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/geoip/${id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          country_code: editCountryCode.trim().toUpperCase(),
          action: editAction,
          status: editStatus,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Update failed: ${res.status}`);
      }
      setEditingId(null);
      setFeedback({ type: "success", message: "Rule updated" });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update rule";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setSaving(false);
    }
  }

  // ── Toggle status ──
  async function handleToggleStatus(rule: GeoIpRule) {
    const newStatus = rule.status === "active" ? "disabled" : "active";
    setTogglingId(rule.id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/geoip/${rule.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          country_code: rule.country_code,
          action: rule.action,
          status: newStatus,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Toggle failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: `${rule.country_code} ${newStatus}` });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to toggle status";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setTogglingId(null);
    }
  }

  // ── Delete rule ──
  async function handleDeleteRule(id: string, countryCode: string) {
    if (!confirm(`Delete rule for ${countryCode}?`)) return;

    setDeletingId(id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/geoip/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Delete failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: `Rule for ${countryCode} deleted` });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete rule";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setDeletingId(null);
    }
  }

  // ── IP Lookup ──
  async function handleLookup() {
    setLookupError("");
    setLookupResult(null);

    const trimmed = lookupIp.trim();
    if (!trimmed) {
      setLookupError("Enter an IP address");
      return;
    }

    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (!ipPattern.test(trimmed)) {
      setLookupError("Invalid IPv4 address format");
      return;
    }

    setLookupLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/geoip/lookup/${encodeURIComponent(trimmed)}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Lookup failed: ${res.status}`);
      }
      const data: LookupResult = await res.json();
      setLookupResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Lookup failed";
      setLookupError(msg);
    } finally {
      setLookupLoading(false);
    }
  }

  // ── Start editing a row ──
  function startEdit(rule: GeoIpRule) {
    setEditingId(rule.id);
    setEditCountryCode(rule.country_code);
    setEditAction(rule.action as "block" | "allow");
    setEditStatus(rule.status as "active" | "disabled");
  }

  function cancelEdit() {
    setEditingId(null);
  }

  // ── Computed stats ──
  const blockedCountries = rules.filter((r) => r.action === "block" && r.status === "active").length;
  const allowedCountries = rules.filter((r) => r.action === "allow" && r.status === "active").length;
  const totalCidrs = rules.reduce((sum, r) => sum + (r.cidr_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Geo-IP Filtering</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Country-level traffic filtering using MaxMind GeoIP databases and pf tables
        </p>
      </div>

      {/* Feedback */}
      <FeedbackBanner feedback={feedback} />

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <Card title="Countries Blocked" value={blockedCountries} color="red" subtitle="active block rules" />
        <Card title="Countries Allowed" value={allowedCountries} color="green" subtitle="active allow rules" />
        <Card title="CIDRs Loaded" value={totalCidrs.toLocaleString()} color="cyan" subtitle="across all tables" />
      </div>

      {/* Geo-IP Rules Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-sm font-medium">Geo-IP Rules</h3>
          <span className="text-xs text-[var(--text-muted)]">{rules.length} rules</span>
        </div>

        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">Loading rules...</div>
        ) : rules.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">No geo-IP rules configured</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Country Code</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Action</th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">CIDRs</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Status</th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Created</th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                    {editingId === rule.id ? (
                      <>
                        {/* Inline edit row */}
                        <td className="py-2.5 px-3">
                          <input
                            type="text"
                            value={editCountryCode}
                            onChange={(e) => setEditCountryCode(e.target.value.toUpperCase().slice(0, 2))}
                            maxLength={2}
                            className="w-16 bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-sm font-mono uppercase text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                          />
                        </td>
                        <td className="py-2.5 px-3">
                          <select
                            value={editAction}
                            onChange={(e) => setEditAction(e.target.value as "block" | "allow")}
                            className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                          >
                            <option value="block">block</option>
                            <option value="allow">allow</option>
                          </select>
                        </td>
                        <td className="py-2.5 px-3 text-right text-xs text-[var(--text-secondary)]">
                          {(rule.cidr_count || 0).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-3">
                          <select
                            value={editStatus}
                            onChange={(e) => setEditStatus(e.target.value as "active" | "disabled")}
                            className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                          >
                            <option value="active">active</option>
                            <option value="disabled">disabled</option>
                          </select>
                        </td>
                        <td className="py-2.5 px-3 text-xs text-[var(--text-muted)]">
                          {new Date(rule.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => handleUpdateRule(rule.id)}
                              disabled={saving}
                              className="px-2 py-1 text-xs bg-green-600 hover:bg-green-500 disabled:opacity-40 text-white rounded transition-colors"
                            >
                              {saving ? "..." : "Save"}
                            </button>
                            <button
                              onClick={cancelEdit}
                              className="px-2 py-1 text-xs bg-gray-600 hover:bg-gray-500 text-white rounded transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        {/* Display row */}
                        <td className="py-2.5 px-3 font-mono text-xs font-bold">{rule.country_code}</td>
                        <td className="py-2.5 px-3">
                          <StatusBadge status={rule.action} />
                        </td>
                        <td className="py-2.5 px-3 text-xs text-right text-[var(--text-secondary)]">
                          {(rule.cidr_count || 0).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-3">
                          <button
                            onClick={() => handleToggleStatus(rule)}
                            disabled={togglingId === rule.id}
                            className="group flex items-center gap-1.5 disabled:opacity-40"
                            title={`Click to ${rule.status === "active" ? "disable" : "enable"}`}
                          >
                            <div
                              className={`relative w-8 h-4 rounded-full transition-colors ${
                                rule.status === "active" ? "bg-green-600" : "bg-gray-600"
                              }`}
                            >
                              <div
                                className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                                  rule.status === "active" ? "left-4" : "left-0.5"
                                }`}
                              />
                            </div>
                            <span className="text-xs text-[var(--text-muted)] group-hover:text-[var(--text-primary)] transition-colors">
                              {togglingId === rule.id ? "..." : rule.status}
                            </span>
                          </button>
                        </td>
                        <td className="py-2.5 px-3 text-xs text-[var(--text-muted)]">
                          {new Date(rule.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => startEdit(rule)}
                              className="text-[var(--text-muted)] hover:text-blue-400 transition-colors"
                              title="Edit rule"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                              </svg>
                            </button>
                            <button
                              onClick={() => handleDeleteRule(rule.id, rule.country_code)}
                              disabled={deletingId === rule.id}
                              className="text-[var(--text-muted)] hover:text-red-400 disabled:opacity-40 transition-colors"
                              title="Delete rule"
                            >
                              {deletingId === rule.id ? (
                                <span className="text-xs">...</span>
                              ) : (
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                </svg>
                              )}
                            </button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bottom Row: Lookup + Add Rule */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* IP Lookup */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">IP Address Lookup</h3>
          <p className="text-xs text-[var(--text-muted)] mb-4">Check which country an IP address maps to</p>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={lookupIp}
              onChange={(e) => setLookupIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              placeholder="e.g. 203.0.113.42"
              className="flex-1 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
            <button
              onClick={handleLookup}
              disabled={lookupLoading}
              className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-40 text-white text-sm font-medium rounded-md transition-colors"
            >
              {lookupLoading ? "..." : "Lookup"}
            </button>
          </div>

          {lookupError && (
            <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
              {lookupError}
            </div>
          )}

          {lookupResult && (
            <div className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm">{lookupResult.ip}</span>
                {lookupResult.found ? (
                  <span className="text-xs px-2 py-0.5 rounded bg-green-500/20 text-green-400 border border-green-500/30">
                    Found
                  </span>
                ) : (
                  <span className="text-xs px-2 py-0.5 rounded bg-gray-500/20 text-gray-400 border border-gray-500/30">
                    Not Found
                  </span>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[var(--text-muted)]">Country:</span>
                  <span className="ml-2 text-[var(--text-primary)]">
                    {lookupResult.country_name || "Unknown"}
                  </span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">Code:</span>
                  <span className="ml-2 font-mono text-[var(--text-primary)]">
                    {lookupResult.country_code || "--"}
                  </span>
                </div>
              </div>
            </div>
          )}

          {!lookupResult && !lookupError && (
            <div className="text-xs text-[var(--text-muted)]">
              Enter an IP address to look up its country of origin
            </div>
          )}
        </div>

        {/* Add Rule */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Add Geo-IP Rule</h3>
          <p className="text-xs text-[var(--text-muted)] mb-4">Add a new country-level block or allow rule</p>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Country Code (ISO 3166-1 alpha-2)</label>
              <input
                type="text"
                value={newCountryCode}
                onChange={(e) => setNewCountryCode(e.target.value.toUpperCase().slice(0, 2))}
                placeholder="e.g. FR"
                maxLength={2}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors font-mono uppercase"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Action</label>
              <select
                value={newAction}
                onChange={(e) => setNewAction(e.target.value as "block" | "allow")}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              >
                <option value="block">Block</option>
                <option value="allow">Allow</option>
              </select>
            </div>
            <button
              onClick={handleAddRule}
              disabled={!newCountryCode.trim() || newCountryCode.trim().length !== 2 || adding}
              className="w-full px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
            >
              {adding ? "Adding..." : "Add Rule"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
