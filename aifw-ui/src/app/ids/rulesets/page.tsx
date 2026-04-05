"use client";

import { useState, useEffect, useCallback } from "react";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface Ruleset {
  id: string;
  name: string;
  source_url: string;
  rule_format: string;
  enabled: boolean;
  auto_update: boolean;
  rule_count: number;
  last_updated: string | null;
  created_at: string;
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

const formatBadge: Record<string, string> = {
  suricata: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  sigma: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  yara: "bg-orange-500/20 text-orange-400 border-orange-500/30",
};

export default function IdsRulesetsPage() {
  const [rulesets, setRulesets] = useState<Ruleset[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);

  // Add form
  const [showAddForm, setShowAddForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newFormat, setNewFormat] = useState<"suricata" | "sigma" | "yara">("suricata");
  const [newAutoUpdate, setNewAutoUpdate] = useState(true);
  const [adding, setAdding] = useState(false);

  // Toggle/Delete
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchRulesets = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/ids/rulesets`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`Failed to fetch rulesets: ${res.status}`);
      const json = await res.json();
      const d = json.data || json;
      setRulesets(d.rulesets || d || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load rulesets";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [clearFeedback]);

  useEffect(() => {
    fetchRulesets();
  }, [fetchRulesets]);

  async function handleAddRuleset() {
    if (!newName.trim() || !newUrl.trim()) return;

    setAdding(true);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/rulesets`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          name: newName.trim(),
          source_url: newUrl.trim(),
          rule_format: newFormat,
          enabled: true,
          auto_update: newAutoUpdate,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Create failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: `Ruleset "${newName.trim()}" created` });
      clearFeedback();
      setNewName("");
      setNewUrl("");
      setNewFormat("suricata");
      setNewAutoUpdate(true);
      setShowAddForm(false);
      await fetchRulesets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to create ruleset";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setAdding(false);
    }
  }

  async function handleToggleRuleset(ruleset: Ruleset) {
    setTogglingId(ruleset.id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/rulesets/${ruleset.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ enabled: !ruleset.enabled }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Toggle failed: ${res.status}`);
      }
      setFeedback({
        type: "success",
        message: `${ruleset.name} ${!ruleset.enabled ? "enabled" : "disabled"}`,
      });
      clearFeedback();
      await fetchRulesets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to toggle ruleset";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setTogglingId(null);
    }
  }

  async function handleDeleteRuleset(ruleset: Ruleset) {
    if (!confirm(`Delete ruleset "${ruleset.name}"? This will remove all associated rules.`))
      return;

    setDeletingId(ruleset.id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/rulesets/${ruleset.id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Delete failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: `Ruleset "${ruleset.name}" deleted` });
      clearFeedback();
      await fetchRulesets();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete ruleset";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">IDS Rulesets</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Manage detection rule sources and auto-update configuration
          </p>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-sm font-medium rounded-md transition-colors"
        >
          {showAddForm ? "Cancel" : "Add Ruleset"}
        </button>
      </div>

      <FeedbackBanner feedback={feedback} />

      {/* Add Ruleset Form */}
      {showAddForm && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-4">Add New Ruleset</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. ET Open Emerging Threats"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Format</label>
              <select
                value={newFormat}
                onChange={(e) =>
                  setNewFormat(e.target.value as "suricata" | "sigma" | "yara")
                }
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              >
                <option value="suricata">Suricata</option>
                <option value="sigma">Sigma</option>
                <option value="yara">YARA</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs text-[var(--text-muted)] mb-1">Source URL</label>
              <input
                type="url"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                placeholder="https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setNewAutoUpdate(!newAutoUpdate)}
                className="group flex items-center gap-2"
              >
                <div
                  className={`relative w-8 h-4 rounded-full transition-colors ${
                    newAutoUpdate ? "bg-green-600" : "bg-gray-600"
                  }`}
                >
                  <div
                    className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                      newAutoUpdate ? "left-4" : "left-0.5"
                    }`}
                  />
                </div>
                <span className="text-xs text-[var(--text-secondary)]">Auto-update</span>
              </button>
            </div>
            <div className="flex items-end justify-end">
              <button
                onClick={handleAddRuleset}
                disabled={!newName.trim() || !newUrl.trim() || adding}
                className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
              >
                {adding ? "Adding..." : "Add Ruleset"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rulesets */}
      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="text-center">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-sm text-[var(--text-muted)]">Loading rulesets...</p>
          </div>
        </div>
      ) : rulesets.length === 0 ? (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-12 text-center">
          <p className="text-sm text-[var(--text-muted)]">
            No rulesets configured. Add a ruleset to start detecting threats.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {rulesets.map((ruleset) => {
            const fmtStyle = formatBadge[ruleset.rule_format] || formatBadge.suricata;
            return (
              <div
                key={ruleset.id}
                className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 hover:bg-[var(--bg-card-hover)] transition-colors"
              >
                {/* Card header */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-medium truncate">{ruleset.name}</h3>
                      <span
                        className={`inline-flex items-center rounded border font-medium uppercase tracking-wider text-[10px] px-1.5 py-0.5 ${fmtStyle}`}
                      >
                        {ruleset.rule_format}
                      </span>
                    </div>
                    <p className="text-[11px] text-[var(--text-muted)] mt-0.5 truncate font-mono">
                      {ruleset.source_url}
                    </p>
                  </div>
                  <button
                    onClick={() => handleToggleRuleset(ruleset)}
                    disabled={togglingId === ruleset.id}
                    className="group flex items-center gap-1.5 disabled:opacity-40 ml-3 shrink-0"
                    title={`Click to ${ruleset.enabled ? "disable" : "enable"}`}
                  >
                    <div
                      className={`relative w-8 h-4 rounded-full transition-colors ${
                        ruleset.enabled ? "bg-green-600" : "bg-gray-600"
                      }`}
                    >
                      <div
                        className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                          ruleset.enabled ? "left-4" : "left-0.5"
                        }`}
                      />
                    </div>
                  </button>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-3 gap-3 text-xs mb-3">
                  <div>
                    <span className="text-[var(--text-muted)]">Rules</span>
                    <p className="font-mono text-sm font-bold text-[var(--text-primary)] mt-0.5">
                      {ruleset.rule_count.toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)]">Last Updated</span>
                    <p className="text-[var(--text-secondary)] mt-0.5">
                      {ruleset.last_updated
                        ? new Date(ruleset.last_updated).toLocaleDateString()
                        : "Never"}
                    </p>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)]">Auto-Update</span>
                    <p className="mt-0.5">
                      {ruleset.auto_update ? (
                        <span className="text-green-400">Enabled</span>
                      ) : (
                        <span className="text-[var(--text-muted)]">Disabled</span>
                      )}
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between pt-3 border-t border-[var(--border)]">
                  <span className="text-[10px] text-[var(--text-muted)]">
                    Created {new Date(ruleset.created_at).toLocaleDateString()}
                  </span>
                  <button
                    onClick={() => handleDeleteRuleset(ruleset)}
                    disabled={deletingId === ruleset.id}
                    className="text-xs text-[var(--text-muted)] hover:text-red-400 disabled:opacity-40 transition-colors flex items-center gap-1"
                  >
                    {deletingId === ruleset.id ? (
                      "Deleting..."
                    ) : (
                      <>
                        <svg
                          className="w-3.5 h-3.5"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                          strokeWidth={1.5}
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                          />
                        </svg>
                        Delete
                      </>
                    )}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
