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

interface IdsRule {
  id: string;
  sid: number;
  msg: string | null;
  severity: number;
  enabled: boolean;
  action_override: string | null;
  hit_count: number;
  ruleset_id: string;
  rule_text: string;
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

const severityLabel: Record<number, string> = { 1: "critical", 2: "high", 3: "medium", 4: "info" };
const severityStyles: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const actionOptions = ["alert", "drop", "reject", "pass"];

export default function IdsRulesPage() {
  const [rules, setRules] = useState<IdsRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);
  const [total, setTotal] = useState(0);

  // Filters
  const [search, setSearch] = useState("");
  const [enabledFilter, setEnabledFilter] = useState<"" | "true" | "false">("");

  // Pagination
  const [page, setPage] = useState(0);
  const limit = 50;

  // Updating
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchRules = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      params.set("limit", String(limit));
      params.set("offset", String(page * limit));
      if (search.trim()) params.set("search", search.trim());
      if (enabledFilter) params.set("enabled", enabledFilter);

      const res = await fetch(`${API}/api/v1/ids/rules?${params.toString()}`, {
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`Failed to fetch rules: ${res.status}`);
      const json = await res.json();
      const d = json.data || json;
      setRules(d.rules || d || []);
      setTotal(d.total ?? (d.rules || d || []).length);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load rules";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [page, search, enabledFilter, clearFeedback]);

  useEffect(() => {
    setLoading(true);
    fetchRules();
  }, [fetchRules]);

  async function handleToggleEnabled(rule: IdsRule) {
    setUpdatingId(rule.id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/rules/${rule.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          enabled: !rule.enabled,
          action_override: rule.action_override,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Toggle failed: ${res.status}`);
      }
      setFeedback({
        type: "success",
        message: `SID ${rule.sid} ${!rule.enabled ? "enabled" : "disabled"}`,
      });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to toggle rule";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setUpdatingId(null);
    }
  }

  async function handleActionOverride(rule: IdsRule, newAction: string) {
    setUpdatingId(rule.id);
    setFeedback(null);
    try {
      const override_action = newAction === "alert" && !rule.action_override ? null : newAction;
      const res = await fetch(`${API}/api/v1/ids/rules/${rule.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          enabled: rule.enabled,
          action_override: override_action,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Override failed: ${res.status}`);
      }
      setFeedback({
        type: "success",
        message: `SID ${rule.sid} action set to ${newAction}`,
      });
      clearFeedback();
      await fetchRules();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to update action";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setUpdatingId(null);
    }
  }

  function handleSearch() {
    setPage(0);
  }

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">IDS Rules</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage detection signatures and rule actions
        </p>
      </div>

      <FeedbackBanner feedback={feedback} />

      {/* Search & Filters */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Search by SID or message
            </label>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              placeholder="e.g. 2100498 or SQL injection"
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Status</label>
            <select
              value={enabledFilter}
              onChange={(e) => setEnabledFilter(e.target.value as "" | "true" | "false")}
              className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            >
              <option value="">All</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>
          <button
            onClick={handleSearch}
            className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-sm font-medium rounded-md transition-colors"
          >
            Search
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-sm font-medium">Detection Rules</h3>
          <span className="text-xs text-[var(--text-muted)]">
            {total.toLocaleString()} rules &middot; page {page + 1} of{" "}
            {Math.max(totalPages, 1)}
          </span>
        </div>

        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
            Loading rules...
          </div>
        ) : rules.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
            No rules matching current filters
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-24">
                    SID
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Message
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-24">
                    Severity
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">
                    Enabled
                  </th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">
                    Hits
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-28">
                    Action
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-32">
                    Ruleset
                  </th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => {
                  const sevLabel = severityLabel[rule.severity] || "info";
                  const sevStyle =
                    severityStyles[sevLabel] || severityStyles.info;
                  const effectiveAction =
                    rule.action_override || "alert";
                  return (
                    <tr
                      key={rule.id}
                      className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors"
                    >
                      <td className="py-2.5 px-3 text-xs font-mono text-cyan-400">
                        {rule.sid}
                      </td>
                      <td className="py-2.5 px-3 text-xs text-[var(--text-primary)] max-w-[400px] truncate">
                        {rule.msg || rule.rule_text?.slice(0, 80)}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`inline-flex items-center rounded border font-medium uppercase tracking-wider text-[10px] px-1.5 py-0.5 ${sevStyle}`}
                        >
                          {sevLabel}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => handleToggleEnabled(rule)}
                          disabled={updatingId === rule.id}
                          className="group flex items-center gap-1.5 disabled:opacity-40"
                          title={`Click to ${rule.enabled ? "disable" : "enable"}`}
                        >
                          <div
                            className={`relative w-8 h-4 rounded-full transition-colors ${
                              rule.enabled ? "bg-green-600" : "bg-gray-600"
                            }`}
                          >
                            <div
                              className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                                rule.enabled ? "left-4" : "left-0.5"
                              }`}
                            />
                          </div>
                        </button>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-right font-mono text-[var(--text-secondary)]">
                        {rule.hit_count.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3">
                        <select
                          value={effectiveAction}
                          onChange={(e) =>
                            handleActionOverride(rule, e.target.value)
                          }
                          disabled={updatingId === rule.id}
                          className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] disabled:opacity-40 transition-colors"
                        >
                          {actionOptions.map((action) => (
                            <option key={action} value={action}>
                              {action}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-[var(--text-muted)] truncate max-w-[120px]">
                        {rule.ruleset_id?.slice(0, 8)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-4 py-3 border-t border-[var(--border)] flex items-center justify-between">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1.5 text-xs bg-[var(--bg-primary)] border border-[var(--border)] rounded-md hover:bg-[var(--bg-card-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Previous
            </button>
            <span className="text-xs text-[var(--text-muted)]">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1.5 text-xs bg-[var(--bg-primary)] border border-[var(--border)] rounded-md hover:bg-[var(--bg-card-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
