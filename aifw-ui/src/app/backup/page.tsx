"use client";

import { useState, useEffect, useCallback, useRef } from "react";

/* -- Types ---------------------------------------------------------- */

interface ConfigVersion {
  version: number;
  hash: string;
  applied: boolean;
  applied_at: string | null;
  rolled_back: boolean;
  created_by: string;
  created_at: string;
  comment: string | null;
  resource_count: number;
}

interface ConfigCheck {
  valid: boolean;
  errors: string[];
  warnings: string[];
  info: string[];
}

interface DiffSummary {
  v1: number;
  v2: number;
  v1_hash: string;
  v2_hash: string;
  identical: boolean;
  rules_diff: { added: number; removed: number; v1_count: number; v2_count: number };
  nat_diff: { added: number; removed: number; v1_count: number; v2_count: number };
  total_v1: number;
  total_v2: number;
  v1_json: Record<string, unknown>;
  v2_json: Record<string, unknown>;
}

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtDate(iso: string | null): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

const TABS = ["History", "Config Check", "Export / Import", "OPNsense Import"] as const;
type Tab = (typeof TABS)[number];

/* -- Page ------------------------------------------------------------ */

export default function BackupPage() {
  const [activeTab, setActiveTab] = useState<Tab>("History");
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [loading, setLoading] = useState(true);

  // History
  const [history, setHistory] = useState<ConfigVersion[]>([]);
  const [saving, setSaving] = useState(false);
  const [comment, setComment] = useState("");
  const [restoring, setRestoring] = useState<number | null>(null);

  // Diff
  const [diff, setDiff] = useState<DiffSummary | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffV1, setDiffV1] = useState<number | null>(null);
  const [diffV2, setDiffV2] = useState<number | null>(null);
  const [diffSection, setDiffSection] = useState<string>("rules");

  // Config check
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [checking, setChecking] = useState(false);

  // Export/Import
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  // OPNsense
  const [opnXml, setOpnXml] = useState("");
  const [opnImporting, setOpnImporting] = useState(false);
  const [opnPreview, setOpnPreview] = useState<Record<string, unknown> | null>(null);
  const [opnIfaceMap, setOpnIfaceMap] = useState<Record<string, string>>({});
  const opnFileRef = useRef<HTMLInputElement>(null);

  // Commit Confirm
  const [commitConfirm, setCommitConfirm] = useState<{ active: boolean; seconds_remaining: number; description: string } | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 8000);
  };

  /* -- Fetch History ------------------------------------------------- */

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/config/history?limit=100", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setHistory(body.data || []);
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchHistory();
      setLoading(false);
    })();
  }, [fetchHistory]);

  /* -- Save snapshot ------------------------------------------------- */

  const saveSnapshot = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/v1/config/save", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ comment: comment || null }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Config snapshot saved");
      setComment("");
      await fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  /* -- Restore ------------------------------------------------------- */

  const restore = async (version: number) => {
    if (!confirm(`Restore to version ${version}? This will replace all current rules and NAT configuration.`)) return;
    setRestoring(version);
    try {
      const res = await fetch("/api/v1/config/restore", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ version }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Restored");
      await fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Restore failed");
    } finally {
      setRestoring(null);
    }
  };

  /* -- Diff ---------------------------------------------------------- */

  const loadDiff = async (v1: number, v2: number) => {
    setDiffLoading(true);
    setDiffV1(v1);
    setDiffV2(v2);
    try {
      const res = await fetch(`/api/v1/config/diff?v1=${v1}&v2=${v2}`, { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setDiff(body.data);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Diff failed");
    } finally {
      setDiffLoading(false);
    }
  };

  /* -- Config Check -------------------------------------------------- */

  const runCheck = async () => {
    setChecking(true);
    try {
      const res = await fetch("/api/v1/config/check", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setCheck(body.data);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Check failed");
    } finally {
      setChecking(false);
    }
  };

  /* -- Export -------------------------------------------------------- */

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await fetch("/api/v1/config/export", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aifw-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showFeedback("success", "Config exported");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  /* -- Import -------------------------------------------------------- */

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setPreview(text);
    };
    reader.readAsText(file);
  };

  const handleImport = async () => {
    if (!preview) return;
    setImporting(true);
    try {
      const data = JSON.parse(preview);
      const res = await fetch("/api/v1/config/import", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      showFeedback("success", body.message || "Config imported");
      setPreview(null);
      if (fileRef.current) fileRef.current.value = "";
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  /* -- OPNsense Import ----------------------------------------------- */

  const handleOpnFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setOpnXml(ev.target?.result as string);
    reader.readAsText(file);
  };

  const handleOpnPreview = async () => {
    if (!opnXml.trim()) return;
    try {
      const res = await fetch("/api/v1/config/preview-opnsense", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ xml: opnXml }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setOpnPreview(data);
      // Initialize interface mapping with empty values
      const found = (data.interfaces_found || []) as string[];
      const map: Record<string, string> = {};
      for (const i of found) map[i] = "";
      setOpnIfaceMap(map);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Preview failed");
    }
  };

  const handleOpnImport = async () => {
    if (!opnXml.trim() || !opnPreview) return;
    setOpnImporting(true);
    try {
      const res = await fetch("/api/v1/config/import-opnsense", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ xml: opnXml, interface_map: opnIfaceMap }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      showFeedback("success", body.message || "OPNsense config imported");
      setOpnXml(""); setOpnPreview(null); setOpnIfaceMap({});
      if (opnFileRef.current) opnFileRef.current.value = "";
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setOpnImporting(false);
    }
  };

  /* -- Commit Confirm ------------------------------------------------ */

  const fetchCommitStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/config/commit-confirm/status", { headers: authHeadersPlain() });
      if (res.ok) {
        const data = await res.json();
        setCommitConfirm(data.active ? data : null);
      }
    } catch { /* silent */ }
  }, []);

  const handleCommitConfirm = async () => {
    try {
      const res = await fetch("/api/v1/config/commit-confirm/confirm", { method: "POST", headers: authHeaders() });
      if (res.ok) {
        const body = await res.json();
        showFeedback("success", body.message);
        setCommitConfirm(null);
      }
    } catch (err) {
      showFeedback("error", "Failed to confirm");
    }
  };

  // Poll commit confirm status
  useEffect(() => {
    fetchCommitStatus();
    const t = setInterval(fetchCommitStatus, 5000);
    return () => clearInterval(t);
  }, [fetchCommitStatus]);

  /* -- Render -------------------------------------------------------- */

  const inputClass = "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]";
  const btnPrimary = "px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50";
  const btnSecondary = "px-3 py-1.5 text-xs border border-[var(--border)] rounded-md text-[var(--text-secondary)] hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50";

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Backup & Restore</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Manage config versions, compare changes, validate, and restore previous configurations
        </p>
      </div>

      {feedback && (
        <div className={`p-3 text-sm rounded-md border ${
          feedback.type === "success"
            ? "text-green-400 bg-green-500/10 border-green-500/20"
            : "text-red-400 bg-red-500/10 border-red-500/20"
        }`}>
          {feedback.msg}
        </div>
      )}

      {/* Tabs */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex border-b border-[var(--border)] overflow-x-auto">
          {TABS.map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium whitespace-nowrap transition-colors ${
                activeTab === tab
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}>
              {tab}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* ===================== History Tab ===================== */}
          {activeTab === "History" && (
            <div className="space-y-5">
              {/* Save snapshot */}
              <div className="flex gap-3 items-end">
                <div className="flex-1">
                  <label className="text-xs text-[var(--text-muted)] block mb-1">Save Current Config</label>
                  <input type="text" value={comment} onChange={e => setComment(e.target.value)}
                    placeholder="Optional comment (e.g. 'before NAT changes')"
                    className={inputClass}
                    onKeyDown={e => e.key === "Enter" && saveSnapshot()} />
                </div>
                <button onClick={saveSnapshot} disabled={saving} className={btnPrimary}>
                  {saving ? "Saving..." : "Save Snapshot"}
                </button>
              </div>

              {/* Version history table */}
              {history.length === 0 ? (
                <div className="text-center py-12 text-[var(--text-muted)]">
                  <p className="text-lg mb-2">No config versions saved yet</p>
                  <p className="text-sm">Save a snapshot to start tracking configuration changes</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border)]">
                        <th className="pb-2 pr-4">Version</th>
                        <th className="pb-2 pr-4">Status</th>
                        <th className="pb-2 pr-4">Resources</th>
                        <th className="pb-2 pr-4">Created</th>
                        <th className="pb-2 pr-4">Comment</th>
                        <th className="pb-2 pr-4">Hash</th>
                        <th className="pb-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((v, idx) => (
                        <tr key={v.version} className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-primary)]/50">
                          <td className="py-2.5 pr-4 font-mono font-semibold">v{v.version}</td>
                          <td className="py-2.5 pr-4">
                            {v.applied ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30">Active</span>
                            ) : v.rolled_back ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">Rolled Back</span>
                            ) : (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-gray-500/20 text-gray-400 border border-gray-500/30">Saved</span>
                            )}
                          </td>
                          <td className="py-2.5 pr-4 text-[var(--text-muted)]">{v.resource_count}</td>
                          <td className="py-2.5 pr-4 text-[var(--text-muted)] whitespace-nowrap">{fmtDate(v.created_at)}</td>
                          <td className="py-2.5 pr-4 text-[var(--text-secondary)] max-w-[200px] truncate">{v.comment || "-"}</td>
                          <td className="py-2.5 pr-4 font-mono text-xs text-[var(--text-muted)]">{v.hash.substring(0, 8)}</td>
                          <td className="py-2.5 text-right space-x-2 whitespace-nowrap">
                            {!v.applied && (
                              <button onClick={() => restore(v.version)}
                                disabled={restoring === v.version}
                                className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors disabled:opacity-50">
                                {restoring === v.version ? "..." : "Restore"}
                              </button>
                            )}
                            {idx < history.length - 1 && (
                              <button onClick={() => loadDiff(history[idx + 1].version, v.version)}
                                className={btnSecondary}>
                                Diff
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Diff viewer */}
              {diff && (
                <div className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold">
                      Comparing v{diffV1} → v{diffV2}
                      {diff.identical && <span className="ml-2 text-xs text-green-400">(identical)</span>}
                    </h3>
                    <button onClick={() => setDiff(null)} className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]">Close</button>
                  </div>

                  {diffLoading ? (
                    <div className="flex justify-center py-6">
                      <div className="w-5 h-5 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
                    </div>
                  ) : (
                    <>
                      {/* Summary */}
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
                        <div className="bg-[var(--bg-card)] rounded p-3">
                          <div className="text-xs text-[var(--text-muted)]">Rules</div>
                          <div className="font-semibold">{diff.rules_diff.v1_count} → {diff.rules_diff.v2_count}</div>
                          <div className="text-xs">
                            {diff.rules_diff.added > 0 && <span className="text-green-400">+{diff.rules_diff.added} </span>}
                            {diff.rules_diff.removed > 0 && <span className="text-red-400">-{diff.rules_diff.removed}</span>}
                            {diff.rules_diff.added === 0 && diff.rules_diff.removed === 0 && <span className="text-[var(--text-muted)]">no change</span>}
                          </div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded p-3">
                          <div className="text-xs text-[var(--text-muted)]">NAT Rules</div>
                          <div className="font-semibold">{diff.nat_diff.v1_count} → {diff.nat_diff.v2_count}</div>
                          <div className="text-xs">
                            {diff.nat_diff.added > 0 && <span className="text-green-400">+{diff.nat_diff.added} </span>}
                            {diff.nat_diff.removed > 0 && <span className="text-red-400">-{diff.nat_diff.removed}</span>}
                            {diff.nat_diff.added === 0 && diff.nat_diff.removed === 0 && <span className="text-[var(--text-muted)]">no change</span>}
                          </div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded p-3">
                          <div className="text-xs text-[var(--text-muted)]">Total Resources</div>
                          <div className="font-semibold">{diff.total_v1} → {diff.total_v2}</div>
                        </div>
                        <div className="bg-[var(--bg-card)] rounded p-3">
                          <div className="text-xs text-[var(--text-muted)]">Hash Match</div>
                          <div className={`font-semibold ${diff.identical ? "text-green-400" : "text-yellow-400"}`}>
                            {diff.identical ? "Identical" : "Changed"}
                          </div>
                        </div>
                      </div>

                      {/* JSON diff */}
                      <div>
                        <div className="flex gap-2 mb-3">
                          {["rules", "nat", "system", "auth", "vpn", "geoip"].map(s => (
                            <button key={s} onClick={() => setDiffSection(s)}
                              className={`px-3 py-1 text-xs rounded-md transition-colors ${
                                diffSection === s
                                  ? "bg-blue-600/20 border border-blue-500/40 text-blue-400"
                                  : "bg-[var(--bg-card)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                              }`}>
                              {s}
                            </button>
                          ))}
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          <div>
                            <div className="text-xs text-[var(--text-muted)] mb-1">v{diffV1}</div>
                            <pre className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-80 text-red-300">
                              {JSON.stringify((diff.v1_json as Record<string, unknown>)[diffSection] ?? {}, null, 2)}
                            </pre>
                          </div>
                          <div>
                            <div className="text-xs text-[var(--text-muted)] mb-1">v{diffV2}</div>
                            <pre className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-80 text-green-300">
                              {JSON.stringify((diff.v2_json as Record<string, unknown>)[diffSection] ?? {}, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ===================== Config Check Tab ================ */}
          {activeTab === "Config Check" && (
            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold">Configuration Validator</h2>
                  <p className="text-xs text-[var(--text-muted)]">Checks firewall rules, NAT, DNS, VPN, and pf status for common issues</p>
                </div>
                <button onClick={runCheck} disabled={checking} className={btnPrimary}>
                  {checking ? "Checking..." : "Run Check"}
                </button>
              </div>

              {check && (
                <div className="space-y-4">
                  {/* Overall status */}
                  <div className={`flex items-center gap-3 p-4 rounded-lg border ${
                    check.valid
                      ? "bg-green-500/10 border-green-500/20"
                      : "bg-red-500/10 border-red-500/20"
                  }`}>
                    <div className={`w-10 h-10 rounded-full flex items-center justify-center text-lg ${
                      check.valid ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"
                    }`}>
                      {check.valid ? "\u2713" : "\u2717"}
                    </div>
                    <div>
                      <div className={`font-semibold ${check.valid ? "text-green-400" : "text-red-400"}`}>
                        {check.valid ? "Configuration Valid" : "Issues Found"}
                      </div>
                      <div className="text-xs text-[var(--text-muted)]">
                        {check.errors.length} errors, {check.warnings.length} warnings, {check.info.length} info
                      </div>
                    </div>
                  </div>

                  {/* Errors */}
                  {check.errors.length > 0 && (
                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider">Errors</h3>
                      {check.errors.map((e, i) => (
                        <div key={i} className="flex items-start gap-2 p-2.5 bg-red-500/10 border border-red-500/20 rounded text-sm text-red-300">
                          <span className="text-red-400 mt-0.5">&#x2716;</span> {e}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Warnings */}
                  {check.warnings.length > 0 && (
                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider">Warnings</h3>
                      {check.warnings.map((w, i) => (
                        <div key={i} className="flex items-start gap-2 p-2.5 bg-yellow-500/10 border border-yellow-500/20 rounded text-sm text-yellow-300">
                          <span className="text-yellow-400 mt-0.5">&#x26A0;</span> {w}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Info */}
                  {check.info.length > 0 && (
                    <div className="space-y-1">
                      <h3 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Info</h3>
                      {check.info.map((inf, i) => (
                        <div key={i} className="flex items-start gap-2 p-2.5 bg-blue-500/10 border border-blue-500/20 rounded text-sm text-blue-300">
                          <span className="text-blue-400 mt-0.5">&#x2139;</span> {inf}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ===================== Export / Import Tab ================ */}
          {activeTab === "Export / Import" && (
            <div className="space-y-6">
              {/* Export */}
              <div className="space-y-3">
                <h2 className="text-lg font-semibold">Export Configuration</h2>
                <p className="text-xs text-[var(--text-muted)]">Download the current firewall configuration as a JSON file</p>
                <button onClick={handleExport} disabled={exporting} className={btnPrimary}>
                  {exporting ? "Exporting..." : "Download Backup"}
                </button>
              </div>

              <hr className="border-[var(--border)]" />

              {/* Import */}
              <div className="space-y-3">
                <h2 className="text-lg font-semibold">Import Configuration</h2>
                <p className="text-xs text-[var(--text-muted)]">Upload a previously exported AiFw configuration JSON file</p>
                <input ref={fileRef} type="file" accept=".json" onChange={handleFileSelect}
                  className="block w-full text-sm text-[var(--text-secondary)] file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-[var(--accent)] file:text-white hover:file:bg-[var(--accent-hover)]" />
                {preview && (
                  <div className="space-y-3">
                    <details>
                      <summary className="text-xs text-[var(--text-muted)] cursor-pointer hover:text-[var(--text-secondary)]">
                        Preview JSON ({(preview.length / 1024).toFixed(1)} KB)
                      </summary>
                      <pre className="mt-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-60 text-[var(--text-secondary)]">
                        {preview.substring(0, 5000)}{preview.length > 5000 ? "\n... (truncated)" : ""}
                      </pre>
                    </details>
                    <div className="flex gap-3">
                      <button onClick={handleImport} disabled={importing} className={btnPrimary}>
                        {importing ? "Importing..." : "Import & Apply"}
                      </button>
                      <button onClick={() => { setPreview(null); if (fileRef.current) fileRef.current.value = ""; }}
                        className={btnSecondary}>Cancel</button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== OPNsense Import Tab ================ */}
          {activeTab === "OPNsense Import" && (
            <div className="space-y-5">
              {/* Commit Confirm Banner */}
              {commitConfirm && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-semibold text-amber-400">Pending Config Change — Confirm Required</p>
                      <p className="text-xs text-amber-300 mt-1">
                        {commitConfirm.description}. If you do not confirm within <strong>{commitConfirm.seconds_remaining}s</strong>, the configuration will automatically revert to the previous state.
                      </p>
                      <p className="text-xs text-amber-300/70 mt-1">
                        If your network configuration changed, log in at the new IP address to confirm.
                      </p>
                    </div>
                    <button onClick={handleCommitConfirm}
                      className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded font-medium whitespace-nowrap">
                      Confirm Config
                    </button>
                  </div>
                </div>
              )}

              <div>
                <h2 className="text-lg font-semibold">Import from OPNsense</h2>
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Upload an OPNsense/pfSense <code className="bg-[var(--bg-primary)] px-1 rounded">config.xml</code> backup file.
                  AiFw will validate and show a summary before importing.
                </p>
              </div>

              {/* Step 1: Upload */}
              <div className="space-y-3">
                <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 1: Upload config.xml</label>
                <input ref={opnFileRef} type="file" accept=".xml" onChange={handleOpnFileSelect}
                  className="block w-full text-sm text-[var(--text-secondary)] file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-[var(--accent)] file:text-white hover:file:bg-[var(--accent-hover)]" />

                {opnXml && !opnPreview && (
                  <div className="flex gap-3">
                    <button onClick={handleOpnPreview} className={btnPrimary}>Analyze Config</button>
                    <button onClick={() => { setOpnXml(""); if (opnFileRef.current) opnFileRef.current.value = ""; }}
                      className={btnSecondary}>Cancel</button>
                  </div>
                )}
              </div>

              {/* Step 2: Preview + Interface Mapping */}
              {opnPreview && (
                <div className="space-y-4">
                  {!(opnPreview as Record<string, unknown>).valid ? (
                    <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-sm text-red-400">
                      This does not appear to be a valid OPNsense/pfSense configuration file.
                    </div>
                  ) : (
                    <>
                      <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 2: Review Summary</label>
                      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-2 text-sm">
                        {(opnPreview as { hostname?: string }).hostname && (
                          <div className="flex justify-between"><span className="text-[var(--text-muted)]">Hostname</span><span>{(opnPreview as { hostname: string }).hostname}</span></div>
                        )}
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Firewall Rules</span><span className="font-mono">{((opnPreview as { rules: unknown[] }).rules || []).length}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">NAT Rules</span><span className="font-mono">{((opnPreview as { nat_rules: unknown[] }).nat_rules || []).length}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Static Routes</span><span className="font-mono">{((opnPreview as { routes: unknown[] }).routes || []).length}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">DNS Servers</span><span className="font-mono">{((opnPreview as { dns_servers: string[] }).dns_servers || []).join(", ") || "none"}</span></div>
                      </div>

                      {/* Interface Mapping */}
                      {(opnPreview as { interfaces_need_mapping: boolean }).interfaces_need_mapping && (
                        <div className="space-y-2">
                          <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 3: Map Interfaces</label>
                          <p className="text-xs text-amber-300">
                            The config references interfaces that don't match this system. Map each OPNsense interface to a local interface.
                          </p>
                          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 space-y-2">
                            {((opnPreview as { interfaces_found: string[] }).interfaces_found || []).map((ci: string) => (
                              <div key={ci} className="flex items-center gap-3">
                                <span className="text-xs font-mono text-amber-400 w-20">{ci}</span>
                                <span className="text-xs text-[var(--text-muted)]">→</span>
                                <select value={opnIfaceMap[ci] || ""} onChange={(e) => setOpnIfaceMap(prev => ({ ...prev, [ci]: e.target.value }))}
                                  className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-white">
                                  <option value="">-- select --</option>
                                  {((opnPreview as { interfaces_system: string[] }).interfaces_system || []).map((si: string) => (
                                    <option key={si} value={si}>{si}</option>
                                  ))}
                                </select>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Confirm Import */}
                      <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 text-xs text-yellow-300">
                        Review the summary above. Imported rules will be added to your existing configuration. DNS servers will be applied immediately.
                      </div>
                      <div className="flex gap-3">
                        <button onClick={handleOpnImport} disabled={opnImporting} className={btnPrimary}>
                          {opnImporting ? "Importing..." : "Confirm & Import"}
                        </button>
                        <button onClick={() => { setOpnXml(""); setOpnPreview(null); setOpnIfaceMap({}); if (opnFileRef.current) opnFileRef.current.value = ""; }}
                          className={btnSecondary}>Cancel</button>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
