"use client";

import { useState, useEffect, useCallback } from "react";

interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  rule_id: string | null;
  details: string;
  source: string;
}

const actionColors: Record<string, string> = {
  RuleAdded: "text-green-400",
  RuleRemoved: "text-red-400",
  RuleUpdated: "text-yellow-400",
  RulesApplied: "text-cyan-400",
  RulesFlushed: "text-orange-400",
  DaemonStarted: "text-blue-400",
  DaemonStopped: "text-gray-400",
  ConfigChanged: "text-purple-400",
};

export default function LogsPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("all");

  const fetchLogs = useCallback(async () => {
    try {
      const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
      const res = await fetch("/api/v1/logs", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Failed to fetch logs (${res.status})`);
      const json = await res.json();
      setEntries(json.data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 10_000);
    return () => clearInterval(interval);
  }, [fetchLogs]);

  const actions = [...new Set(entries.map((e) => e.action))];

  const filtered = entries.filter((entry) => {
    if (actionFilter !== "all" && entry.action !== actionFilter) return false;
    if (
      filter &&
      !entry.details.toLowerCase().includes(filter.toLowerCase()) &&
      !entry.action.toLowerCase().includes(filter.toLowerCase())
    )
      return false;
    return true;
  });

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-gray-400">Loading audit logs...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="bg-gray-800 border border-red-500/30 rounded-lg p-6 max-w-md text-center">
          <p className="text-red-400 font-medium mb-2">Error loading logs</p>
          <p className="text-sm text-gray-400">{error}</p>
          <button
            onClick={() => { setLoading(true); fetchLogs(); }}
            className="mt-4 px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 rounded-md transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Logs</h1>
        <p className="text-sm text-gray-400">
          Complete history of all firewall configuration changes -- auto-refreshes every 10s
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Search logs..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 px-3 py-2 text-sm bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="px-3 py-2 text-sm bg-gray-800 border border-gray-700 rounded-md text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Actions</option>
          {actions.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      {/* Log Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Action</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Rule ID</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Details</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-gray-500">
                    No log entries match your filter
                  </td>
                </tr>
              ) : (
                filtered.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-gray-700 hover:bg-gray-700/50 transition-colors"
                  >
                    <td className="py-2.5 px-3 text-gray-400 font-mono text-xs whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`text-xs font-medium ${actionColors[entry.action] || "text-gray-400"}`}
                      >
                        {entry.action}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      {entry.rule_id ? (
                        <span className="text-[10px] font-mono text-gray-400 bg-gray-900 px-1.5 py-0.5 rounded">
                          {entry.rule_id.length > 8
                            ? entry.rule_id.slice(0, 8)
                            : entry.rule_id}
                        </span>
                      ) : (
                        <span className="text-gray-600">--</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-300 font-mono max-w-md truncate">
                      {entry.details}
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-500">
                      {entry.source}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="text-xs text-gray-500 text-center">
        Showing {filtered.length} of {entries.length} entries
      </div>
    </div>
  );
}
