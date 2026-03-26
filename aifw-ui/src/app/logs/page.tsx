"use client";

import { useState } from "react";
import StatusBadge from "@/components/StatusBadge";

const demoLogs = [
  { id: "1", timestamp: "2026-03-25T14:32:01Z", action: "RuleAdded", ruleId: "a1b2c3d4", details: "pf: block in quick proto tcp to any port 22 keep state", source: "engine" },
  { id: "2", timestamp: "2026-03-25T14:31:45Z", action: "RulesApplied", ruleId: null, details: "24 rules applied to anchor aifw", source: "engine" },
  { id: "3", timestamp: "2026-03-25T14:30:12Z", action: "RuleRemoved", ruleId: "e5f6a7b8", details: "rule deleted", source: "engine" },
  { id: "4", timestamp: "2026-03-25T14:28:33Z", action: "RuleAdded", ruleId: "c9d0e1f2", details: "pf: pass in quick proto tcp to any port 443 keep state", source: "api" },
  { id: "5", timestamp: "2026-03-25T14:25:00Z", action: "DaemonStarted", ruleId: null, details: "AiFw daemon started", source: "daemon" },
  { id: "6", timestamp: "2026-03-25T14:24:55Z", action: "RulesApplied", ruleId: null, details: "18 rules applied to anchor aifw", source: "engine" },
  { id: "7", timestamp: "2026-03-25T14:20:10Z", action: "RulesFlushed", ruleId: null, details: "flushed anchor aifw", source: "engine" },
  { id: "8", timestamp: "2026-03-25T14:15:00Z", action: "ConfigChanged", ruleId: null, details: "metrics backend changed to postgres", source: "settings" },
  { id: "9", timestamp: "2026-03-25T13:45:22Z", action: "RuleAdded", ruleId: "f3a4b5c6", details: "pf: block drop in quick from <geoip_cn>", source: "geoip" },
  { id: "10", timestamp: "2026-03-25T13:30:00Z", action: "DaemonStarted", ruleId: null, details: "AiFw daemon started", source: "daemon" },
];

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
  const [filter, setFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("all");

  const filtered = demoLogs.filter((log) => {
    if (actionFilter !== "all" && log.action !== actionFilter) return false;
    if (filter && !log.details.toLowerCase().includes(filter.toLowerCase()) && !log.action.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  const actions = [...new Set(demoLogs.map((l) => l.action))];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Logs</h1>
        <p className="text-sm text-[var(--text-muted)]">Complete history of all firewall configuration changes</p>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Search logs..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 px-3 py-2 text-sm bg-[var(--bg-card)] border border-[var(--border)] rounded-md text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]"
        />
        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="px-3 py-2 text-sm bg-[var(--bg-card)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
        >
          <option value="all">All Actions</option>
          {actions.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
      </div>

      {/* Log entries */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg divide-y divide-[var(--border)]">
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">No log entries match your filter</div>
        ) : (
          filtered.map((log) => (
            <div key={log.id} className="p-3 hover:bg-[var(--bg-card-hover)] transition-colors">
              <div className="flex items-center gap-3 mb-1">
                <span className="text-xs text-[var(--text-muted)] font-mono w-20">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={`text-xs font-medium ${actionColors[log.action] || "text-gray-400"}`}>
                  {log.action}
                </span>
                {log.ruleId && (
                  <span className="text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-primary)] px-1.5 py-0.5 rounded">
                    {log.ruleId.slice(0, 8)}
                  </span>
                )}
                <span className="text-[10px] text-[var(--text-muted)]">via {log.source}</span>
              </div>
              <div className="text-sm text-[var(--text-secondary)] ml-[92px] font-mono">
                {log.details}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="text-xs text-[var(--text-muted)] text-center">
        Showing {filtered.length} of {demoLogs.length} entries
      </div>
    </div>
  );
}
