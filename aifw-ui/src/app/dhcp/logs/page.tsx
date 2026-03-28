"use client";

import { useState, useEffect, useCallback } from "react";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

export default function DhcpLogsPage() {
  const [logs, setLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [lines, setLines] = useState(200);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = useCallback(async () => {
    try {
      const params = new URLSearchParams({ lines: String(lines) });
      if (search) params.set("search", search);
      const res = await fetch(`/api/v1/dhcp/logs?${params}`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLogs(data.data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch logs");
    } finally {
      setLoading(false);
    }
  }, [lines, search]);

  useEffect(() => {
    fetchLogs();
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [fetchLogs, autoRefresh]);

  const getLogLevel = (line: string): string => {
    if (line.includes("ERROR") || line.includes("FATAL")) return "error";
    if (line.includes("WARN")) return "warn";
    if (line.includes("DEBUG")) return "debug";
    return "info";
  };

  const levelColor = (level: string) => {
    switch (level) {
      case "error": return "text-red-400";
      case "warn": return "text-yellow-400";
      case "debug": return "text-gray-500";
      default: return "text-[var(--text-secondary)]";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">DHCP Logs</h1>
          <p className="text-sm text-[var(--text-muted)]">Kea DHCP server activity log</p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-[var(--text-muted)] cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded border-gray-600"
            />
            Auto-refresh
          </label>
          <button
            onClick={fetchLogs}
            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded-md transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search logs (IP, MAC, DHCPACK, DHCPDISCOVER...)"
          className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <select
          value={lines}
          onChange={(e) => setLines(Number(e.target.value))}
          className="bg-gray-800 border border-gray-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value={50}>50 lines</option>
          <option value={100}>100 lines</option>
          <option value={200}>200 lines</option>
          <option value={500}>500 lines</option>
          <option value={1000}>1000 lines</option>
        </select>
      </div>

      {/* Log output */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 border-b border-gray-700 flex items-center justify-between">
          <span className="text-xs text-[var(--text-muted)]">
            {logs.length} log entries · /var/log/kea-dhcp4.log
          </span>
          {autoRefresh && (
            <span className="flex items-center gap-1 text-xs text-green-400">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
              Live
            </span>
          )}
        </div>
        <div className="overflow-y-auto max-h-[calc(100vh-280px)] p-1">
          {loading ? (
            <div className="text-center py-8 text-[var(--text-muted)]">Loading logs...</div>
          ) : logs.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)]">
              {search ? "No matching log entries" : "No DHCP logs yet. Start the DHCP server to see activity."}
            </div>
          ) : (
            <div className="font-mono text-xs space-y-px">
              {logs.map((line, i) => {
                const level = getLogLevel(line);
                // Highlight key DHCP events
                const isDhcpEvent = /DHCPACK|DHCPNAK|DHCPOFFER|DHCPDISCOVER|DHCPREQUEST|DHCPRELEASE|DHCPDECLINE/.test(line);
                return (
                  <div
                    key={i}
                    className={`px-3 py-0.5 rounded hover:bg-gray-800 ${levelColor(level)} ${isDhcpEvent ? "bg-gray-800/50" : ""}`}
                  >
                    {line}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
