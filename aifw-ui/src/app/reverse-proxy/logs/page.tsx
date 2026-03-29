"use client";

import { useState, useEffect, useCallback } from "react";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

type LogType = "server" | "access";

export default function ReverseProxyLogsPage() {
  const [logs, setLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [lines, setLines] = useState(200);
  const [logType, setLogType] = useState<LogType>("server");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = useCallback(async () => {
    try {
      const params = new URLSearchParams({ lines: String(lines), log_type: logType });
      if (search) params.set("search", search);
      const res = await fetch(`/api/v1/reverse-proxy/logs?${params}`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setLogs(data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch logs");
    } finally {
      setLoading(false);
    }
  }, [lines, search, logType]);

  useEffect(() => {
    setLoading(true);
    fetchLogs();
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [fetchLogs, autoRefresh]);

  const getLogLevel = (line: string): string => {
    if (line.includes("ERROR") || line.includes("FATAL")) return "error";
    if (line.includes("WARN")) return "warn";
    if (line.includes("DEBUG") || line.includes("TRACE")) return "debug";
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

  const logFile = logType === "server"
    ? "/var/log/trafficcop/trafficcop.log"
    : "/var/log/trafficcop/access.log";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Logs</h1>
          <p className="text-sm text-[var(--text-muted)]">TrafficCop reverse proxy logs</p>
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

      {/* Log type tabs */}
      <div className="flex gap-0 border-b border-[var(--border)]">
        <button
          onClick={() => setLogType("server")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            logType === "server"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          Server Log
        </button>
        <button
          onClick={() => setLogType("access")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            logType === "access"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
          }`}
        >
          Access Log
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={logType === "server" ? "Search logs..." : "Search (URL, status code, IP...)"}
          className="flex-1 px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
        <select
          value={lines}
          onChange={(e) => setLines(Number(e.target.value))}
          className="bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value={50}>50 lines</option>
          <option value={100}>100 lines</option>
          <option value={200}>200 lines</option>
          <option value={500}>500 lines</option>
        </select>
      </div>

      {/* Log output */}
      <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
        <div className="px-4 py-2 border-b border-gray-700 flex items-center justify-between">
          <span className="text-xs text-[var(--text-muted)]">
            {logs.length} log entries · {logFile}
          </span>
          {autoRefresh && (
            <span className="flex items-center gap-1 text-xs text-green-400">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
              Live
            </span>
          )}
        </div>
        <div className="overflow-y-auto max-h-[calc(100vh-340px)] p-1">
          {loading ? (
            <div className="text-center py-8 text-[var(--text-muted)]">Loading logs...</div>
          ) : logs.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)]">
              {search ? "No matching log entries" : "No log entries found"}
            </div>
          ) : (
            <div className="font-mono text-xs space-y-px">
              {logs.map((line, i) => {
                const level = getLogLevel(line);
                return (
                  <div
                    key={i}
                    className={`px-3 py-0.5 rounded hover:bg-gray-800 ${levelColor(level)}`}
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
