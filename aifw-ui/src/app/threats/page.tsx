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

const THREAT_KEYWORDS = [
  "threat_detected",
  "auto_response",
  "blocked",
  "brute_force",
  "ddos",
  "port_scan",
  "c2_beacon",
  "dns_tunnel",
  "intrusion",
  "anomaly",
  "malicious",
  "attack",
];

function isThreatEntry(entry: AuditEntry): boolean {
  const text = `${entry.action} ${entry.details}`.toLowerCase();
  return THREAT_KEYWORDS.some((kw) => text.includes(kw));
}

function extractThreatType(entry: AuditEntry): string {
  const text = `${entry.action} ${entry.details}`.toLowerCase();
  if (text.includes("ddos")) return "DDoS";
  if (text.includes("brute_force")) return "Brute Force";
  if (text.includes("port_scan")) return "Port Scan";
  if (text.includes("c2_beacon")) return "C2 Beacon";
  if (text.includes("dns_tunnel")) return "DNS Tunnel";
  if (text.includes("intrusion")) return "Intrusion";
  if (text.includes("anomaly")) return "Anomaly";
  return entry.action;
}

function extractScore(entry: AuditEntry): number | null {
  const match = entry.details.match(/score[:\s]+([0-9.]+)/i);
  if (match) return parseFloat(match[1]);
  return null;
}

function severityFromAction(entry: AuditEntry): "high" | "medium" | "low" {
  const score = extractScore(entry);
  if (score !== null) {
    if (score > 0.7) return "high";
    if (score > 0.4) return "medium";
    return "low";
  }
  const text = `${entry.action} ${entry.details}`.toLowerCase();
  if (text.includes("blocked") || text.includes("auto_response")) return "high";
  if (text.includes("flagged") || text.includes("rate_limited")) return "medium";
  return "low";
}

function severityColor(severity: "high" | "medium" | "low"): string {
  if (severity === "high") return "#ef4444";
  if (severity === "medium") return "#eab308";
  return "#22c55e";
}

export default function ThreatsPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    try {
      const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
      const res = await fetch("/api/v1/logs", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Failed to fetch logs (${res.status})`);
      const json = await res.json();
      const allEntries: AuditEntry[] = json.data || [];
      setEntries(allEntries.filter(isThreatEntry));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 10_000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-gray-400">Loading threat data...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="bg-gray-800 border border-red-500/30 rounded-lg p-6 max-w-md text-center">
          <p className="text-red-400 font-medium mb-2">Error loading threats</p>
          <p className="text-sm text-gray-400">{error}</p>
          <button
            onClick={() => { setLoading(true); fetchThreats(); }}
            className="mt-4 px-4 py-2 text-sm bg-gray-700 hover:bg-gray-600 rounded-md transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <div className="min-h-screen bg-gray-900 text-white p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold">AI Threat Detection</h1>
          <p className="text-sm text-gray-400">
            Real-time threat analysis and automated response
          </p>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
          <div className="text-4xl mb-4 text-gray-600">&#x2714;</div>
          <p className="text-lg font-medium text-gray-300">No threats detected</p>
          <p className="text-sm text-gray-500 mt-2">
            The system is monitoring for threats. This page auto-refreshes every 10 seconds.
          </p>
        </div>
      </div>
    );
  }

  const highCount = entries.filter((e) => severityFromAction(e) === "high").length;
  const mediumCount = entries.filter((e) => severityFromAction(e) === "medium").length;
  const lowCount = entries.filter((e) => severityFromAction(e) === "low").length;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">AI Threat Detection</h1>
        <p className="text-sm text-gray-400">
          Real-time threat analysis and automated response -- auto-refreshes every 10s
        </p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="text-xs text-gray-400 uppercase tracking-wider">Total Threats</div>
          <div className="text-2xl font-bold mt-1">{entries.length}</div>
        </div>
        <div className="bg-gray-800 border border-red-500/30 rounded-lg p-4">
          <div className="text-xs text-red-400 uppercase tracking-wider">High</div>
          <div className="text-2xl font-bold mt-1 text-red-400">{highCount}</div>
        </div>
        <div className="bg-gray-800 border border-yellow-500/30 rounded-lg p-4">
          <div className="text-xs text-yellow-400 uppercase tracking-wider">Medium</div>
          <div className="text-2xl font-bold mt-1 text-yellow-400">{mediumCount}</div>
        </div>
        <div className="bg-gray-800 border border-green-500/30 rounded-lg p-4">
          <div className="text-xs text-green-400 uppercase tracking-wider">Low</div>
          <div className="text-2xl font-bold mt-1 text-green-400">{lowCount}</div>
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Type</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Score</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Severity</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Action</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => {
                const severity = severityFromAction(entry);
                const score = extractScore(entry);
                const color = severityColor(severity);
                return (
                  <tr key={entry.id} className="border-b border-gray-700 hover:bg-gray-700/50 transition-colors">
                    <td className="py-2.5 px-3 text-gray-400 font-mono text-xs">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 text-xs font-medium text-gray-200">
                      {extractThreatType(entry)}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs text-gray-400">
                      {entry.source}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs text-gray-300">
                      {score !== null ? score.toFixed(2) : "--"}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded border font-medium uppercase tracking-wider"
                        style={{
                          color,
                          borderColor: `${color}40`,
                          backgroundColor: `${color}15`,
                        }}
                      >
                        {severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-300">
                      {entry.action}
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-400 max-w-xs truncate">
                      {entry.details}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="text-xs text-gray-500 text-center">
        Showing {entries.length} threat entries
      </div>
    </div>
  );
}
