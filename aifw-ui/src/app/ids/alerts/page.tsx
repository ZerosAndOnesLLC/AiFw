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

interface IdsAlert {
  id: string;
  timestamp: string;
  severity: number;
  signature_id: number;
  signature_msg: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  action: string;
  acknowledged: boolean;
  payload_excerpt?: string;
  metadata?: Record<string, string>;
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

const severityStyles: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const severityLabel: Record<number, string> = { 1: "critical", 2: "high", 3: "medium", 4: "info" };

function SeverityBadge({ severity }: { severity: number }) {
  const label = severityLabel[severity] || "info";
  const style = severityStyles[label] || severityStyles.info;
  return (
    <span
      className={`inline-flex items-center rounded border font-medium uppercase tracking-wider text-[10px] px-1.5 py-0.5 ${style}`}
    >
      {label}
    </span>
  );
}

export default function IdsAlertsPage() {
  const [alerts, setAlerts] = useState<IdsAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);
  const [total, setTotal] = useState(0);

  // Filters
  const [severityFilter, setSeverityFilter] = useState("");
  const [srcIpFilter, setSrcIpFilter] = useState("");
  const [ackFilter, setAckFilter] = useState<"" | "true" | "false">("");

  // Pagination
  const [page, setPage] = useState(0);
  const limit = 25;

  // Expanded row
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Acknowledging
  const [ackingId, setAckingId] = useState<string | null>(null);

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchAlerts = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      params.set("limit", String(limit));
      params.set("offset", String(page * limit));
      if (severityFilter) params.set("severity", severityFilter);
      if (srcIpFilter.trim()) params.set("src_ip", srcIpFilter.trim());
      if (ackFilter) params.set("acknowledged", ackFilter);

      const res = await fetch(`${API}/api/v1/ids/alerts?${params.toString()}`, {
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`Failed to fetch alerts: ${res.status}`);
      const json = await res.json();
      const d = json.data || json;
      setAlerts(d.alerts || d || []);
      setTotal(d.total ?? (d.alerts || d || []).length);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load alerts";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [page, severityFilter, srcIpFilter, ackFilter, clearFeedback]);

  useEffect(() => {
    setLoading(true);
    fetchAlerts();
  }, [fetchAlerts]);

  async function handleAcknowledge(id: string) {
    setAckingId(id);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/alerts/${id}/acknowledge`, {
        method: "PUT",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Acknowledge failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: "Alert acknowledged" });
      clearFeedback();
      await fetchAlerts();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to acknowledge alert";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setAckingId(null);
    }
  }

  function handleFilterApply() {
    setPage(0);
  }

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">IDS Alerts</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Detected threats and signature matches
        </p>
      </div>

      <FeedbackBanner feedback={feedback} />

      {/* Filters */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Severity</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            >
              <option value="">All</option>
              <option value="1">Critical</option>
              <option value="2">High</option>
              <option value="3">Medium</option>
              <option value="4">Info</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Source IP</label>
            <input
              type="text"
              value={srcIpFilter}
              onChange={(e) => setSrcIpFilter(e.target.value)}
              placeholder="e.g. 192.168.1.100"
              className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors w-44"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Acknowledged</label>
            <select
              value={ackFilter}
              onChange={(e) => setAckFilter(e.target.value as "" | "true" | "false")}
              className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            >
              <option value="">All</option>
              <option value="false">Unacknowledged</option>
              <option value="true">Acknowledged</option>
            </select>
          </div>
          <button
            onClick={handleFilterApply}
            className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-sm font-medium rounded-md transition-colors"
          >
            Filter
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-sm font-medium">Alerts</h3>
          <span className="text-xs text-[var(--text-muted)]">
            {total.toLocaleString()} total &middot; page {page + 1} of {Math.max(totalPages, 1)}
          </span>
        </div>

        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
            Loading alerts...
          </div>
        ) : alerts.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
            No alerts matching current filters
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Time
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Severity
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Signature
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Source
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Destination
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Proto
                  </th>
                  <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Action
                  </th>
                  <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                    Ack
                  </th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <AlertRow
                    key={alert.id}
                    alert={alert}
                    expanded={expandedId === alert.id}
                    onToggle={() =>
                      setExpandedId(expandedId === alert.id ? null : alert.id)
                    }
                    onAcknowledge={() => handleAcknowledge(alert.id)}
                    acking={ackingId === alert.id}
                  />
                ))}
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

function AlertRow({
  alert,
  expanded,
  onToggle,
  onAcknowledge,
  acking,
}: {
  alert: IdsAlert;
  expanded: boolean;
  onToggle: () => void;
  onAcknowledge: () => void;
  acking: boolean;
}) {
  const actionStyle =
    alert.action === "drop" || alert.action === "reject"
      ? "text-red-400"
      : alert.action === "pass"
      ? "text-green-400"
      : "text-yellow-400";

  return (
    <>
      <tr
        className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
        onClick={onToggle}
      >
        <td className="py-2.5 px-3 text-xs font-mono text-[var(--text-muted)] whitespace-nowrap">
          {new Date(alert.timestamp).toLocaleString()}
        </td>
        <td className="py-2.5 px-3">
          <SeverityBadge severity={alert.severity} />
        </td>
        <td className="py-2.5 px-3 text-xs text-[var(--text-primary)] max-w-[250px] truncate">
          <span className="text-[var(--text-muted)] font-mono mr-1.5">
            [{alert.signature_id}]
          </span>
          {alert.signature_msg}
        </td>
        <td className="py-2.5 px-3 text-xs font-mono text-[var(--text-secondary)]">
          {alert.src_ip}:{alert.src_port}
        </td>
        <td className="py-2.5 px-3 text-xs font-mono text-[var(--text-secondary)]">
          {alert.dst_ip}:{alert.dst_port}
        </td>
        <td className="py-2.5 px-3 text-xs uppercase text-cyan-400">
          {alert.protocol}
        </td>
        <td className={`py-2.5 px-3 text-xs font-medium ${actionStyle}`}>
          {alert.action}
        </td>
        <td className="py-2.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
          {alert.acknowledged ? (
            <span className="text-[10px] text-green-400 px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/20">
              ACK
            </span>
          ) : (
            <button
              onClick={onAcknowledge}
              disabled={acking}
              className="text-[10px] px-2 py-0.5 rounded bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] disabled:opacity-40 transition-colors"
            >
              {acking ? "..." : "Ack"}
            </button>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-[var(--border)]">
          <td colSpan={8} className="px-4 py-3 bg-[var(--bg-primary)]">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs mb-3">
              <div>
                <span className="text-[var(--text-muted)]">Alert ID</span>
                <p className="font-mono mt-0.5">{alert.id}</p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Signature ID</span>
                <p className="font-mono mt-0.5">{alert.signature_id}</p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Protocol</span>
                <p className="font-mono mt-0.5 uppercase">{alert.protocol}</p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Action Taken</span>
                <p className={`font-mono mt-0.5 ${actionStyle}`}>{alert.action}</p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Source</span>
                <p className="font-mono mt-0.5">
                  {alert.src_ip}:{alert.src_port}
                </p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Destination</span>
                <p className="font-mono mt-0.5">
                  {alert.dst_ip}:{alert.dst_port}
                </p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Timestamp</span>
                <p className="font-mono mt-0.5">
                  {new Date(alert.timestamp).toISOString()}
                </p>
              </div>
              <div>
                <span className="text-[var(--text-muted)]">Acknowledged</span>
                <p className="mt-0.5">{alert.acknowledged ? "Yes" : "No"}</p>
              </div>
            </div>
            {alert.metadata && Object.keys(alert.metadata).length > 0 && (
              <div className="mb-3">
                <span className="text-xs text-[var(--text-muted)]">Metadata</span>
                <div className="mt-1 flex flex-wrap gap-2">
                  {Object.entries(alert.metadata).map(([k, v]) => (
                    <span
                      key={k}
                      className="text-[10px] px-2 py-0.5 rounded bg-[var(--bg-card)] border border-[var(--border)] font-mono"
                    >
                      {k}={v}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {alert.payload_excerpt && (
              <div>
                <span className="text-xs text-[var(--text-muted)]">
                  Payload Excerpt
                </span>
                <pre className="mt-1 text-[11px] font-mono bg-[var(--bg-card)] border border-[var(--border)] rounded-md p-3 overflow-x-auto text-[var(--text-secondary)] whitespace-pre-wrap break-all">
                  {alert.payload_excerpt}
                </pre>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
