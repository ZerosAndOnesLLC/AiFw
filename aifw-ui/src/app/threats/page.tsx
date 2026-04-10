"use client";

import { useState, useEffect, useCallback } from "react";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

interface IdsAlert {
  id: string;
  timestamp: string;
  signature_id: number | null;
  signature_msg: string;
  severity: number;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string;
  action: string;
  rule_source: string;
  payload_excerpt?: string;
  metadata?: Record<string, string>;
  acknowledged: boolean;
  classification: string;
  analyst_notes?: string;
}

const SEV_META: Record<number, { label: string; color: string; bg: string; border: string; desc: string }> = {
  1: { label: "Critical", color: "text-red-400", bg: "bg-red-500/15", border: "border-red-500/30", desc: "Immediate threat requiring action" },
  2: { label: "High", color: "text-orange-400", bg: "bg-orange-500/15", border: "border-orange-500/30", desc: "Significant threat — investigate promptly" },
  3: { label: "Medium", color: "text-yellow-400", bg: "bg-yellow-500/15", border: "border-yellow-500/30", desc: "Suspicious activity — review when possible" },
  4: { label: "Info", color: "text-blue-400", bg: "bg-blue-500/15", border: "border-blue-500/30", desc: "Informational — policy match or low confidence" },
};

const CLASS_META: Record<string, { label: string; icon: string; color: string; bg: string; border: string }> = {
  unreviewed: { label: "Unreviewed", icon: "?", color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30" },
  confirmed: { label: "Confirmed Threat", icon: "!", color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
  false_positive: { label: "False Positive", icon: "x", color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30" },
  investigating: { label: "Investigating", icon: "~", color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
};

function formatTime(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function formatRelative(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60000) return "just now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch { return iso; }
}

// Explain what this signature likely means in plain English
function explainSignature(msg: string, action: string, protocol: string): string {
  const m = msg.toLowerCase();
  if (m.includes("trojan")) return "A rule matched traffic patterns associated with trojan malware. This could indicate a compromised host communicating with a command and control server.";
  if (m.includes("malware")) return "Traffic matched a known malware signature. The source or destination host may be infected.";
  if (m.includes("exploit")) return "An exploit attempt was detected. An attacker may be trying to take advantage of a known vulnerability.";
  if (m.includes("scan") || m.includes("recon")) return "Reconnaissance or port scanning activity detected. Someone is probing your network to map services.";
  if (m.includes("dos") || m.includes("ddos")) return "Denial of service patterns detected. This could be an attempt to overwhelm your network or a specific service.";
  if (m.includes("brute") || m.includes("credential")) return "Brute force or credential stuffing attempt detected. Someone is trying to guess passwords.";
  if (m.includes("dns") && (m.includes("tunnel") || m.includes("exfil"))) return "DNS tunneling or data exfiltration attempt. Data may be being smuggled out through DNS queries.";
  if (m.includes("c2") || m.includes("command and control") || m.includes("beacon")) return "Command and control beacon detected. A compromised host may be checking in with an attacker.";
  if (m.includes("policy") || m.includes("info")) return "This is a policy-based or informational alert. It matched a rule that flags specific traffic patterns for visibility.";
  if (m.includes("shellcode")) return "Shellcode detected in network traffic. This often indicates an active exploitation attempt.";
  if (m.includes("overflow")) return "Buffer overflow attempt detected. An attacker may be trying to execute arbitrary code by overflowing a memory buffer.";
  if (m.includes("sql") && m.includes("inject")) return "SQL injection attempt detected in network traffic targeting a web application or database.";
  if (m.includes("xss") || m.includes("cross-site")) return "Cross-site scripting (XSS) attempt detected targeting a web application.";
  return `The IDS engine matched this ${protocol.toUpperCase()} traffic against a ${action === "drop" ? "blocking" : "detection"} rule. Review the signature details and source/destination to determine if this is legitimate or malicious.`;
}

export default function ThreatsPage() {
  const [alerts, setAlerts] = useState<IdsAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [classFilter, setClassFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [noteText, setNoteText] = useState("");
  const [classifying, setClassifying] = useState<string | null>(null);
  const [aiRunning, setAiRunning] = useState(false);
  const [aiLog, setAiLog] = useState<{ id: string; signature_msg: string; provider: string; model: string; response: string; classification: string | null; duration_ms: number | null; created_at: string }[]>([]);
  const [showAiLog, setShowAiLog] = useState(false);

  const fetchAlerts = useCallback(async () => {
    try {
      // Fetch latest alerts + AI-reviewed alerts (may overlap, deduplicate by id)
      const [latestRes, reviewedRes] = await Promise.all([
        fetch(`${API}/api/v1/ids/alerts?limit=200`, { headers: authHeaders() }),
        fetch(`${API}/api/v1/ids/alerts?limit=300&classification=reviewed`, { headers: authHeaders() }),
      ]);
      const latest = latestRes.ok ? (await latestRes.json()).data || [] : [];
      const reviewed = reviewedRes.ok ? (await reviewedRes.json()).data || [] : [];
      // Merge and deduplicate
      const byId = new Map<string, IdsAlert>();
      for (const a of [...reviewed, ...latest]) byId.set(a.id, a);
      const merged = [...byId.values()].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      setAlerts(merged);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 15_000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const runAiAnalysis = async () => {
    setAiRunning(true);
    try {
      const res = await fetch(`${API}/api/v1/ai/analyze`, { method: "POST", headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        if (data.classified > 0) await fetchAlerts();
      }
    } catch { /* ignore */ }
    finally { setAiRunning(false); }
  };

  const fetchAiLog = async () => {
    try {
      const res = await fetch(`${API}/api/v1/ai/audit-log?limit=30`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setAiLog(data.entries || []);
      }
    } catch { /* ignore */ }
  };

  const handleClassify = async (id: string, classification: string) => {
    setClassifying(id);
    try {
      await fetch(`${API}/api/v1/ids/alerts/${id}/classify`, {
        method: "PUT", headers: authHeaders(),
        body: JSON.stringify({ classification, notes: noteText || null }),
      });
      setNoteText("");
      await fetchAlerts();
    } catch { /* ignore */ }
    finally { setClassifying(null); }
  };

  const toggleExpand = (id: string) => {
    if (expandedId === id) {
      setExpandedId(null);
      setNoteText("");
    } else {
      setExpandedId(id);
      const alert = alerts.find(a => a.id === id);
      setNoteText(alert?.analyst_notes || "");
    }
  };

  // Apply filters
  const filtered = alerts.filter(a => {
    if (filter !== "all" && SEV_META[a.severity]?.label.toLowerCase() !== filter) return false;
    if (classFilter !== "all" && a.classification !== classFilter) return false;
    return true;
  });

  const counts = {
    total: alerts.length,
    critical: alerts.filter(a => a.severity === 1).length,
    high: alerts.filter(a => a.severity === 2).length,
    medium: alerts.filter(a => a.severity === 3).length,
    info: alerts.filter(a => a.severity >= 4).length,
    unreviewed: alerts.filter(a => a.classification === "unreviewed").length,
    confirmed: alerts.filter(a => a.classification === "confirmed").length,
    false_positive: alerts.filter(a => a.classification === "false_positive").length,
    investigating: alerts.filter(a => a.classification === "investigating").length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-[var(--text-muted)]">Loading threat data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Threat Investigation</h1>
          <p className="text-sm text-[var(--text-muted)]">
            IDS/IPS alerts — review, classify, and track findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={runAiAnalysis}
            disabled={aiRunning}
            className="px-4 py-2 text-xs font-medium rounded-md bg-purple-600 hover:bg-purple-500 text-white transition-colors disabled:opacity-50 flex items-center gap-1.5"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg>
            {aiRunning ? "Analyzing..." : "AI Analyze"}
          </button>
          <button
            onClick={() => { setShowAiLog(!showAiLog); if (!showAiLog) fetchAiLog(); }}
            className={`px-3 py-2 text-xs font-medium rounded-md border transition-colors ${
              showAiLog ? "border-purple-500/30 text-purple-400 bg-purple-500/10" : "border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            AI Log
          </button>
        </div>
      </div>

      {/* WIP Banner */}
      <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-lg px-4 py-3">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-yellow-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          <p className="text-xs text-[var(--text-muted)]">
            <span className="text-yellow-400 font-medium">AI-assisted analysis coming soon.</span> Currently showing IDS/IPS rule-based detections. AI detectors for behavioral analysis are in development.
          </p>
        </div>
      </div>

      {/* AI Audit Log */}
      {showAiLog && (
        <div className="bg-[var(--bg-card)] border border-purple-500/20 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" /></svg>
              AI Analysis Log
            </h3>
            <span className="text-[10px] text-[var(--text-muted)]">{aiLog.length} entries</span>
          </div>
          {aiLog.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
              No AI analysis has been run yet. Click &quot;AI Analyze&quot; to review unclassified critical/high alerts.
            </div>
          ) : (
            <div className="divide-y divide-[var(--border)] max-h-96 overflow-y-auto">
              {aiLog.map(entry => (
                <div key={entry.id} className="px-4 py-3">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium">{entry.signature_msg}</span>
                      {entry.classification && (
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${
                          entry.classification === "false_positive" ? "text-green-400 bg-green-500/10 border-green-500/30"
                          : entry.classification === "confirmed" ? "text-red-400 bg-red-500/10 border-red-500/30"
                          : "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                        }`}>{entry.classification}</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 text-[10px] text-[var(--text-muted)]">
                      <span>{entry.provider}/{entry.model}</span>
                      {entry.duration_ms && <span>{entry.duration_ms}ms</span>}
                      <span>{new Date(entry.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] bg-[var(--bg-primary)] rounded px-2 py-1.5 whitespace-pre-wrap">
                    {entry.response}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error} <button onClick={() => { setLoading(true); fetchAlerts(); }} className="ml-3 underline text-xs">Retry</button>
        </div>
      )}

      {/* Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-center">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Total</div>
          <div className="text-xl font-bold mt-1">{counts.total}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-red-500/20 rounded-lg p-3 text-center">
          <div className="text-[10px] text-red-400 uppercase tracking-wider">Critical / High</div>
          <div className="text-xl font-bold mt-1 text-red-400">{counts.critical + counts.high}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-gray-500/20 rounded-lg p-3 text-center">
          <div className="text-[10px] text-gray-400 uppercase tracking-wider">Unreviewed</div>
          <div className="text-xl font-bold mt-1 text-gray-400">{counts.unreviewed}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-red-500/20 rounded-lg p-3 text-center">
          <div className="text-[10px] text-red-400 uppercase tracking-wider">Confirmed</div>
          <div className="text-xl font-bold mt-1 text-red-400">{counts.confirmed}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-green-500/20 rounded-lg p-3 text-center">
          <div className="text-[10px] text-green-400 uppercase tracking-wider">False Positives</div>
          <div className="text-xl font-bold mt-1 text-green-400">{counts.false_positive}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div>
          <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mr-2">Severity</span>
          <div className="inline-flex gap-1 bg-[var(--bg-card)] rounded-lg p-1 border border-[var(--border)]">
            {["all", "critical", "high", "medium", "info"].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-3 py-1 text-[11px] font-medium rounded-md transition-all capitalize ${
                  filter === f ? "bg-[var(--accent)] text-white" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}>{f}</button>
            ))}
          </div>
        </div>
        <div>
          <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mr-2">Status</span>
          <div className="inline-flex gap-1 bg-[var(--bg-card)] rounded-lg p-1 border border-[var(--border)]">
            {["all", "unreviewed", "confirmed", "false_positive", "investigating"].map(f => (
              <button key={f} onClick={() => setClassFilter(f)}
                className={`px-3 py-1 text-[11px] font-medium rounded-md transition-all ${
                  classFilter === f ? "bg-[var(--accent)] text-white" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}>{CLASS_META[f]?.label || "All"}</button>
            ))}
          </div>
        </div>
      </div>

      {/* Alerts */}
      {filtered.length === 0 ? (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-12 text-center">
          <div className="text-4xl mb-4 text-green-500">&#x2714;</div>
          <p className="text-lg font-medium">No {filter !== "all" || classFilter !== "all" ? "matching " : ""}threats detected</p>
          <p className="text-sm text-[var(--text-muted)] mt-2">
            {alerts.length === 0
              ? "Enable IDS/IPS and configure rulesets (Intrusion Detection > Rulesets) to start detecting threats."
              : "No alerts match the current filters. Try adjusting severity or status."}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(alert => {
            const sev = SEV_META[alert.severity] || SEV_META[4];
            const cls = CLASS_META[alert.classification] || CLASS_META.unreviewed;
            const isExpanded = expandedId === alert.id;

            return (
              <div key={alert.id} className={`bg-[var(--bg-card)] border rounded-lg overflow-hidden transition-all ${
                alert.classification === "confirmed" ? "border-red-500/30" :
                alert.classification === "false_positive" ? "border-green-500/20 opacity-60" :
                alert.classification === "investigating" ? "border-yellow-500/30" :
                "border-[var(--border)]"
              }`}>
                {/* Alert row — always visible */}
                <button onClick={() => toggleExpand(alert.id)} className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-[var(--bg-card-hover)] transition-colors">
                  {/* Severity dot */}
                  <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${sev.bg.replace('/15', '')} ${
                    alert.severity === 1 ? "bg-red-500" : alert.severity === 2 ? "bg-orange-500" : alert.severity === 3 ? "bg-yellow-500" : "bg-blue-500"
                  }`} />

                  {/* Main content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium truncate">{alert.signature_msg}</span>
                      {alert.signature_id && <span className="text-[10px] font-mono text-[var(--text-muted)]">SID:{alert.signature_id}</span>}
                    </div>
                    <div className="flex items-center gap-3 mt-0.5 text-[11px] text-[var(--text-muted)]">
                      <span className="font-mono">{alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ""}</span>
                      <span>&#8594;</span>
                      <span className="font-mono">{alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ""}</span>
                      <span className="uppercase text-cyan-400">{alert.protocol}</span>
                      <span>{formatRelative(alert.timestamp)}</span>
                    </div>
                  </div>

                  {/* Status badges */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium uppercase tracking-wider ${sev.color} ${sev.bg} ${sev.border}`}>
                      {sev.label}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${cls.color} ${cls.bg} ${cls.border}`}>
                      {cls.label}
                    </span>
                    {alert.action === "drop" || alert.action === "reject" ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded border font-medium text-red-400 bg-red-500/10 border-red-500/30">BLOCKED</span>
                    ) : null}
                  </div>

                  {/* Expand chevron */}
                  <svg className={`w-4 h-4 text-[var(--text-muted)] flex-shrink-0 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-[var(--border)] px-4 py-4 space-y-4">
                    {/* What does this mean? */}
                    <div className="bg-[var(--bg-primary)] rounded-lg p-4">
                      <h4 className="text-xs font-medium text-[var(--text-primary)] mb-1.5">What does this mean?</h4>
                      <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                        {explainSignature(alert.signature_msg, alert.action, alert.protocol)}
                      </p>
                    </div>

                    {/* Details grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2 text-xs">
                        <h4 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider">Connection Details</h4>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Source</span><span className="font-mono">{alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ""}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Destination</span><span className="font-mono">{alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ""}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Protocol</span><span className="uppercase">{alert.protocol}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Action Taken</span><span className={alert.action === "drop" || alert.action === "reject" ? "text-red-400 font-medium" : "text-yellow-400"}>{alert.action}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Timestamp</span><span>{formatTime(alert.timestamp)}</span></div>
                      </div>
                      <div className="space-y-2 text-xs">
                        <h4 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider">Rule Details</h4>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Signature</span><span className="text-right max-w-[200px] truncate">{alert.signature_msg}</span></div>
                        {alert.signature_id && <div className="flex justify-between"><span className="text-[var(--text-muted)]">SID</span><span className="font-mono">{alert.signature_id}</span></div>}
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Rule Source</span><span>{alert.rule_source}</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Severity</span><span className={sev.color}>{sev.label} — {sev.desc}</span></div>
                      </div>
                    </div>

                    {/* Payload excerpt */}
                    {alert.payload_excerpt && (
                      <div>
                        <h4 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-1">Payload Excerpt</h4>
                        <pre className="text-[11px] font-mono bg-[var(--bg-primary)] rounded-md p-3 overflow-x-auto text-[var(--text-secondary)] whitespace-pre-wrap break-all">
                          {alert.payload_excerpt}
                        </pre>
                      </div>
                    )}

                    {/* Classification + Notes */}
                    <div className="border-t border-[var(--border)] pt-4">
                      <h4 className="text-xs font-medium mb-3">Classify This Alert</h4>

                      <div className="flex flex-wrap gap-2 mb-3">
                        {(["confirmed", "false_positive", "investigating", "unreviewed"] as const).map(c => {
                          const meta = CLASS_META[c];
                          const isActive = alert.classification === c;
                          return (
                            <button key={c} onClick={() => handleClassify(alert.id, c)}
                              disabled={classifying === alert.id}
                              className={`px-3 py-2 rounded-md text-xs font-medium border transition-all disabled:opacity-50 ${
                                isActive
                                  ? `${meta.bg} ${meta.color} ${meta.border} ring-1 ring-current`
                                  : `bg-[var(--bg-primary)] border-[var(--border)] text-[var(--text-secondary)] hover:${meta.border} hover:${meta.color}`
                              }`}>
                              {meta.label}
                            </button>
                          );
                        })}
                      </div>

                      <div>
                        <label className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider block mb-1">Analyst Notes</label>
                        <div className="flex gap-2">
                          <textarea
                            value={noteText}
                            onChange={e => setNoteText(e.target.value)}
                            placeholder="Add notes about your investigation, findings, or why this is a false positive..."
                            rows={2}
                            className="flex-1 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] resize-none"
                          />
                          <button
                            onClick={() => handleClassify(alert.id, alert.classification || "investigating")}
                            disabled={classifying === alert.id || !noteText.trim()}
                            className="px-3 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-xs font-medium transition-colors disabled:opacity-50 self-end"
                          >
                            Save Note
                          </button>
                        </div>
                        {alert.analyst_notes && noteText !== alert.analyst_notes && (
                          <div className="mt-2 p-2 bg-[var(--bg-primary)] rounded-md">
                            <span className="text-[10px] text-[var(--text-muted)]">Previous note: </span>
                            <span className="text-xs text-[var(--text-secondary)]">{alert.analyst_notes}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className="text-xs text-[var(--text-muted)] text-center">
        Showing {filtered.length} of {alerts.length} alerts — auto-refreshes every 15s
      </div>
    </div>
  );
}
