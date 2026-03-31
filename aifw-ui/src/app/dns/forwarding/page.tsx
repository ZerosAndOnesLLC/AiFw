"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

/* -- Page ------------------------------------------------------------ */

export default function DnsForwardingPage() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  const [forwardingEnabled, setForwardingEnabled] = useState(false);
  const [useSystemNs, setUseSystemNs] = useState(false);
  const [servers, setServers] = useState<string[]>([]);
  const [newServer, setNewServer] = useState("");

  // DoT state
  const [dotEnabled, setDotEnabled] = useState(false);
  const [dotUpstream, setDotUpstream] = useState<string[]>([]);
  const [newDot, setNewDot] = useState("");

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/config", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const c = await res.json();
      setForwardingEnabled(c.forwarding_enabled ?? false);
      setUseSystemNs(c.use_system_nameservers ?? false);
      setServers(c.forwarding_servers ?? []);
      setDotEnabled(c.dot_enabled ?? false);
      setDotUpstream(c.dot_upstream ?? []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load config");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchConfig();
      setLoading(false);
    })();
  }, [fetchConfig]);

  /* -- Save --------------------------------------------------------- */

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/v1/dns/resolver/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          forwarding_enabled: forwardingEnabled,
          forwarding_servers: servers.filter(s => s.trim()),
          use_system_nameservers: useSystemNs,
          dot_enabled: dotEnabled,
          dot_upstream: dotUpstream.filter(s => s.trim()),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Forwarding configuration saved");
      // Apply config
      await fetch("/api/v1/dns/resolver/apply", { method: "POST", headers: authHeaders() });
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  /* -- Server list helpers ------------------------------------------ */

  const addServer = () => {
    const s = newServer.trim();
    if (!s || servers.includes(s)) return;
    setServers([...servers, s]);
    setNewServer("");
  };

  const removeServer = (idx: number) => {
    setServers(servers.filter((_, i) => i !== idx));
  };

  const addDotServer = () => {
    const s = newDot.trim();
    if (!s || dotUpstream.includes(s)) return;
    setDotUpstream([...dotUpstream, s]);
    setNewDot("");
  };

  const removeDotServer = (idx: number) => {
    setDotUpstream(dotUpstream.filter((_, i) => i !== idx));
  };

  /* -- Render ------------------------------------------------------- */

  const inputClass = "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]";
  const btnPrimary = "px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50";
  const btnDanger = "px-2 py-1 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors";

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Query Forwarding</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Forward DNS queries to upstream resolvers instead of resolving recursively
          </p>
        </div>
        <button onClick={handleSave} disabled={saving} className={btnPrimary}>
          {saving ? "Saving..." : "Save & Apply"}
        </button>
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

      {/* DNS Forwarding */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-5">
        <h2 className="text-lg font-semibold">DNS Forwarding</h2>
        <p className="text-xs text-[var(--text-muted)]">
          When enabled, Unbound forwards all queries to the configured upstream DNS servers
          instead of performing recursive resolution itself. This is useful when you need to
          use specific DNS servers (e.g. ISP, corporate, or filtering DNS).
        </p>

        <label className="flex items-center gap-3 cursor-pointer">
          <input type="checkbox" checked={forwardingEnabled} onChange={e => setForwardingEnabled(e.target.checked)}
            className="w-4 h-4 rounded accent-[var(--accent)]" />
          <span className="text-sm">Enable DNS Query Forwarding</span>
        </label>

        {forwardingEnabled && (
          <>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={useSystemNs} onChange={e => setUseSystemNs(e.target.checked)}
                className="w-4 h-4 rounded accent-[var(--accent)]" />
              <div>
                <span className="text-sm">Use System Nameservers</span>
                <p className="text-xs text-[var(--text-muted)]">
                  Also forward queries to nameservers from /etc/resolv.conf (excludes 127.0.0.1)
                </p>
              </div>
            </label>

            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-2">
                Upstream DNS Servers
              </label>

              {servers.length > 0 && (
                <div className="space-y-1 mb-3">
                  {servers.map((s, i) => (
                    <div key={i} className="flex items-center gap-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2">
                      <span className="flex-1 text-sm font-mono">{s}</span>
                      <button onClick={() => removeServer(i)} className={btnDanger}>Remove</button>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex gap-2">
                <input
                  type="text"
                  value={newServer}
                  onChange={e => setNewServer(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && (e.preventDefault(), addServer())}
                  placeholder="e.g. 8.8.8.8 or 1.1.1.1"
                  className={inputClass}
                />
                <button onClick={addServer} className={btnPrimary}>Add</button>
              </div>

              {servers.length === 0 && !useSystemNs && (
                <p className="text-xs text-yellow-400 mt-2">
                  Add at least one upstream server or enable system nameservers
                </p>
              )}
            </div>
          </>
        )}
      </div>

      {/* DNS over TLS */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-5">
        <h2 className="text-lg font-semibold">DNS over TLS (DoT)</h2>
        <p className="text-xs text-[var(--text-muted)]">
          When enabled, all forwarded queries use TLS encryption (port 853). This overrides
          plain DNS forwarding above. Queries are encrypted end-to-end to the upstream resolver.
        </p>

        <label className="flex items-center gap-3 cursor-pointer">
          <input type="checkbox" checked={dotEnabled} onChange={e => setDotEnabled(e.target.checked)}
            className="w-4 h-4 rounded accent-[var(--accent)]" />
          <span className="text-sm">Enable DNS over TLS</span>
        </label>

        {dotEnabled && (
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-2">
              DoT Upstream Servers
            </label>
            <p className="text-xs text-[var(--text-muted)] mb-3">
              Format: <code className="bg-[var(--bg-primary)] px-1 rounded">IP@PORT#HOSTNAME</code> (e.g. 1.1.1.1@853#cloudflare-dns.com)
            </p>

            {dotUpstream.length > 0 && (
              <div className="space-y-1 mb-3">
                {dotUpstream.map((s, i) => (
                  <div key={i} className="flex items-center gap-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2">
                    <span className="flex-1 text-sm font-mono">{s}</span>
                    <button onClick={() => removeDotServer(i)} className={btnDanger}>Remove</button>
                  </div>
                ))}
              </div>
            )}

            <div className="flex gap-2">
              <input
                type="text"
                value={newDot}
                onChange={e => setNewDot(e.target.value)}
                onKeyDown={e => e.key === "Enter" && (e.preventDefault(), addDotServer())}
                placeholder="e.g. 1.1.1.1@853#cloudflare-dns.com"
                className={inputClass}
              />
              <button onClick={addDotServer} className={btnPrimary}>Add</button>
            </div>
          </div>
        )}

        {dotEnabled && forwardingEnabled && (
          <div className="p-3 text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 rounded-md">
            DNS over TLS takes priority over plain forwarding when both are enabled.
          </div>
        )}
      </div>
    </div>
  );
}
