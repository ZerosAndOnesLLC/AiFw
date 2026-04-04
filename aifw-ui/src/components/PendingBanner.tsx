"use client";

import { useState, useEffect, useCallback, useRef } from "react";

interface PendingState {
  firewall: boolean;
  nat: boolean;
  dns: boolean;
}

export default function PendingBanner() {
  const [pending, setPending] = useState<PendingState>({ firewall: false, nat: false, dns: false });
  const [applying, setApplying] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  const hasPending = pending.firewall || pending.nat || pending.dns;

  // One-shot fetch for initial state or fallback
  const fetchPending = useCallback(async () => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    try {
      const res = await fetch("/api/v1/pending", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) setPending(await res.json());
    } catch { /* silent */ }
  }, []);

  // SSE connection
  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;

    const connect = () => {
      // EventSource doesn't support custom headers, so use query param for auth
      // The SSE endpoint will also accept the cookie/session if present.
      // For now, fall back to polling if EventSource fails.
      const es = new EventSource(`/api/v1/pending/stream?token=${encodeURIComponent(token)}`);
      esRef.current = es;

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as PendingState;
          setPending(data);
        } catch { /* ignore parse errors */ }
      };

      es.onerror = () => {
        es.close();
        esRef.current = null;
        // Reconnect after 5 seconds
        setTimeout(connect, 5000);
      };
    };

    // Fetch once immediately, then open SSE
    fetchPending();
    connect();

    return () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
    };
  }, [fetchPending]);

  const applyChanges = async () => {
    setApplying(true);
    setFeedback(null);
    const token = localStorage.getItem("aifw_token") || "";
    try {
      if (pending.firewall || pending.nat) {
        const res = await fetch("/api/v1/reload", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`Reload failed: HTTP ${res.status}`);
      }
      if (pending.dns) {
        const res = await fetch("/api/v1/dns/resolver/apply", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        });
        if (!res.ok) throw new Error(`DNS apply failed: HTTP ${res.status}`);
      }
      setPending({ firewall: false, nat: false, dns: false });
      setFeedback("Changes applied successfully");
      setTimeout(() => setFeedback(null), 3000);
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : "Apply failed");
      setTimeout(() => setFeedback(null), 5000);
    } finally {
      setApplying(false);
    }
  };

  if (!hasPending && !feedback) return null;

  const parts: string[] = [];
  if (pending.firewall) parts.push("Firewall Rules");
  if (pending.nat) parts.push("NAT");
  if (pending.dns) parts.push("DNS");

  return (
    <div className={`sticky top-0 z-10 px-4 py-2.5 flex items-center justify-between text-sm border-b ${
      feedback && !hasPending
        ? "bg-green-500/10 border-green-500/20 text-green-400"
        : "bg-yellow-500/10 border-yellow-500/20 text-yellow-300"
    }`}>
      <div className="flex items-center gap-2">
        {hasPending ? (
          <>
            <svg className="w-4 h-4 text-yellow-400 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <span>
              Unsaved changes: <strong>{parts.join(", ")}</strong>
            </span>
          </>
        ) : feedback ? (
          <>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            <span>{feedback}</span>
          </>
        ) : null}
      </div>
      {hasPending && (
        <button
          onClick={applyChanges}
          disabled={applying}
          className="px-4 py-1.5 bg-green-600 hover:bg-green-700 text-white text-xs font-medium rounded-md transition-colors disabled:opacity-50 flex items-center gap-1.5"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          {applying ? "Applying..." : "Apply Changes"}
        </button>
      )}
    </div>
  );
}
