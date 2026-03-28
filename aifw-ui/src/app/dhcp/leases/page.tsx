"use client";

import { useState, useEffect, useCallback, useRef } from "react";

/* -- Types ---------------------------------------------------------- */

interface DhcpLease {
  ip_address: string;
  mac_address: string;
  hostname?: string;
  state: string;
  starts?: string;
  expires?: string;
  subnet_id?: string;
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

function fmtDateTime(iso?: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function StateBadge({ state }: { state: string }) {
  const map: Record<string, string> = {
    active: "bg-green-500/20 text-green-400 border-green-500/30",
    free: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    expired: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    released: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    abandoned: "bg-red-500/20 text-red-400 border-red-500/30",
    backup: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  };
  const cls = map[state] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} capitalize`}>{state}</span>
  );
}

/* -- Page ------------------------------------------------------------ */

export default function DhcpLeasesPage() {
  const [leases, setLeases] = useState<DhcpLease[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [search, setSearch] = useState("");
  const [releaseIp, setReleaseIp] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchLeases = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/v4/leases", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setLeases(body.data || []);
    } catch {
      /* silent on auto-refresh failures */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchLeases();
      setLoading(false);
    })();

    // Auto-refresh every 5 seconds
    intervalRef.current = setInterval(fetchLeases, 5000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchLeases]);

  /* -- Actions ------------------------------------------------------ */

  const releaseLease = async (ip: string) => {
    try {
      const res = await fetch(`/api/v1/dhcp/v4/leases/${encodeURIComponent(ip)}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", `Lease for ${ip} released`);
      setReleaseIp(null);
      await fetchLeases();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to release lease");
    }
  };

  /* -- Filter ------------------------------------------------------- */

  const filtered = leases.filter((l) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      l.ip_address.toLowerCase().includes(q) ||
      l.mac_address.toLowerCase().includes(q) ||
      (l.hostname || "").toLowerCase().includes(q) ||
      l.state.toLowerCase().includes(q)
    );
  });

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading leases...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">DHCP Leases</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Active DHCP leases (auto-refreshes every 5 seconds)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--text-muted)]">
            {filtered.length} lease{filtered.length !== 1 ? "s" : ""}
          </span>
          <button
            onClick={fetchLeases}
            className="p-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded hover:bg-white/5"
            title="Refresh now"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* -- Search bar ---------------------------------------------- */}
      <div className="relative">
        <svg
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter by IP, MAC, hostname, or state..."
          className="w-full pl-10 pr-4 py-2.5 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* -- Table --------------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {filtered.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            {leases.length === 0
              ? "No active leases found."
              : "No leases match your search."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">IP Address</th>
                  <th className="px-6 py-3">MAC Address</th>
                  <th className="px-6 py-3">Hostname</th>
                  <th className="px-6 py-3">State</th>
                  <th className="px-6 py-3">Starts</th>
                  <th className="px-6 py-3">Expires</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((lease) => (
                  <tr
                    key={lease.ip_address}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02]"
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {lease.ip_address}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {lease.mac_address}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {lease.hostname || "-"}
                    </td>
                    <td className="px-6 py-3">
                      <StateBadge state={lease.state} />
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">
                      {fmtDateTime(lease.starts)}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">
                      {fmtDateTime(lease.expires)}
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex items-center justify-end">
                        <button
                          onClick={() => setReleaseIp(lease.ip_address)}
                          title="Release Lease"
                          className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* -- Release Confirm Modal ----------------------------------- */}
      {releaseIp && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Release Lease</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to release the lease for{" "}
              <span className="font-mono text-white">{releaseIp}</span>? The client will need to
              request a new address.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setReleaseIp(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => releaseLease(releaseIp)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
              >
                Release
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
