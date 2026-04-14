"use client";

import { useState, useEffect, useCallback } from "react";
import Help, { HelpBanner } from "../Help";
import { api, FlowSummary } from "../lib";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(1)} GB`;
}

function formatAge(s: number): string {
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export default function FlowsPage() {
  const [flows, setFlows] = useState<FlowSummary[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liveRefresh, setLiveRefresh] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const r = await api<{ data: FlowSummary[] }>("GET", "/api/v1/multiwan/flows");
      setFlows(r.data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    if (!liveRefresh) return;
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [refresh, liveRefresh]);

  async function migrateLabel(label: string) {
    if (!confirm(`Kill pf states with label "${label}"? Clients will reconnect.`))
      return;
    try {
      await api("POST", `/api/v1/multiwan/flows/${encodeURIComponent(label)}/migrate`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "migrate failed");
    }
  }

  const visible = flows.filter((f) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      f.src.toLowerCase().includes(q) ||
      f.dst.toLowerCase().includes(q) ||
      f.protocol.toLowerCase().includes(q) ||
      (f.iface || "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Live Flows
            <Help title="Live flows" size="md">
              <p>
                Real-time dump of the pf state table. One row per active flow.
                Refreshes every 3 seconds when auto-refresh is on.
              </p>
              <p>
                <b>Iface</b> = which interface the flow is bound to (its{" "}
                <code>(if-bound)</code> state).
              </p>
              <p>
                <b>FIB</b> = which routing table the flow is using. Useful to
                confirm your policies are steering traffic correctly.
              </p>
              <p>
                <b>Bytes</b> is in + out combined. <b>Age</b> is time since the
                state entry was created.
              </p>
            </Help>
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Live pf state table with interface + FIB. Force-migrate kills states by label to force reroute.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-white">
          <input
            type="checkbox"
            checked={liveRefresh}
            onChange={(e) => setLiveRefresh(e.target.checked)}
          />
          Auto-refresh (3s)
        </label>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      <input
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter src/dst/proto/iface…"
        className="w-full px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
      />

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : visible.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">
            No flows match.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Proto</th>
                <th className="text-left px-4 py-2">Source</th>
                <th className="text-left px-4 py-2">Destination</th>
                <th className="text-left px-4 py-2">Iface</th>
                <th className="text-right px-4 py-2">FIB</th>
                <th className="text-right px-4 py-2">Bytes</th>
                <th className="text-right px-4 py-2">Age</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <tr key={f.id} className="border-t border-[var(--border)]">
                  <td className="px-4 py-3 font-mono text-cyan-400">{f.protocol}</td>
                  <td className="px-4 py-3 font-mono text-xs">{f.src}</td>
                  <td className="px-4 py-3 font-mono text-xs">{f.dst}</td>
                  <td className="px-4 py-3 text-[var(--text-muted)]">
                    {f.iface || "—"}
                  </td>
                  <td className="px-4 py-3 text-right font-mono">
                    {f.rtable ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)]">
                    {formatBytes(f.bytes)}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-muted)]">
                    {formatAge(f.age_secs)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h2 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          Force-migrate by label
          <Help title="Force-migrate">
            <p>
              Every multi-WAN pf rule is labeled <code>pbr:&lt;policy-uuid&gt;</code>{" "}
              or <code>leak:&lt;leak-uuid&gt;</code>. This kills every pf state
              whose rule matched that label.
            </p>
            <p>
              Use it when you&apos;ve changed a policy and want existing long-lived
              flows (SSH, videoconference) to re-evaluate routing instead of
              waiting for TCP timeout.
            </p>
            <p className="text-red-400">
              This drops the flow. Clients must reconnect. Don&apos;t use on
              your own admin session unless you know what you&apos;re doing.
            </p>
          </Help>
        </h2>
        <p className="text-xs text-[var(--text-muted)] mb-2">
          Enter a policy label (e.g. <code>pbr:&lt;uuid&gt;</code>) to kill all matching states.
          Clients reconnect via the current active route.
        </p>
        <MigrateByLabel onMigrate={migrateLabel} />
      </div>
    </div>
  );
}

function MigrateByLabel({ onMigrate }: { onMigrate: (label: string) => Promise<void> }) {
  const [label, setLabel] = useState("");
  return (
    <div className="flex gap-2">
      <input
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        placeholder="pbr:<uuid>"
        className="flex-1 px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm font-mono"
      />
      <button
        onClick={() => label && onMigrate(label)}
        disabled={!label}
        className="px-3 py-2 rounded bg-yellow-600 hover:bg-yellow-700 text-white text-sm disabled:opacity-50"
      >
        Migrate
      </button>
    </div>
  );
}
