"use client";

import type { DiffSummary } from "@/lib/api/backup";

/* ===================== Diff viewer ===================== */

export function DiffViewer({
  diff,
  diffLoading,
  diffV1,
  diffV2,
  diffSection,
  setDiffSection,
  onClose,
}: {
  diff: DiffSummary;
  diffLoading: boolean;
  diffV1: number | null;
  diffV2: number | null;
  diffSection: string;
  setDiffSection: (s: string) => void;
  onClose: () => void;
}) {
  return (
    <div className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-lg p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">
          Comparing v{diffV1} → v{diffV2}
          {diff.identical && <span className="ml-2 text-xs text-green-400">(identical)</span>}
        </h3>
        <button onClick={onClose} className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]">Close</button>
      </div>

      {diffLoading ? (
        <div className="flex justify-center py-6">
          <div className="w-5 h-5 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
            <div className="bg-[var(--bg-card)] rounded p-3">
              <div className="text-xs text-[var(--text-muted)]">Rules</div>
              <div className="font-semibold">{diff.rules_diff.v1_count} → {diff.rules_diff.v2_count}</div>
              <div className="text-xs">
                {diff.rules_diff.added > 0 && <span className="text-green-400">+{diff.rules_diff.added} </span>}
                {diff.rules_diff.removed > 0 && <span className="text-red-400">-{diff.rules_diff.removed}</span>}
                {diff.rules_diff.added === 0 && diff.rules_diff.removed === 0 && <span className="text-[var(--text-muted)]">no change</span>}
              </div>
            </div>
            <div className="bg-[var(--bg-card)] rounded p-3">
              <div className="text-xs text-[var(--text-muted)]">NAT Rules</div>
              <div className="font-semibold">{diff.nat_diff.v1_count} → {diff.nat_diff.v2_count}</div>
              <div className="text-xs">
                {diff.nat_diff.added > 0 && <span className="text-green-400">+{diff.nat_diff.added} </span>}
                {diff.nat_diff.removed > 0 && <span className="text-red-400">-{diff.nat_diff.removed}</span>}
                {diff.nat_diff.added === 0 && diff.nat_diff.removed === 0 && <span className="text-[var(--text-muted)]">no change</span>}
              </div>
            </div>
            <div className="bg-[var(--bg-card)] rounded p-3">
              <div className="text-xs text-[var(--text-muted)]">Total Resources</div>
              <div className="font-semibold">{diff.total_v1} → {diff.total_v2}</div>
            </div>
            <div className="bg-[var(--bg-card)] rounded p-3">
              <div className="text-xs text-[var(--text-muted)]">Hash Match</div>
              <div className={`font-semibold ${diff.identical ? "text-green-400" : "text-yellow-400"}`}>
                {diff.identical ? "Identical" : "Changed"}
              </div>
            </div>
          </div>

          {/* JSON diff */}
          <div>
            <div className="flex gap-2 mb-3">
              {["rules", "nat", "system", "auth", "vpn", "geoip"].map(s => (
                <button key={s} onClick={() => setDiffSection(s)}
                  className={`px-3 py-1 text-xs rounded-md transition-colors ${
                    diffSection === s
                      ? "bg-blue-600/20 border border-blue-500/40 text-blue-400"
                      : "bg-[var(--bg-card)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  }`}>
                  {s}
                </button>
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <div className="text-xs text-[var(--text-muted)] mb-1">v{diffV1}</div>
                <pre className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-80 text-red-300">
                  {JSON.stringify((diff.v1_json as Record<string, unknown>)[diffSection] ?? {}, null, 2)}
                </pre>
              </div>
              <div>
                <div className="text-xs text-[var(--text-muted)] mb-1">v{diffV2}</div>
                <pre className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-80 text-green-300">
                  {JSON.stringify((diff.v2_json as Record<string, unknown>)[diffSection] ?? {}, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
