"use client";

import { fmtDate, type ConfigVersion, type DiffSummary } from "@/lib/api/backup";
import { DiffViewer } from "./DiffViewer";
import { inputClass, btnPrimary, btnSecondary } from "./styles";

/* ===================== History Tab ===================== */

export function HistoryTab({
  history,
  saving,
  comment,
  setComment,
  saveSnapshot,
  restoring,
  restore,
  loadDiff,
  diff,
  diffLoading,
  diffV1,
  diffV2,
  diffSection,
  setDiffSection,
  closeDiff,
}: {
  history: ConfigVersion[];
  saving: boolean;
  comment: string;
  setComment: (v: string) => void;
  saveSnapshot: () => void;
  restoring: number | null;
  restore: (version: number) => void;
  loadDiff: (v1: number, v2: number) => void;
  diff: DiffSummary | null;
  diffLoading: boolean;
  diffV1: number | null;
  diffV2: number | null;
  diffSection: string;
  setDiffSection: (s: string) => void;
  closeDiff: () => void;
}) {
  return (
    <div className="space-y-5">
      {/* Save snapshot */}
      <div className="flex gap-3 items-end">
        <div className="flex-1">
          <label className="text-xs text-[var(--text-muted)] block mb-1">Save Current Config</label>
          <input type="text" value={comment} onChange={e => setComment(e.target.value)}
            placeholder="Optional comment (e.g. 'before NAT changes')"
            className={inputClass}
            onKeyDown={e => e.key === "Enter" && saveSnapshot()} />
        </div>
        <button onClick={saveSnapshot} disabled={saving} className={btnPrimary}>
          {saving ? "Saving..." : "Save Snapshot"}
        </button>
      </div>

      {/* Version history table */}
      {history.length === 0 ? (
        <div className="text-center py-12 text-[var(--text-muted)]">
          <p className="text-lg mb-2">No config versions saved yet</p>
          <p className="text-sm">Save a snapshot to start tracking configuration changes</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border)]">
                <th className="pb-2 pr-4">Version</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Resources</th>
                <th className="pb-2 pr-4">Created</th>
                <th className="pb-2 pr-4">Comment</th>
                <th className="pb-2 pr-4">Hash</th>
                <th className="pb-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((v, idx) => (
                <tr key={v.version} className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-primary)]/50">
                  <td className="py-2.5 pr-4 font-mono font-semibold">v{v.version}</td>
                  <td className="py-2.5 pr-4">
                    {v.applied ? (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30">Active</span>
                    ) : v.rolled_back ? (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">Rolled Back</span>
                    ) : (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-gray-500/20 text-gray-400 border border-gray-500/30">Saved</span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-[var(--text-muted)]">{v.resource_count}</td>
                  <td className="py-2.5 pr-4 text-[var(--text-muted)] whitespace-nowrap">{fmtDate(v.created_at)}</td>
                  <td className="py-2.5 pr-4 text-[var(--text-secondary)] max-w-[200px] truncate">{v.comment || "-"}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-[var(--text-muted)]">{v.hash.substring(0, 8)}</td>
                  <td className="py-2.5 text-right space-x-2 whitespace-nowrap">
                    {!v.applied && (
                      <button onClick={() => restore(v.version)}
                        disabled={restoring === v.version}
                        className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors disabled:opacity-50">
                        {restoring === v.version ? "..." : "Restore"}
                      </button>
                    )}
                    {idx < history.length - 1 && (
                      <button onClick={() => loadDiff(history[idx + 1].version, v.version)}
                        className={btnSecondary}>
                        Diff
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Diff viewer */}
      {diff && (
        <DiffViewer
          diff={diff}
          diffLoading={diffLoading}
          diffV1={diffV1}
          diffV2={diffV2}
          diffSection={diffSection}
          setDiffSection={setDiffSection}
          onClose={closeDiff}
        />
      )}
    </div>
  );
}
