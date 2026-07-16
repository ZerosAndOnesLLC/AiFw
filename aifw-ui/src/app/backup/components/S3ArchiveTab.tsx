"use client";

import { useS3Archive } from "@/hooks/useBackups";

/* ===================== S3 Archive tab ===================== */

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function fmtWhen(s: string | null): string {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

export function S3ArchiveTab() {
  const { loading, error, items, importing, status, reload, importNow } = useS3Archive();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">S3 Archive</h2>
          <p className="text-xs text-[var(--text-muted)]">
            Remote config versions archived to the S3 bucket configured under{" "}
            <a className="text-blue-400 underline" href="/settings">Settings → S3 Backup Sync</a>.
            Importing fetches a copy as a new local version; nothing is applied automatically.
          </p>
        </div>
        <button
          onClick={reload}
          disabled={loading}
          className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
        >
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
          ⚠ {error}
          <div className="text-xs text-red-300/70 mt-1">
            Enable S3 sync in Settings and run the Test connection to confirm credentials are valid.
          </div>
        </div>
      )}

      {status && (
        <div className="rounded border border-emerald-500/40 bg-emerald-500/10 p-3 text-sm text-emerald-200">
          {status}
        </div>
      )}

      {!error && !loading && items.length === 0 && (
        <div className="text-sm text-[var(--text-muted)]">No archived versions found.</div>
      )}

      {items.length > 0 && (
        <div className="border border-[var(--border)] rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-[var(--bg-card-secondary)] text-xs text-[var(--text-muted)]">
              <tr>
                <th className="text-left px-3 py-2">Key</th>
                <th className="text-right px-3 py-2">Size</th>
                <th className="text-left px-3 py-2">Last modified</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((o) => (
                <tr key={o.key} className="border-t border-[var(--border)]">
                  <td className="px-3 py-2 font-mono text-[11px] text-white truncate max-w-md" title={o.key}>{o.key}</td>
                  <td className="px-3 py-2 text-right tabular-nums text-[var(--text-muted)]">{fmtBytes(o.size)}</td>
                  <td className="px-3 py-2 text-[var(--text-muted)]">{fmtWhen(o.last_modified)}</td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => importNow(o.key)}
                      disabled={!!importing}
                      className="px-2 py-1 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
                    >
                      {importing === o.key ? "Importing…" : "Import"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
