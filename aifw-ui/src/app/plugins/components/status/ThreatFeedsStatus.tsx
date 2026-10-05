import { LoaderCircle } from "lucide-react";
import { relativeTime } from "@/lib/api/plugins";
import { Tile } from "./Tile";

interface FeedStatus {
  id: string;
  name: string;
  url: string;
  entries: number;
  last_success: string | null;
  last_attempt: string | null;
  last_error: string | null;
  next_due: string | null;
  skipped_lines: number;
}

export interface ThreatFeedsStatusData {
  table: string;
  table_entries: number;
  pf_table_entries: number | null;
  dropped: {
    non_public: number;
    too_broad: number;
    allowlisted: number;
    redundant: number;
    over_cap: number;
  };
  last_applied: string | null;
  refreshing: boolean;
  mode: "block" | "log";
  direction: "both" | "inbound";
  feeds: FeedStatus[];
}

export function ThreatFeedsStatus({ s }: { s: ThreatFeedsStatusData }) {
  const healthy = s.feeds.filter((f) => !f.last_error && f.last_success).length;
  const d = s.dropped;
  const skipped: [string, number][] = [
    ["private / bogon", d.non_public],
    ["too broad", d.too_broad],
    ["allowlisted", d.allowlisted],
    ["duplicate", d.redundant],
    ["over cap", d.over_cap],
  ].filter(([, n]) => (n as number) > 0) as [string, number][];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Tile
          label={s.mode === "block" ? "Networks blocked" : "Networks logged"}
          value={s.table_entries.toLocaleString()}
          sub={<code>&lt;{s.table}&gt;</code>}
          tone="good"
        />
        <Tile
          label="Feeds healthy"
          value={`${healthy} / ${s.feeds.length}`}
          tone={healthy === s.feeds.length ? "good" : "warn"}
        />
        <Tile
          label="Last update"
          value={
            s.refreshing ? (
              <span className="inline-flex items-center gap-2 text-base">
                <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> Refreshing…
              </span>
            ) : (
              relativeTime(s.last_applied)
            )
          }
        />
        <Tile
          label="Enforcement"
          value={s.mode === "block" ? "Block" : "Log only"}
          sub={s.direction === "both" ? "Inbound + outbound" : "Inbound"}
          tone={s.mode === "block" ? "default" : "warn"}
        />
      </div>

      <div className="overflow-x-auto border border-[var(--border)] rounded-lg">
        <table className="w-full text-sm">
          <thead className="bg-[var(--bg-primary)]/60 text-xs uppercase tracking-wider text-[var(--text-muted)]">
            <tr>
              <th className="text-left font-medium px-3 py-2">Feed</th>
              <th className="text-right font-medium px-3 py-2">Entries</th>
              <th className="text-left font-medium px-3 py-2">Updated</th>
              <th className="text-left font-medium px-3 py-2">Next</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {s.feeds.map((f) => (
              <tr key={f.id}>
                <td className="px-3 py-2">
                  <div className="text-[var(--text-primary)] break-all">{f.name}</div>
                  {f.last_error && <div className="text-xs text-red-400">{f.last_error}</div>}
                </td>
                <td className="px-3 py-2 text-right tabular-nums">{f.entries.toLocaleString()}</td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {f.last_success ? relativeTime(f.last_success) : "never"}
                </td>
                <td className="px-3 py-2 text-[var(--text-muted)]">
                  {f.next_due ? relativeTime(f.next_due) : "now"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {skipped.length > 0 && (
        <p className="text-xs text-[var(--text-muted)]">
          Skipped for safety: {skipped.map(([k, n]) => `${n.toLocaleString()} ${k}`).join(" · ")}
        </p>
      )}
    </div>
  );
}
