import { relativeTime } from "@/lib/api/plugins";
import { Tile } from "./Tile";

const NAMES: Record<string, string> = {
  ntfy: "ntfy",
  discord: "Discord",
  slack: "Slack",
  telegram: "Telegram",
  webhook: "Webhook",
};

export interface NotifierStatusData {
  channels: {
    id: string;
    sent: number;
    failed: number;
    last_error: string | null;
    last_sent_at: string | null;
  }[];
  queue_depth: number;
  dropped_queue_full: number;
  duplicates: number;
  rate_limited: number;
  last_notification: { title: string; at: string } | null;
}

export function NotifierStatus({ s }: { s: NotifierStatusData }) {
  const sent = s.channels.reduce((n, c) => n + c.sent, 0);
  const failed = s.channels.reduce((n, c) => n + c.failed, 0);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Tile label="Delivered" value={sent.toLocaleString()} tone="good" />
        <Tile label="Failed" value={failed.toLocaleString()} tone={failed ? "bad" : "default"} />
        <Tile
          label="Suppressed"
          value={(s.duplicates + s.rate_limited + s.dropped_queue_full).toLocaleString()}
          sub={`${s.duplicates} repeats · ${s.rate_limited} rate-limited`}
        />
        <Tile
          label="Last sent"
          value={relativeTime(s.last_notification?.at)}
          sub={s.last_notification?.title}
        />
      </div>

      <ul className="divide-y divide-[var(--border)] border border-[var(--border)] rounded-lg">
        {s.channels.map((c) => (
          <li key={c.id} className="flex items-start gap-3 px-3 py-2.5 text-sm">
            <span
              className={`mt-1.5 h-2 w-2 rounded-full flex-shrink-0 ${
                c.last_error ? "bg-red-400" : c.sent ? "bg-green-400" : "bg-gray-500"
              }`}
            />
            <div className="min-w-0 flex-1">
              <div className="text-[var(--text-primary)]">{NAMES[c.id] ?? c.id}</div>
              {c.last_error ? (
                <div className="text-xs text-red-400 break-words">{c.last_error}</div>
              ) : (
                <div className="text-xs text-[var(--text-muted)]">
                  {c.sent ? `last delivery ${relativeTime(c.last_sent_at)}` : "nothing sent yet"}
                </div>
              )}
            </div>
            <div className="text-xs text-[var(--text-muted)] tabular-nums text-right">
              {c.sent} sent
              {c.failed > 0 && <span className="text-red-400"> · {c.failed} failed</span>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
