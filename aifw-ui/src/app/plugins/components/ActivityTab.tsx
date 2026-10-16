import { RefreshCw } from "lucide-react";
import { LogEntry, LogLevel } from "@/lib/api/plugins";

const LEVELS: { value: LogLevel; label: string }[] = [
  { value: "info", label: "All" },
  { value: "warn", label: "Warnings" },
  { value: "error", label: "Errors" },
];

const BADGE: Record<LogLevel, string> = {
  info: "text-blue-300 bg-blue-500/10 border-blue-500/20",
  warn: "text-amber-300 bg-amber-500/10 border-amber-500/20",
  error: "text-red-300 bg-red-500/10 border-red-500/20",
};

export function ActivityTab({
  logs,
  level,
  onLevel,
  onRefresh,
}: {
  logs: LogEntry[];
  level: LogLevel;
  onLevel: (l: LogLevel) => void;
  onRefresh: () => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div role="radiogroup" aria-label="Minimum level" className="inline-flex rounded-md border border-[var(--border)] overflow-hidden">
          {LEVELS.map((l) => (
            <button
              key={l.value}
              type="button"
              role="radio"
              aria-checked={level === l.value}
              onClick={() => onLevel(l.value)}
              className={`px-3 py-1.5 text-xs ${
                level === l.value
                  ? "bg-[var(--accent)] text-white"
                  : "text-[var(--text-muted)] hover:text-white"
              }`}
            >
              {l.label}
            </button>
          ))}
        </div>
        <span className="text-xs text-[var(--text-muted)]">
          Last {logs.length} entries · refreshes every 5s · cleared when the API restarts
        </span>
        <button
          type="button"
          onClick={onRefresh}
          aria-label="Refresh activity"
          className="ml-auto p-1.5 rounded-md text-[var(--text-muted)] hover:text-white hover:bg-[var(--bg-card-hover)]"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {logs.length === 0 ? (
        <p className="py-10 text-center text-sm text-[var(--text-muted)]">
          No activity yet. Entries appear here when the plugin starts, works, or hits a problem.
        </p>
      ) : (
        <ul className="divide-y divide-[var(--border)] border border-[var(--border)] rounded-lg overflow-hidden">
          {logs.map((e, i) => (
            <li key={`${e.ts}-${i}`} className="flex items-start gap-3 px-3 py-2 text-sm bg-[var(--bg-primary)]/40">
              <time
                dateTime={e.ts}
                title={new Date(e.ts).toLocaleString()}
                className="flex-shrink-0 w-20 text-xs text-[var(--text-muted)] font-mono pt-0.5"
              >
                {new Date(e.ts).toLocaleTimeString()}
              </time>
              <span className={`flex-shrink-0 px-1.5 py-0.5 rounded border text-[11px] uppercase ${BADGE[e.level]}`}>
                {e.level}
              </span>
              <span className="text-[var(--text-secondary)] break-words min-w-0">{e.message}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
