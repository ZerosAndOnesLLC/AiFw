import { ChevronRight, TriangleAlert } from "lucide-react";
import { Toggle } from "@/components/ui/Toggle";
import { HOOK_LABELS, PluginSummary, relativeTime } from "@/lib/api/plugins";
import { PluginIcon } from "./PluginIcon";
import { StateBadge } from "./StateBadge";

export function PluginCard({
  plugin,
  canWrite,
  busy,
  onToggle,
  onOpen,
}: {
  plugin: PluginSummary;
  canWrite: boolean;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
  onOpen: () => void;
}) {
  const p = plugin;
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 flex flex-col gap-3 hover:border-[var(--accent)]/40 transition-colors">
      <div className="flex items-start gap-3">
        <PluginIcon name={p.name} />
        <div className="min-w-0 flex-1">
          <button
            type="button"
            onClick={onOpen}
            className="text-left text-base font-semibold text-white hover:text-[var(--accent)] focus:outline-none focus-visible:underline"
          >
            {p.title}
          </button>
          <div className="text-xs text-[var(--text-muted)]">
            v{p.version} · {p.author}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <StateBadge state={p.state} />
          <Toggle
            checked={p.enabled}
            disabled={!canWrite || busy}
            onChange={() => onToggle(!p.enabled)}
            label={`${p.enabled ? "Disable" : "Enable"} ${p.title}`}
            title={canWrite ? undefined : "You don't have permission to change plugins"}
          />
        </div>
      </div>

      <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{p.description}</p>

      {p.state === "error" && p.last_error && (
        <div className="flex gap-2 p-2.5 rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-300">
          <TriangleAlert className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden />
          <span>{p.last_error}</span>
        </div>
      )}

      <div className="mt-auto flex flex-wrap items-center gap-2 pt-1">
        {p.hooks.map((h) => (
          <span
            key={h}
            className="px-2 py-0.5 rounded text-xs bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-muted)]"
          >
            {HOOK_LABELS[h] ?? h}
          </span>
        ))}
        <span className="ml-auto text-xs text-[var(--text-muted)]">
          {p.state === "running"
            ? `${p.stats.events.toLocaleString()} events · last ${relativeTime(p.stats.last_event_at)}`
            : ""}
        </span>
        <button
          type="button"
          onClick={onOpen}
          className="inline-flex items-center gap-1 text-sm font-medium text-[var(--accent)] hover:text-[var(--accent-hover)]"
        >
          Configure <ChevronRight className="h-4 w-4" aria-hidden />
        </button>
      </div>
    </div>
  );
}
