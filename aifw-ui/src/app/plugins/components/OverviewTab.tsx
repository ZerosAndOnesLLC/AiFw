import { TriangleAlert } from "lucide-react";
import { ActionInfo, PluginDetail, SettingValue, formatLatency, relativeTime } from "@/lib/api/plugins";
import { ActionBar } from "./ActionBar";
import { ResultView } from "./ResultView";
import { PluginStatus } from "./status/PluginStatus";
import { Tile } from "./status/Tile";

export function OverviewTab({
  detail,
  status,
  canWrite,
  actionBusy,
  lastResult,
  onRun,
  onDismissResult,
}: {
  detail: PluginDetail;
  status: unknown;
  canWrite: boolean;
  actionBusy: string | null;
  lastResult: { action: string; result: unknown } | null;
  onRun: (a: ActionInfo, args: Record<string, SettingValue>) => void;
  onDismissResult: () => void;
}) {
  const running = detail.state === "running";
  const s = detail.stats;
  const problems = s.timeouts + s.panics + s.errors;

  return (
    <div className="space-y-6">
      <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{detail.description}</p>

      {detail.state === "error" && detail.last_error && (
        <div className="flex gap-2 p-3 rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-300">
          <TriangleAlert className="h-4 w-4 flex-shrink-0 mt-0.5" aria-hidden />
          <div>
            <div className="font-medium">The plugin is enabled but could not start.</div>
            <div>{detail.last_error}</div>
            <div className="text-xs text-red-300/80 mt-1">
              Fix the settings below; it restarts automatically when they change.
            </div>
          </div>
        </div>
      )}

      {detail.state === "stopped" && (
        <div className="p-3 rounded-md border border-[var(--border)] bg-[var(--bg-primary)]/40 text-sm text-[var(--text-muted)]">
          This plugin is disabled. Review its settings, then turn it on with the switch above.
        </div>
      )}

      {running && status !== null && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">Status</h3>
          <PluginStatus name={detail.name} status={status} />
        </section>
      )}

      {detail.actions.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">Actions</h3>
          <ActionBar
            actions={detail.actions}
            running={running}
            canWrite={canWrite}
            busy={actionBusy}
            onRun={onRun}
          />
          {lastResult && (
            <ResultView action={lastResult.action} result={lastResult.result} onClose={onDismissResult} />
          )}
        </section>
      )}

      {running && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Hook activity since start
          </h3>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Tile label="Events" value={s.events.toLocaleString()} sub={`last ${relativeTime(s.last_event_at)}`} />
            <Tile label="Actions taken" value={s.actions.toLocaleString()} />
            <Tile label="Avg. handling" value={formatLatency(s.avg_latency_us)} />
            <Tile
              label="Problems"
              value={problems.toLocaleString()}
              sub={`${s.timeouts} timeouts · ${s.panics} crashes · ${s.errors} failed actions`}
              tone={problems ? "bad" : "default"}
            />
          </div>
        </section>
      )}

      {detail.rules.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            pf rules (anchor aifw-plugins)
          </h3>
          <pre className="text-xs p-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] overflow-x-auto text-[var(--text-secondary)]">
            {detail.rules.join("\n")}
          </pre>
        </section>
      )}
    </div>
  );
}
