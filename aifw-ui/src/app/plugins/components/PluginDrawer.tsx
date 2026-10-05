"use client";

import { useState } from "react";
import { Activity, LoaderCircle, Settings2, Sparkles, X } from "lucide-react";
import { ModalOverlay } from "@/components/ui/ModalOverlay";
import { Toggle } from "@/components/ui/Toggle";
import { usePlugin } from "@/hooks/usePlugin";
import { PluginSummary } from "@/lib/api/plugins";
import { FeedbackBanner } from "@/app/settings/components/FeedbackBanner";
import { ActivityTab } from "./ActivityTab";
import { OverviewTab } from "./OverviewTab";
import { PluginIcon } from "./PluginIcon";
import { SettingsTab } from "./SettingsTab";
import { StateBadge } from "./StateBadge";

export type Tab = "overview" | "settings" | "activity";

const TABS: { id: Tab; label: string; Icon: typeof Activity }[] = [
  { id: "overview", label: "Overview", Icon: Sparkles },
  { id: "settings", label: "Settings", Icon: Settings2 },
  { id: "activity", label: "Activity", Icon: Activity },
];

export function PluginDrawer({
  summary,
  canWrite,
  busy,
  initialTab,
  notice,
  onToggle,
  onSummary,
  onClose,
}: {
  summary: PluginSummary;
  canWrite: boolean;
  busy: boolean;
  initialTab: Tab;
  /** Why the drawer was opened (e.g. enabling failed validation). */
  notice?: string;
  onToggle: (enabled: boolean) => Promise<string | null>;
  onSummary: (s: PluginSummary) => void;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<Tab>(initialTab);
  const p = usePlugin(summary.name, onSummary);
  const d = p.detail;
  const warnings = p.logs.filter((l) => l.level !== "info").length;

  return (
    <ModalOverlay
      onClose={onClose}
      ariaLabel={`${summary.title} plugin`}
      className="fixed inset-0 bg-black/60 z-50 flex justify-end"
      panelClassName="h-full w-full max-w-3xl bg-[var(--bg-secondary)] border-l border-[var(--border)] flex flex-col shadow-2xl"
    >
      <header className="px-6 pt-5 pb-0 border-b border-[var(--border)]">
        <div className="flex items-start gap-3">
          <PluginIcon name={summary.name} size="lg" />
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold text-white">{summary.title}</h2>
            <div className="text-xs text-[var(--text-muted)]">
              v{summary.version} · {summary.author} · <code>{summary.name}</code>
            </div>
          </div>
          <StateBadge state={summary.state} />
          <Toggle
            checked={summary.enabled}
            disabled={!canWrite || busy}
            onChange={async () => {
              const err = await onToggle(!summary.enabled);
              if (err) p.showFeedback("error", err);
              p.reload();
            }}
            label={`${summary.enabled ? "Disable" : "Enable"} ${summary.title}`}
          />
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1.5 rounded-md text-[var(--text-muted)] hover:text-white hover:bg-[var(--bg-card-hover)]"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav role="tablist" aria-label="Plugin sections" className="flex gap-1 mt-4">
          {TABS.map(({ id, label, Icon }) => (
            <button
              key={id}
              role="tab"
              type="button"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
                tab === id
                  ? "border-[var(--accent)] text-white"
                  : "border-transparent text-[var(--text-muted)] hover:text-white"
              }`}
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
              {id === "activity" && warnings > 0 && (
                <span className="ml-1 px-1.5 rounded-full text-[11px] bg-amber-500/20 text-amber-300">
                  {warnings}
                </span>
              )}
            </button>
          ))}
        </nav>
      </header>

      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
        <FeedbackBanner feedback={p.feedback} />
        {notice && !summary.enabled && (
          <div className="p-3 rounded-md border border-amber-500/30 bg-amber-500/10 text-sm text-amber-200">
            {notice}
          </div>
        )}
        {p.loadError && !d ? (
          <div className="p-3 rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-300">
            {p.loadError}{" "}
            <button type="button" onClick={p.reload} className="underline">
              Retry
            </button>
          </div>
        ) : !d ? (
          <div className="flex items-center gap-2 text-sm text-[var(--text-muted)] py-10 justify-center">
            <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> Loading…
          </div>
        ) : tab === "overview" ? (
          <OverviewTab
            detail={d}
            status={p.status}
            canWrite={canWrite}
            actionBusy={p.actionBusy}
            lastResult={p.lastResult}
            onRun={(a, args) => p.runAction(a.id, a.label, args)}
            onDismissResult={p.clearResult}
          />
        ) : tab === "settings" ? (
          <SettingsTab
            detail={d}
            fields={p.fields}
            canWrite={canWrite}
            onSave={p.saveField}
            onReset={p.reset}
          />
        ) : (
          <ActivityTab
            logs={p.logs}
            level={p.logLevel}
            onLevel={p.setLogLevel}
            onRefresh={p.refreshLogs}
          />
        )}
      </div>
    </ModalOverlay>
  );
}
