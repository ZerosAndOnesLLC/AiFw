"use client";

import { useState } from "react";
import { LoaderCircle, Play } from "lucide-react";
import { ActionInfo, SettingValue } from "@/lib/api/plugins";
import { inputCls } from "@/app/settings/components/sectionStyles";

function ActionCard({
  action,
  busy,
  disabled,
  onRun,
}: {
  action: ActionInfo;
  busy: boolean;
  disabled: boolean;
  onRun: (args: Record<string, SettingValue>) => void;
}) {
  const [args, setArgs] = useState<Record<string, SettingValue>>(() =>
    Object.fromEntries(action.args.map((a) => [a.key, a.default])),
  );
  // An argument with no default must be filled in, whatever its kind.
  const missing = action.args.some(
    (a) => a.default === null && !String(args[a.key] ?? "").trim(),
  );

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!missing) onRun(args);
      }}
      className="flex flex-wrap items-end gap-3 p-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)]/40"
    >
      <div className="min-w-[12rem] flex-1">
        <div className="text-sm font-medium text-[var(--text-primary)]">{action.label}</div>
        <div className="text-xs text-[var(--text-muted)]">{action.description}</div>
      </div>
      {action.args.map((a) => (
        <div key={a.key} className="w-48">
          <label className="sr-only" htmlFor={`action-${action.id}-${a.key}`}>
            {a.label}
          </label>
          {a.kind.type === "select" ? (
            <select
              id={`action-${action.id}-${a.key}`}
              value={String(args[a.key] ?? "")}
              onChange={(e) => setArgs({ ...args, [a.key]: e.target.value })}
              className={inputCls}
            >
              {a.kind.options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          ) : (
            <input
              id={`action-${action.id}-${a.key}`}
              type={a.kind.type === "integer" ? "number" : "text"}
              min={a.kind.type === "integer" ? a.kind.min : undefined}
              max={a.kind.type === "integer" ? a.kind.max : undefined}
              value={String(args[a.key] ?? "")}
              placeholder={a.label}
              onChange={(e) => setArgs({ ...args, [a.key]: e.target.value })}
              className={inputCls}
            />
          )}
        </div>
      ))}
      <button
        type="submit"
        disabled={disabled || busy || missing}
        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-medium bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {busy ? (
          <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden />
        ) : (
          <Play className="h-4 w-4" aria-hidden />
        )}
        {action.args.length ? "Run" : action.label}
      </button>
    </form>
  );
}

export function ActionBar({
  actions,
  running,
  canWrite,
  busy,
  onRun,
}: {
  actions: ActionInfo[];
  running: boolean;
  canWrite: boolean;
  busy: string | null;
  onRun: (a: ActionInfo, args: Record<string, SettingValue>) => void;
}) {
  if (actions.length === 0) return null;
  return (
    <div className="space-y-2">
      {!running && (
        <p className="text-xs text-[var(--text-muted)]">Enable the plugin to use these actions.</p>
      )}
      {actions.map((a) => (
        <ActionCard
          key={a.id}
          action={a}
          busy={busy === a.id}
          disabled={!running || !canWrite || (busy !== null && busy !== a.id)}
          onRun={(args) => onRun(a, args)}
        />
      ))}
    </div>
  );
}
