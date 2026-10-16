"use client";

import { RotateCcw } from "lucide-react";
import { FieldSave } from "@/hooks/usePlugin";
import { PluginDetail, SettingField, SettingValue, isVisible } from "@/lib/api/plugins";
import { SchemaField } from "./SchemaField";
import { SecretField } from "./SecretField";

function groupFields(schema: SettingField[]): [string, SettingField[]][] {
  const groups = new Map<string, SettingField[]>();
  for (const f of schema) {
    const g = f.group ?? "Settings";
    groups.set(g, [...(groups.get(g) ?? []), f]);
  }
  return [...groups.entries()];
}

export function SettingsTab({
  detail,
  fields,
  canWrite,
  onSave,
  onReset,
}: {
  detail: PluginDetail;
  fields: Record<string, FieldSave>;
  canWrite: boolean;
  onSave: (key: string, label: string, value: SettingValue, secret: boolean) => Promise<boolean>;
  onReset: () => void;
}) {
  if (detail.schema.length === 0) {
    return <p className="text-sm text-[var(--text-muted)]">This plugin has no settings.</p>;
  }
  const values = detail.effective;

  return (
    <div className="space-y-5">
      <p className="text-xs text-[var(--text-muted)]">
        Changes save automatically
        {detail.state === "running" ? " and restart the plugin so they take effect right away" : ""}.
        {!canWrite && " You have read-only access."}
      </p>

      {groupFields(detail.schema).map(([group, groupFields]) => {
        const visible = groupFields.filter((f) => isVisible(f, values));
        if (visible.length === 0) return null;
        return (
          <section
            key={group}
            className="bg-[var(--bg-primary)]/40 border border-[var(--border)] rounded-lg p-4 space-y-4"
          >
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              {group}
            </h3>
            {visible.map((f) =>
              f.secret ? (
                <SecretField
                  key={f.key}
                  field={f}
                  isSet={detail.secrets_set.includes(f.key)}
                  save={fields[f.key]}
                  canWrite={canWrite}
                  onSave={(v) => onSave(f.key, f.label, v, true)}
                />
              ) : (
                <SchemaField
                  key={f.key}
                  field={f}
                  value={values[f.key] ?? null}
                  save={fields[f.key]}
                  canWrite={canWrite}
                  onSave={(v) => onSave(f.key, f.label, v, false)}
                />
              ),
            )}
          </section>
        );
      })}

      {canWrite && (
        <section className="border border-red-500/20 rounded-lg p-4 flex items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-medium text-[var(--text-primary)]">Reset to defaults</h3>
            <p className="text-xs text-[var(--text-muted)]">
              Clears every setting and secret and disables the plugin.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              if (confirm(`Reset ${detail.title} to its defaults? Saved secrets are deleted.`)) {
                onReset();
              }
            }}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm rounded-md border border-red-500/30 text-red-400 hover:bg-red-500/10"
          >
            <RotateCcw className="h-4 w-4" aria-hidden /> Reset
          </button>
        </section>
      )}
    </div>
  );
}
