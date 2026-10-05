"use client";

import { useState } from "react";
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { FieldSave } from "@/hooks/usePlugin";
import { SettingField } from "@/lib/api/plugins";
import { inputCls } from "@/app/settings/components/sectionStyles";
import { SaveIndicator } from "./SaveIndicator";

/**
 * Write-only secret input. The API never returns secret values, only
 * whether one is set — so a set secret shows as "Set" with Replace / Clear,
 * and a new value is saved on blur / Enter.
 */
export function SecretField({
  field,
  isSet,
  save,
  canWrite,
  onSave,
}: {
  field: SettingField;
  isSet: boolean;
  save?: FieldSave;
  canWrite: boolean;
  onSave: (value: string | null) => Promise<boolean>;
}) {
  const [editing, setEditing] = useState(!isSet);
  const [draft, setDraft] = useState("");
  const [reveal, setReveal] = useState(false);
  const id = `plugin-field-${field.key}`;

  const commit = async () => {
    if (!draft.trim()) {
      if (isSet) setEditing(false);
      return;
    }
    if (await onSave(draft.trim())) {
      setDraft("");
      setEditing(false);
      setReveal(false);
    }
  };

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-sm font-medium text-[var(--text-primary)]">
          {field.label}
        </label>
        <SaveIndicator save={save} />
      </div>

      {isSet && !editing ? (
        <div className="flex items-center gap-2">
          <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-md border border-[var(--border)] bg-[var(--bg-primary)] text-sm">
            <KeyRound className="h-4 w-4 text-green-400" aria-hidden />
            <span className="text-[var(--text-secondary)] tracking-widest">••••••••</span>
            <span className="ml-auto text-xs text-green-400">Set</span>
          </div>
          {canWrite && (
            <>
              <button
                type="button"
                onClick={() => setEditing(true)}
                className="px-3 py-2 text-sm rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:text-white hover:border-[var(--text-muted)]"
              >
                Replace
              </button>
              <button
                type="button"
                onClick={() => {
                  if (confirm(`Remove the saved ${field.label.toLowerCase()}?`)) onSave(null);
                }}
                className="px-3 py-2 text-sm rounded-md border border-red-500/30 text-red-400 hover:bg-red-500/10"
              >
                Clear
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="relative">
          <input
            id={id}
            type={reveal ? "text" : "password"}
            value={draft}
            disabled={!canWrite}
            autoComplete="off"
            autoFocus={isSet}
            placeholder={isSet ? "Enter a new value" : "Not set"}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                commit();
              }
              if (e.key === "Escape" && isSet) {
                setDraft("");
                setEditing(false);
              }
            }}
            className={`${inputCls} pr-10`}
          />
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => setReveal((r) => !r)}
            aria-label={reveal ? "Hide value" : "Show value"}
            className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-[var(--text-muted)] hover:text-white"
          >
            {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
      )}

      {field.help && <p className="text-xs text-[var(--text-muted)]">{field.help}</p>}
      {save?.state === "error" && (
        <p role="alert" className="text-xs text-red-400">
          {save.message}
        </p>
      )}
    </div>
  );
}
