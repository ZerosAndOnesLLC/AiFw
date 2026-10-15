"use client";

import { useEffect, useRef, useState } from "react";
import { Toggle } from "@/components/ui/Toggle";
import { FieldSave } from "@/hooks/usePlugin";
import { SettingField, SettingValue } from "@/lib/api/plugins";
import { inputCls } from "@/app/settings/components/sectionStyles";
import { SaveIndicator } from "./SaveIndicator";

type Save = (value: SettingValue) => Promise<boolean>;

function FieldShell({
  field,
  save,
  inline,
  children,
}: {
  field: SettingField;
  save?: FieldSave;
  inline?: boolean;
  children: React.ReactNode;
}) {
  const id = `plugin-field-${field.key}`;
  return (
    <div className={inline ? "flex items-start justify-between gap-4" : "space-y-1.5"}>
      <div className={inline ? "min-w-0" : "flex items-center justify-between gap-2"}>
        <label htmlFor={id} className="text-sm font-medium text-[var(--text-primary)]">
          {field.label}
        </label>
        {!inline && <SaveIndicator save={save} />}
        {inline && field.help && (
          <p className="text-xs text-[var(--text-muted)] mt-0.5">{field.help}</p>
        )}
      </div>
      {inline ? (
        <div className="flex items-center gap-2 pt-0.5">
          <SaveIndicator save={save} />
          {children}
        </div>
      ) : (
        children
      )}
      {!inline && field.help && <p className="text-xs text-[var(--text-muted)]">{field.help}</p>}
      {save?.state === "error" && (
        <p role="alert" className="text-xs text-red-400">
          {save.message}
        </p>
      )}
    </div>
  );
}

/** How long a multi-select waits after the last click before saving. */
const MULTI_SELECT_DEBOUNCE_MS = 800;

/**
 * Keep a local draft that follows the saved value when it changes on the
 * server (another tab, a reset), without remounting the input — so focus
 * and caret survive a save.
 */
function useDraft<T>(saved: T): [T, (v: T) => void] {
  const [draft, setDraft] = useState(saved);
  const last = useRef(saved);
  useEffect(() => {
    if (JSON.stringify(last.current) !== JSON.stringify(saved)) {
      last.current = saved;
      setDraft(saved);
    }
  }, [saved]);
  return [draft, setDraft];
}

/** Text-like input that saves on blur / Enter when the value changed. */
function DraftInput({
  field,
  initial,
  disabled,
  onSave,
  type = "text",
  placeholder,
  min,
  max,
}: {
  field: SettingField;
  initial: string;
  disabled: boolean;
  onSave: (draft: string) => void;
  type?: "text" | "number" | "url";
  placeholder?: string;
  min?: number;
  max?: number;
}) {
  const [draft, setDraft] = useDraft(initial);
  const commit = () => {
    if (draft !== initial) onSave(draft);
  };
  return (
    <input
      id={`plugin-field-${field.key}`}
      type={type}
      value={draft}
      disabled={disabled}
      placeholder={placeholder}
      min={min}
      max={max}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          commit();
        }
        if (e.key === "Escape") setDraft(initial);
      }}
      className={inputCls}
    />
  );
}

export function SchemaField({
  field,
  value,
  save,
  canWrite,
  onSave,
}: {
  field: SettingField;
  value: SettingValue;
  save?: FieldSave;
  canWrite: boolean;
  onSave: Save;
}) {
  const disabled = !canWrite;
  const k = field.kind;

  switch (k.type) {
    case "bool":
      return (
        <FieldShell field={field} save={save} inline>
          <Toggle
            checked={value === true}
            disabled={disabled}
            onChange={() => onSave(!(value === true))}
            label={field.label}
            color="blue"
          />
        </FieldShell>
      );

    case "select":
      // Few options that each need explaining read better as cards.
      if (k.options.length <= 4 && k.options.every((o) => o.help)) {
        return (
          <FieldShell field={field} save={save}>
            <div
              id={`plugin-field-${field.key}`}
              role="radiogroup"
              aria-label={field.label}
              className="grid gap-2 sm:grid-cols-2"
            >
              {k.options.map((o) => {
                const on = value === o.value;
                return (
                  <label
                    key={o.value}
                    className={`flex gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                      on
                        ? "border-[var(--accent)]/60 bg-[var(--accent)]/10"
                        : "border-[var(--border)] bg-[var(--bg-primary)] hover:border-[var(--text-muted)]"
                    } ${disabled ? "opacity-60 cursor-not-allowed" : ""}`}
                  >
                    <input
                      type="radio"
                      name={field.key}
                      checked={on}
                      disabled={disabled}
                      onChange={() => onSave(o.value)}
                      className="mt-0.5 accent-[var(--accent)]"
                    />
                    <span>
                      <span className="block text-sm text-[var(--text-primary)]">{o.label}</span>
                      <span className="block text-xs text-[var(--text-muted)] mt-0.5">{o.help}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </FieldShell>
        );
      }
      return (
        <FieldShell field={field} save={save}>
          <select
            id={`plugin-field-${field.key}`}
            value={String(value ?? "")}
            disabled={disabled}
            onChange={(e) => onSave(e.target.value)}
            className={inputCls}
          >
            {k.options.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
                {o.help ? ` — ${o.help}` : ""}
              </option>
            ))}
          </select>
        </FieldShell>
      );

    case "multi_select":
      return (
        <MultiSelectField
          field={field}
          options={k.options}
          value={Array.isArray(value) ? value : []}
          save={save}
          disabled={disabled}
          onSave={onSave}
        />
      );

    case "integer":
      return (
        <FieldShell field={field} save={save}>
          <div className="max-w-[12rem]">
            <DraftInput
              field={field}
              type="number"
              min={k.min}
              max={k.max}
              initial={value === null ? "" : String(value)}
              disabled={disabled}
              placeholder={`${k.min}–${k.max}`}
              onSave={(d) => onSave(d.trim() === "" ? null : Number(d))}
            />
          </div>
        </FieldShell>
      );

    case "text":
    case "url":
      return (
        <FieldShell field={field} save={save}>
          <DraftInput
            field={field}
            type={k.type === "url" ? "url" : "text"}
            initial={typeof value === "string" ? value : ""}
            disabled={disabled}
            placeholder={k.type === "url" ? (k.https_only ? "https://…" : "https:// or http://…") : ""}
            onSave={(d) => onSave(d.trim() === "" ? null : d.trim())}
          />
        </FieldShell>
      );

    case "list": {
      const items = Array.isArray(value) ? value : [];
      return (
        <FieldShell field={field} save={save}>
          <ListInput
            field={field}
            initial={items.join("\n")}
            disabled={disabled}
            placeholder={
              k.item === "cidr"
                ? "203.0.113.7\n198.51.100.0/24"
                : k.item === "url"
                  ? "https://example.com/blocklist.txt"
                  : ""
            }
            onSave={(lines) => onSave(lines)}
          />
          <p className="text-xs text-[var(--text-muted)]">
            One per line · up to {k.max_items}
          </p>
        </FieldShell>
      );
    }
  }
}

/**
 * Checkbox grid whose clicks are batched: the selection is kept locally
 * and saved once the operator pauses, so toggling three feeds restarts
 * the plugin once, not three times, and keyboard focus stays put.
 */
function MultiSelectField({
  field,
  options,
  value,
  save,
  disabled,
  onSave,
}: {
  field: SettingField;
  options: { value: string; label: string; help?: string }[];
  value: string[];
  save?: FieldSave;
  disabled: boolean;
  onSave: Save;
}) {
  const [selected, setSelected] = useDraft(value);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pending = useRef<string[] | null>(null);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );
  const toggle = (v: string) => {
    const next = selected.includes(v) ? selected.filter((s) => s !== v) : [...selected, v];
    setSelected(next);
    pending.current = next;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      timer.current = null;
      if (pending.current) onSave(pending.current);
      pending.current = null;
    }, MULTI_SELECT_DEBOUNCE_MS);
  };
  return (
    <FieldShell field={field} save={save}>
      <div
        id={`plugin-field-${field.key}`}
        role="group"
        aria-label={field.label}
        className="grid gap-2 sm:grid-cols-2"
      >
        {options.map((o) => {
          const on = selected.includes(o.value);
          return (
            <label
              key={o.value}
              className={`flex gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                on
                  ? "border-[var(--accent)]/60 bg-[var(--accent)]/10"
                  : "border-[var(--border)] bg-[var(--bg-primary)] hover:border-[var(--text-muted)]"
              } ${disabled ? "opacity-60 cursor-not-allowed" : ""}`}
            >
              <input
                type="checkbox"
                checked={on}
                disabled={disabled}
                onChange={() => toggle(o.value)}
                className="mt-0.5 accent-[var(--accent)]"
              />
              <span className="min-w-0">
                <span className="block text-sm text-[var(--text-primary)]">{o.label}</span>
                {o.help && (
                  <span className="block text-xs text-[var(--text-muted)] mt-0.5">{o.help}</span>
                )}
              </span>
            </label>
          );
        })}
      </div>
    </FieldShell>
  );
}

function ListInput({
  field,
  initial,
  disabled,
  placeholder,
  onSave,
}: {
  field: SettingField;
  initial: string;
  disabled: boolean;
  placeholder: string;
  onSave: (lines: string[]) => void;
}) {
  const [draft, setDraft] = useDraft(initial);
  return (
    <textarea
      id={`plugin-field-${field.key}`}
      value={draft}
      disabled={disabled}
      rows={Math.min(8, Math.max(3, draft.split("\n").length + 1))}
      placeholder={placeholder}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        if (draft === initial) return;
        onSave(
          draft
            .split("\n")
            .map((l) => l.trim())
            .filter(Boolean),
        );
      }}
      className={`${inputCls} font-mono text-xs`}
    />
  );
}
