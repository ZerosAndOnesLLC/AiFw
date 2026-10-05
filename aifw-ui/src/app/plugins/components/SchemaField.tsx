"use client";

import { useState } from "react";
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

/** Text-like input that saves on blur / Enter when the value changed. */
function DraftInput({
  field,
  initial,
  disabled,
  onSave,
  type = "text",
  placeholder,
}: {
  field: SettingField;
  initial: string;
  disabled: boolean;
  onSave: (draft: string) => void;
  type?: "text" | "number" | "url";
  placeholder?: string;
}) {
  const [draft, setDraft] = useState(initial);
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

    case "multi_select": {
      const selected = Array.isArray(value) ? value : [];
      const toggle = (v: string) =>
        onSave(selected.includes(v) ? selected.filter((s) => s !== v) : [...selected, v]);
      return (
        <FieldShell field={field} save={save}>
          <div
            id={`plugin-field-${field.key}`}
            role="group"
            aria-label={field.label}
            className="grid gap-2 sm:grid-cols-2"
          >
            {k.options.map((o) => {
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

    case "integer":
      return (
        <FieldShell field={field} save={save}>
          <div className="max-w-[12rem]">
            <DraftInput
              field={field}
              type="number"
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
  const [draft, setDraft] = useState(initial);
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
