"use client";

import { useState } from "react";
import { LoaderCircle, Pencil, Trash2 } from "lucide-react";
import StatusBadge from "@/components/StatusBadge";
import { Toggle } from "@/components/ui/Toggle";
import { GeoIpAction, GeoIpRule, GeoIpStatus, RuleInput } from "@/lib/api/geoip";

const cellInput =
  "bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]";

/** One row in edit mode: every field saves as soon as it changes. */
function EditRow({
  rule,
  saving,
  onSave,
  onDone,
}: {
  rule: GeoIpRule;
  saving: boolean;
  onSave: (patch: Partial<RuleInput>) => Promise<boolean>;
  onDone: () => void;
}) {
  const [country, setCountry] = useState(rule.country);
  const [label, setLabel] = useState(rule.label ?? "");
  // Follow the saved values when they change underneath (another save
  // landed) without remounting, so focus survives.
  const [seen, setSeen] = useState({ country: rule.country, label: rule.label });
  if (seen.country !== rule.country || seen.label !== rule.label) {
    setSeen({ country: rule.country, label: rule.label });
    setCountry(rule.country);
    setLabel(rule.label ?? "");
  }

  const commitCountry = () => {
    const c = country.trim().toUpperCase();
    if (c.length === 2 && c !== rule.country) onSave({ country: c });
    else setCountry(rule.country);
  };
  const commitLabel = () => {
    const l = label.trim();
    if (l !== (rule.label ?? "")) onSave({ label: l || null });
  };
  const keys = (commit: () => void) => (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      commit();
    }
    if (e.key === "Escape") onDone();
  };

  return (
    <>
      <td className="py-2 px-3">
        <input
          aria-label="Country code"
          value={country}
          maxLength={2}
          onChange={(e) => setCountry(e.target.value.toUpperCase().slice(0, 2))}
          onBlur={commitCountry}
          onKeyDown={keys(commitCountry)}
          className={`${cellInput} w-16 font-mono uppercase`}
          autoFocus
        />
      </td>
      <td className="py-2 px-3">
        <select
          aria-label="Action"
          value={rule.action}
          onChange={(e) => onSave({ action: e.target.value as GeoIpAction })}
          className={cellInput}
        >
          <option value="block">block</option>
          <option value="allow">allow</option>
        </select>
      </td>
      <td className="py-2 px-3">
        <input
          aria-label="Label"
          value={label}
          placeholder={`geoip-${rule.action}-${rule.country}`}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={commitLabel}
          onKeyDown={keys(commitLabel)}
          className={`${cellInput} w-40`}
        />
      </td>
      <td className="py-2 px-3 text-right text-xs text-[var(--text-secondary)]">
        {rule.cidr_count.toLocaleString()}
      </td>
      <td className="py-2 px-3">
        <select
          aria-label="Status"
          value={rule.status}
          onChange={(e) => onSave({ status: e.target.value as GeoIpStatus })}
          className={cellInput}
        >
          <option value="active">active</option>
          <option value="disabled">disabled</option>
        </select>
      </td>
      <td className="py-2 px-3 text-xs text-[var(--text-muted)]">
        {new Date(rule.created_at).toLocaleDateString()}
      </td>
      <td className="py-2 px-3 text-right">
        <div className="inline-flex items-center gap-2">
          {saving && <LoaderCircle className="h-4 w-4 animate-spin text-[var(--text-muted)]" aria-hidden />}
          <button
            type="button"
            onClick={onDone}
            className="px-2 py-1 text-xs rounded border border-[var(--border)] text-[var(--text-secondary)] hover:text-white"
          >
            Done
          </button>
        </div>
      </td>
    </>
  );
}

export function RulesTable({
  rules,
  loading,
  dbLoaded,
  busy,
  canWrite,
  onSave,
  onDelete,
}: {
  rules: GeoIpRule[];
  loading: boolean;
  dbLoaded: boolean;
  busy: string | null;
  canWrite: boolean;
  onSave: (rule: GeoIpRule, patch: Partial<RuleInput>) => Promise<boolean>;
  onDelete: (rule: GeoIpRule) => Promise<boolean>;
}) {
  const [editingId, setEditingId] = useState<string | null>(null);

  return (
    <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <header className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
        <h3 className="text-sm font-medium">Country rules</h3>
        <span className="text-xs text-[var(--text-muted)]">
          {rules.length} {rules.length === 1 ? "rule" : "rules"}
          {canWrite && rules.length > 0 ? " · click a row to edit" : ""}
        </span>
      </header>

      {loading ? (
        <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">Loading rules…</div>
      ) : rules.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
          No country rules yet. Add one below.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                <th className="text-left py-3 px-3">Country</th>
                <th className="text-left py-3 px-3">Action</th>
                <th className="text-left py-3 px-3">Label</th>
                <th className="text-right py-3 px-3">Networks</th>
                <th className="text-left py-3 px-3">Status</th>
                <th className="text-left py-3 px-3">Created</th>
                <th className="text-right py-3 px-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  className={`border-b border-[var(--border)] transition-colors ${
                    canWrite && editingId !== rule.id ? "hover:bg-[var(--bg-card-hover)] cursor-pointer" : ""
                  }`}
                  onClick={() => canWrite && editingId !== rule.id && setEditingId(rule.id)}
                >
                  {editingId === rule.id ? (
                    <EditRow
                      rule={rule}
                      saving={busy === rule.id}
                      onSave={(patch) => onSave(rule, patch)}
                      onDone={() => setEditingId(null)}
                    />
                  ) : (
                    <>
                      <td className="py-2.5 px-3 font-mono text-xs font-bold">{rule.country}</td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={rule.action} />
                      </td>
                      <td className="py-2.5 px-3 text-xs text-[var(--text-secondary)]">
                        {rule.label ?? <span className="text-[var(--text-muted)]">geoip-{rule.action}-{rule.country}</span>}
                      </td>
                      <td
                        className="py-2.5 px-3 text-xs text-right text-[var(--text-secondary)]"
                        title={`pf table <${rule.table}>`}
                      >
                        {rule.cidr_count > 0 ? (
                          rule.cidr_count.toLocaleString()
                        ) : (
                          <span className="text-amber-300" title={dbLoaded ? "The database has no networks for this code" : "No database loaded"}>
                            0
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-2">
                          <Toggle
                            checked={rule.status === "active"}
                            disabled={!canWrite || busy === rule.id}
                            onChange={() =>
                              onSave(rule, { status: rule.status === "active" ? "disabled" : "active" })
                            }
                            label={`${rule.status === "active" ? "Disable" : "Enable"} ${rule.country}`}
                          />
                          <span className="text-xs text-[var(--text-muted)]">
                            {busy === rule.id ? "…" : rule.status}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-[var(--text-muted)]">
                        {new Date(rule.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-2.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                        {canWrite && (
                          <div className="inline-flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => setEditingId(rule.id)}
                              className="p-1 text-[var(--text-muted)] hover:text-blue-400"
                              aria-label={`Edit ${rule.country}`}
                            >
                              <Pencil className="h-4 w-4" />
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                if (confirm(`Delete the ${rule.action} rule for ${rule.country}?`)) onDelete(rule);
                              }}
                              disabled={busy === rule.id}
                              className="p-1 text-[var(--text-muted)] hover:text-red-400 disabled:opacity-40"
                              aria-label={`Delete ${rule.country}`}
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        )}
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
