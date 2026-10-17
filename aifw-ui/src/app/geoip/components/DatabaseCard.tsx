"use client";

import { useRef, useState } from "react";
import { Database, Download, KeyRound, LoaderCircle, Upload } from "lucide-react";
import { GeoIpDatabase, REFRESH_OPTIONS } from "@/lib/api/geoip";
import { inputCls, labelCls } from "@/app/settings/components/sectionStyles";

function when(iso: string | null): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toLocaleString();
}

/**
 * Where the country networks come from. Without a loaded release every
 * rule is an empty table, so this card leads with that state and the two
 * ways out of it: a MaxMind license key (scheduled downloads) or a manual
 * upload of the GeoLite2 Country CSV release.
 */
export function DatabaseCard({
  db,
  busy,
  canWrite,
  onSaveSettings,
  onRefresh,
  onUpload,
}: {
  db: GeoIpDatabase | null;
  busy: string | null;
  canWrite: boolean;
  onSaveSettings: (patch: { license_key?: string | null; update_interval_hours?: number }) => Promise<boolean>;
  onRefresh: () => Promise<boolean>;
  onUpload: (files: File[]) => Promise<boolean>;
}) {
  const [keyDraft, setKeyDraft] = useState("");
  const [editingKey, setEditingKey] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  if (!db) {
    return (
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 text-sm text-[var(--text-muted)]">
        Loading database status…
      </section>
    );
  }

  const saving = busy === "db-settings";
  const showKeyInput = canWrite && (!db.has_license_key || editingKey);

  const commitKey = async () => {
    const k = keyDraft.trim();
    if (!k) {
      setEditingKey(false);
      return;
    }
    if (await onSaveSettings({ license_key: k })) {
      setKeyDraft("");
      setEditingKey(false);
    }
  };

  return (
    <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <header className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-2">
        <Database className="h-4 w-4 text-[var(--text-muted)]" aria-hidden />
        <h3 className="text-sm font-medium">GeoLite2 database</h3>
        <span className="ml-auto text-xs text-[var(--text-muted)]">
          {db.loaded
            ? `${db.countries} countries · ${db.cidrs.toLocaleString()} networks · ${
                db.source === "maxmind" ? "downloaded" : "uploaded"
              } ${when(db.updated_at)}`
            : "not loaded"}
        </span>
      </header>

      <div className="p-4 space-y-4">
        {!db.loaded && (
          <div className="p-3 rounded-md border border-amber-500/30 bg-amber-500/10 text-sm text-amber-200">
            No country data is loaded, so every rule below matches nothing. Add a free MaxMind
            license key to download GeoLite2 automatically, or upload the{" "}
            <span className="font-mono text-xs">GeoLite2-Country-CSV</span> zip from your MaxMind
            account.
          </div>
        )}
        {db.last_error && (
          <div className="p-3 rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-300">
            Last download failed ({when(db.last_refresh_attempt)}): {db.last_error}
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2">
          {/* License key */}
          <div className="space-y-1.5">
            <label htmlFor="geoip-license-key" className={labelCls}>
              MaxMind license key
            </label>
            {showKeyInput ? (
              <div className="flex gap-2">
                <input
                  id="geoip-license-key"
                  type="password"
                  autoComplete="off"
                  value={keyDraft}
                  placeholder={db.has_license_key ? "Enter a new key" : "40-character key from maxmind.com"}
                  onChange={(e) => setKeyDraft(e.target.value)}
                  onBlur={commitKey}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      commitKey();
                    }
                    if (e.key === "Escape" && db.has_license_key) {
                      setKeyDraft("");
                      setEditingKey(false);
                    }
                  }}
                  disabled={saving}
                  className={inputCls}
                />
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-md border border-[var(--border)] bg-[var(--bg-primary)] text-sm">
                  <KeyRound
                    className={`h-4 w-4 ${db.has_license_key ? "text-green-400" : "text-[var(--text-muted)]"}`}
                    aria-hidden
                  />
                  <span className="text-[var(--text-secondary)]">
                    {db.has_license_key ? "••••••••" : "Not set"}
                  </span>
                  {db.has_license_key && <span className="ml-auto text-xs text-green-400">Set</span>}
                </div>
                {canWrite && db.has_license_key && (
                  <>
                    <button
                      type="button"
                      onClick={() => setEditingKey(true)}
                      className="px-3 py-2 text-sm rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:text-white"
                    >
                      Replace
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm("Remove the stored MaxMind license key? Scheduled downloads stop.")) {
                          onSaveSettings({ license_key: null });
                        }
                      }}
                      className="px-3 py-2 text-sm rounded-md border border-red-500/30 text-red-400 hover:bg-red-500/10"
                    >
                      Clear
                    </button>
                  </>
                )}
              </div>
            )}
            <p className="text-xs text-[var(--text-muted)]">
              Free account at maxmind.com → Manage License Keys. Stored encrypted, never shown again.
            </p>
          </div>

          {/* Schedule */}
          <div className="space-y-1.5">
            <label htmlFor="geoip-refresh" className={labelCls}>
              Automatic refresh
            </label>
            <select
              id="geoip-refresh"
              value={db.update_interval_hours}
              disabled={!canWrite || saving}
              onChange={(e) => onSaveSettings({ update_interval_hours: Number(e.target.value) })}
              className={inputCls}
            >
              {REFRESH_OPTIONS.map((o) => (
                <option key={o.hours} value={o.hours}>
                  {o.label}
                </option>
              ))}
              {!REFRESH_OPTIONS.some((o) => o.hours === db.update_interval_hours) && (
                <option value={db.update_interval_hours}>Every {db.update_interval_hours} h</option>
              )}
            </select>
            <p className="text-xs text-[var(--text-muted)]">
              {db.update_interval_hours === 0
                ? "Downloads only when you click Refresh now."
                : db.has_license_key
                  ? `Next download ${when(db.next_refresh)}. MaxMind publishes GeoLite2 twice a week.`
                  : "Needs a license key to run."}
            </p>
          </div>
        </div>

        {canWrite && (
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={onRefresh}
              disabled={!db.has_license_key || busy !== null}
              title={db.has_license_key ? "Download the latest release from MaxMind" : "Add a license key first"}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {busy === "db-refresh" ? (
                <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <Download className="h-4 w-4" aria-hidden />
              )}
              Refresh now
            </button>
            <button
              type="button"
              onClick={() => fileInput.current?.click()}
              disabled={busy !== null}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-sm rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:text-white hover:border-[var(--text-muted)] disabled:opacity-50"
            >
              {busy === "db-upload" ? (
                <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <Upload className="h-4 w-4" aria-hidden />
              )}
              Upload release…
            </button>
            <input
              ref={fileInput}
              type="file"
              accept=".zip,.csv"
              multiple
              className="hidden"
              aria-label="GeoLite2 Country CSV release"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? []);
                e.target.value = "";
                if (files.length) onUpload(files);
              }}
            />
            <span className="self-center text-xs text-[var(--text-muted)]">
              Upload accepts the GeoLite2-Country-CSV zip or its .csv files.
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
