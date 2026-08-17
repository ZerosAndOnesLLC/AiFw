"use client";

import { useState, type ChangeEvent, type RefObject } from "react";
import type { ImportPreview } from "@/lib/api/backup";
import { InterfaceMappingPanel } from "./InterfaceMappingPanel";
import { btnPrimary, btnSecondary } from "./styles";

const inputCls =
  "w-full px-3 py-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]";

/* ===================== Export / Import Tab ================ */

export function ExportImportTab({
  exporting,
  handleExport,
  importing,
  preview,
  importPreview,
  importMap,
  setImportMap,
  importPassphrase,
  setImportPassphrase,
  fileRef,
  handleFileSelect,
  handleImport,
  cancelImport,
}: {
  exporting: boolean;
  handleExport: (passphrase?: string) => void;
  importing: boolean;
  preview: string | null;
  importPreview: ImportPreview | null;
  importMap: Record<string, string>;
  setImportMap: (m: Record<string, string>) => void;
  importPassphrase: string;
  setImportPassphrase: (p: string) => void;
  fileRef: RefObject<HTMLInputElement | null>;
  handleFileSelect: (e: ChangeEvent<HTMLInputElement>) => void;
  handleImport: () => void;
  cancelImport: () => void;
}) {
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [exportPassphrase2, setExportPassphrase2] = useState("");
  const [showPortable, setShowPortable] = useState(false);
  const passphraseTooShort = exportPassphrase.length > 0 && exportPassphrase.length < 8;
  const passphraseMismatch = exportPassphrase2.length > 0 && exportPassphrase !== exportPassphrase2;
  const portableReady = exportPassphrase.length >= 8 && exportPassphrase === exportPassphrase2;

  const secretsState = importPreview?.secrets;
  const needsPassphrase = secretsState?.state === "passphrase";
  const unresolved = importPreview?.unresolved_secrets ?? [];
  const importBlocked = (needsPassphrase && !importPassphrase) || unresolved.length > 0;

  return (
    <div className="space-y-6">
      {/* Export */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Export Configuration</h2>
        <p className="text-xs text-[var(--text-muted)]">
          Download the current firewall configuration as a JSON file. Secret fields (WireGuard and IPsec keys,
          CARP passwords, DDNS TSIG) are <strong>redacted</strong> — a redacted backup restores onto this
          appliance, which fills the secrets back in from its own state. For a backup that can be restored on
          a replacement box, protect the secrets with a passphrase.
        </p>
        <div className="flex flex-wrap gap-3">
          <button onClick={() => handleExport()} disabled={exporting} className={btnPrimary}>
            {exporting ? "Exporting..." : "Download Backup (secrets redacted)"}
          </button>
          <button onClick={() => setShowPortable((v) => !v)} className={btnSecondary}>
            {showPortable ? "Hide portable export" : "Portable backup (passphrase-protected)…"}
          </button>
        </div>
        {showPortable && (
          <div className="rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-3 max-w-md">
            <p className="text-xs text-[var(--text-muted)]">
              Secrets are wrapped with AES-256-GCM under a key derived from this passphrase (Argon2id). It is
              not stored anywhere — lose it and the backup&apos;s secrets cannot be recovered.
            </p>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Passphrase (min 8 characters)</label>
              <input type="password" autoComplete="new-password" value={exportPassphrase}
                onChange={(e) => setExportPassphrase(e.target.value)} className={inputCls} />
              {passphraseTooShort && <p className="text-xs text-red-400 mt-1">At least 8 characters.</p>}
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Confirm passphrase</label>
              <input type="password" autoComplete="new-password" value={exportPassphrase2}
                onChange={(e) => setExportPassphrase2(e.target.value)} className={inputCls} />
              {passphraseMismatch && <p className="text-xs text-red-400 mt-1">Passphrases do not match.</p>}
            </div>
            <button
              onClick={() => { handleExport(exportPassphrase); setExportPassphrase(""); setExportPassphrase2(""); }}
              disabled={exporting || !portableReady}
              className={btnPrimary}
            >
              {exporting ? "Exporting..." : "Download Portable Backup"}
            </button>
          </div>
        )}
      </div>

      <hr className="border-[var(--border)]" />

      {/* Import */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Import Configuration</h2>
        <p className="text-xs text-[var(--text-muted)]">Upload a previously exported AiFw configuration JSON file. Import replaces the current firewall state — use History restore if you only want to roll back one change.</p>
        <input ref={fileRef} type="file" accept=".json" onChange={handleFileSelect}
          className="block w-full text-sm text-[var(--text-secondary)] file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-[var(--accent)] file:text-white hover:file:bg-[var(--accent-hover)]" />
        {preview && (
          <div className="space-y-3">
            <details>
              <summary className="text-xs text-[var(--text-muted)] cursor-pointer hover:text-[var(--text-secondary)]">
                Preview JSON ({(preview.length / 1024).toFixed(1)} KB)
              </summary>
              <pre className="mt-2 bg-[var(--bg-primary)] border border-[var(--border)] rounded p-3 text-xs font-mono overflow-auto max-h-60 text-[var(--text-secondary)]">
                {preview.substring(0, 5000)}{preview.length > 5000 ? "\n... (truncated)" : ""}
              </pre>
            </details>
            {secretsState?.state === "passphrase" && (
              <div className="rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] p-4 space-y-2 max-w-md">
                <p className="text-xs text-[var(--text-secondary)]">
                  This backup&apos;s {secretsState.count} secret{secretsState.count === 1 ? "" : "s"} are
                  passphrase-protected. Enter the passphrase used when it was exported.
                </p>
                <input type="password" autoComplete="off" placeholder="Backup passphrase" value={importPassphrase}
                  onChange={(e) => setImportPassphrase(e.target.value)} className={inputCls} />
              </div>
            )}
            {secretsState?.state === "redacted" && unresolved.length === 0 && (
              <p className="text-xs text-[var(--text-muted)]">
                This backup was exported with secrets redacted ({secretsState.count}); this appliance holds all of
                them and will fill them in on import.
              </p>
            )}
            {unresolved.length > 0 && (
              <div className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300 space-y-1">
                <p className="font-medium">Import blocked — this backup was exported without secrets and this appliance does not hold them:</p>
                <ul className="list-disc pl-5 font-mono">
                  {unresolved.map((u) => <li key={u}>{u}</li>)}
                </ul>
                <p>Re-export from the source with a passphrase, or remove these objects from the file and recreate them after import.</p>
              </div>
            )}
            {importPreview && importPreview.interfaces_missing.length > 0 && (
              <InterfaceMappingPanel
                preview={importPreview}
                map={importMap}
                onMapChange={setImportMap}
              />
            )}
            <div className="flex gap-3">
              <button onClick={handleImport} disabled={importing || importBlocked} className={btnPrimary}>
                {importing ? "Importing..." : (importPreview && importPreview.interfaces_missing.length > 0 ? "Apply with Mapping" : "Import & Apply")}
              </button>
              <button onClick={cancelImport}
                className={btnSecondary}>Cancel</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
