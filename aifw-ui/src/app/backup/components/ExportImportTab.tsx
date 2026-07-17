"use client";

import type { ChangeEvent, RefObject } from "react";
import type { ImportPreview } from "@/lib/api/backup";
import { InterfaceMappingPanel } from "./InterfaceMappingPanel";
import { btnPrimary, btnSecondary } from "./styles";

/* ===================== Export / Import Tab ================ */

export function ExportImportTab({
  exporting,
  handleExport,
  importing,
  preview,
  importPreview,
  importMap,
  setImportMap,
  fileRef,
  handleFileSelect,
  handleImport,
  cancelImport,
}: {
  exporting: boolean;
  handleExport: () => void;
  importing: boolean;
  preview: string | null;
  importPreview: ImportPreview | null;
  importMap: Record<string, string>;
  setImportMap: (m: Record<string, string>) => void;
  fileRef: RefObject<HTMLInputElement | null>;
  handleFileSelect: (e: ChangeEvent<HTMLInputElement>) => void;
  handleImport: () => void;
  cancelImport: () => void;
}) {
  return (
    <div className="space-y-6">
      {/* Export */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold">Export Configuration</h2>
        <p className="text-xs text-[var(--text-muted)]">Download the current firewall configuration as a JSON file</p>
        <button onClick={handleExport} disabled={exporting} className={btnPrimary}>
          {exporting ? "Exporting..." : "Download Backup"}
        </button>
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
            {importPreview && importPreview.interfaces_missing.length > 0 && (
              <InterfaceMappingPanel
                preview={importPreview}
                map={importMap}
                onMapChange={setImportMap}
              />
            )}
            <div className="flex gap-3">
              <button onClick={handleImport} disabled={importing} className={btnPrimary}>
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
