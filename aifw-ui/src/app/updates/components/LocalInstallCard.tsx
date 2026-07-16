"use client";

import { LocalInstallResult } from "@/lib/api/updates";

interface LocalInstallCardProps {
  tarballFile: File | null;
  installRestart: boolean;
  uploadProgress: number | null;
  result: LocalInstallResult | null;
  installing: boolean;
  onTarballChange: (file: File | null) => void;
  onShaChange: (file: File | null) => void;
  onInstallRestartChange: (checked: boolean) => void;
  onInstall: () => void;
}

export function LocalInstallCard({
  tarballFile,
  installRestart,
  uploadProgress,
  result,
  installing,
  onTarballChange,
  onShaChange,
  onInstallRestartChange,
  onInstall,
}: LocalInstallCardProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <h2 className="text-lg font-semibold mb-1">Install from Package</h2>
      <p className="text-sm text-[var(--text-muted)] mb-4">
        Install a locally-built update tarball (<code className="font-mono text-xs">.tar.xz</code>) without
        fetching from GitHub. Useful for test-cycle iteration — build the tarball with{" "}
        <code className="font-mono text-xs">sh freebsd/build-update.sh</code> and upload it here.
      </p>

      <div className="space-y-4">
        {/* Tarball picker */}
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">
            Update tarball <span className="text-red-400">*</span>
          </label>
          <input
            type="file"
            accept=".xz,.tar.xz"
            onChange={(e) => onTarballChange(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-[var(--text-secondary)] file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-[var(--border)] file:bg-[var(--bg-secondary)] file:text-[var(--text-primary)] file:text-sm hover:file:bg-[var(--bg-card)] cursor-pointer"
          />
          {tarballFile && (
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              {tarballFile.name} &mdash; {Math.round(tarballFile.size / (1024 * 1024))} MB
            </p>
          )}
        </div>

        {/* SHA256 sidecar (optional) */}
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">
            SHA256 checksum file <span className="text-[var(--text-muted)]">(optional — omit to skip verification)</span>
          </label>
          <input
            type="file"
            accept=".sha256,.txt"
            onChange={(e) => onShaChange(e.target.files?.[0] ?? null)}
            className="block w-full text-sm text-[var(--text-secondary)] file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border file:border-[var(--border)] file:bg-[var(--bg-secondary)] file:text-[var(--text-primary)] file:text-sm hover:file:bg-[var(--bg-card)] cursor-pointer"
          />
        </div>

        {/* Auto-restart toggle */}
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={installRestart}
            onChange={(e) => onInstallRestartChange(e.target.checked)}
            className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
          />
          <div>
            <span className="text-sm text-[var(--text-secondary)]">Auto-restart services after install</span>
            <p className="text-xs text-[var(--text-muted)]">
              Restarts all AiFw services immediately after the tarball is installed. Causes a brief outage.
            </p>
          </div>
        </label>

        {/* Upload progress */}
        {uploadProgress !== null && (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-[var(--text-muted)]">
              <span>Uploading...</span>
              <span>{uploadProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-[var(--bg-secondary)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[var(--accent)] rounded-full transition-all duration-200"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Result banner */}
        {result && (
          <div
            className={`px-3 py-2 rounded-md text-sm border ${
              result.ok
                ? "bg-green-500/10 border-green-500/30 text-green-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            }`}
          >
            {result.message}
          </div>
        )}

        {/* Install button */}
        <button
          onClick={onInstall}
          disabled={!tarballFile || installing}
          className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
        >
          {installing && (
            <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          )}
          {installing ? "Installing..." : "Install Package"}
        </button>
      </div>
    </div>
  );
}
