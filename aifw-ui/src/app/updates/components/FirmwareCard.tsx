"use client";

import { AifwUpdateInfo } from "@/lib/api/updates";

interface FirmwareCardProps {
  info: AifwUpdateInfo | null;
  checking: boolean;
  installing: boolean;
  rollingBack: boolean;
  onCheck: () => void;
  onInstall: () => void;
  onRollback: () => void;
  onTogglePrerelease: (enabled: boolean) => void;
}

export function FirmwareCard({
  info,
  checking,
  installing,
  rollingBack,
  onCheck,
  onInstall,
  onRollback,
  onTogglePrerelease,
}: FirmwareCardProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div className="space-y-2">
          <div>
            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">AiFw Firmware</span>
            <p className="text-xl font-semibold text-[var(--text-primary)]">
              v{info?.current_version || "unknown"}
            </p>
          </div>
          {info?.latest_version && (
            <div className="text-xs text-[var(--text-muted)]">
              Latest: v{info.latest_version}
              {info.published_at && ` (${new Date(info.published_at).toLocaleDateString()})`}
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            {info?.update_available ? (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                v{info.latest_version} available
              </span>
            ) : (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                Up to date
              </span>
            )}
            {info?.has_backup && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-500/15 text-gray-400 border border-gray-500/30">
                Backup: v{info.backup_version}
              </span>
            )}
          </div>
          {info?.checksum_signature_url && (
            <a
              href={info.checksum_signature_url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-blue-400 hover:text-blue-300 underline"
            >
              Verify signed checksum
            </a>
          )}
          <label className="flex items-center gap-2 pt-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={info?.include_prereleases ?? false}
              onChange={(e) => onTogglePrerelease(e.target.checked)}
              className="rounded border-gray-600"
            />
            <span className="text-xs text-[var(--text-secondary)]">
              Include pre-releases (test channel)
            </span>
          </label>
        </div>

        <div className="flex flex-wrap gap-2 sm:flex-col sm:items-end">
          <button
            onClick={onCheck}
            disabled={checking}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
          >
            {checking && (
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            )}
            {checking ? "Checking..." : "Check for Update"}
          </button>

          {info?.update_available && info?.os_upgrade_required && (
            <p className="max-w-56 text-xs text-yellow-400">
              v{info.latest_version} requires FreeBSD {info.required_os}.
              Upgrade the operating system first (card above), then install.
            </p>
          )}

          {info?.update_available &&
            !info?.os_upgrade_required &&
            info?.tarball_url &&
            info?.checksum_url &&
            info?.checksum_signature_url && (
            <button
              onClick={onInstall}
              disabled={installing}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {installing && (
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              )}
              {installing ? "Installing..." : `Update to v${info.latest_version}`}
            </button>
          )}

          {info?.update_available && !info?.checksum_signature_url && (
            <p className="max-w-56 text-xs text-red-400">
              Installation blocked: this release has no signed checksum.
            </p>
          )}

          {info?.has_backup && (
            <button
              onClick={onRollback}
              disabled={rollingBack}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {rollingBack ? "Rolling back..." : `Rollback to v${info.backup_version}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
