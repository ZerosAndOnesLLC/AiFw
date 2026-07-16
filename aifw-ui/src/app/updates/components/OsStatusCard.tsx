"use client";

import { UpdateStatus } from "@/lib/api/updates";

interface OsStatusCardProps {
  status: UpdateStatus | null;
  checking: boolean;
  installing: boolean;
  rebooting: boolean;
  rebootConfirm: boolean;
  onCheck: () => void;
  onInstall: () => void;
  onReboot: () => void;
  onRebootConfirmChange: (confirm: boolean) => void;
}

export function OsStatusCard({
  status,
  checking,
  installing,
  rebooting,
  rebootConfirm,
  onCheck,
  onInstall,
  onReboot,
  onRebootConfirmChange,
}: OsStatusCardProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div className="space-y-2">
          <div>
            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">OS Version</span>
            <p className="text-xl font-semibold text-[var(--text-primary)]">
              {status?.os_version || "Unknown"}
            </p>
          </div>
          <div className="text-xs text-[var(--text-muted)]">
            Last checked:{" "}
            {status?.last_check
              ? new Date(status.last_check).toLocaleString()
              : "Never"}
          </div>

          {/* Badges */}
          <div className="flex flex-wrap gap-2 pt-1">
            {status && status.pending_pkg_count > 0 && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                {status.pending_pkg_count} package{status.pending_pkg_count !== 1 ? "s" : ""} pending
              </span>
            )}
            {status?.pending_os_updates && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                OS updates available
              </span>
            )}
            {status?.needs_reboot && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/15 text-red-400 border border-red-500/30">
                Reboot needed
              </span>
            )}
            {status && !status.pending_os_updates && status.pending_pkg_count === 0 && !status.needs_reboot && (
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                System up to date
              </span>
            )}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-2 sm:flex-col sm:items-end">
          <button
            onClick={onCheck}
            disabled={checking}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
          >
            {checking && (
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            )}
            {checking ? "Checking..." : "Check Now"}
          </button>

          {status && (status.pending_pkg_count > 0 || status.pending_os_updates) && (
            <button
              onClick={onInstall}
              disabled={installing}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {installing && (
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              )}
              {installing ? "Installing..." : "Install Updates"}
            </button>
          )}

          {status?.needs_reboot && !rebootConfirm && (
            <button
              onClick={() => onRebootConfirmChange(true)}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
            >
              Reboot
            </button>
          )}

          {rebootConfirm && (
            <div className="flex items-center gap-2">
              <button
                onClick={onReboot}
                disabled={rebooting}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
              >
                {rebooting ? "Rebooting..." : "Confirm Reboot"}
              </button>
              <button
                onClick={() => onRebootConfirmChange(false)}
                className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
