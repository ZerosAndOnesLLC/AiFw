"use client";

import { useState } from "react";
import { AifwUpdateInfo, OsUpgradeStatus } from "@/lib/api/updates";

interface OsUpgradeCardProps {
  osUpgrade: OsUpgradeStatus | null;
  aifwInfo: AifwUpdateInfo | null;
  starting: boolean;
  rebooting: boolean;
  onStart: (target: string) => void;
  onReboot: () => void;
}

const PHASE_LABEL: Record<string, string> = {
  fetching: "Downloading release",
  installing: "Installing kernel",
  reboot_required: "Reboot required",
  finalizing: "Finishing install",
  done: "Complete",
  failed: "Failed",
};

/**
 * FreeBSD release upgrade flow (#613). Shown when the latest AiFw release
 * needs a newer OS than this box runs, or while/after an upgrade job is
 * in flight. The upgrade runs server-side (freebsd-update), needs one
 * reboot in the middle, and finishes itself after boot.
 */
export function OsUpgradeCard({
  osUpgrade,
  aifwInfo,
  starting,
  rebooting,
  onStart,
  onReboot,
}: OsUpgradeCardProps) {
  const [confirming, setConfirming] = useState(false);
  const [rebootConfirming, setRebootConfirming] = useState(false);

  const state = osUpgrade?.state ?? null;
  const currentOs = osUpgrade?.current_os ?? null;
  // Target preference: what the newest blocked release demands (#624 —
  // present even while an older compatible release stays installable),
  // the legacy no-compatible-release fields, then the target of the job
  // already on record (retry-after-failure case).
  const neededTarget =
    aifwInfo?.blocked_requires_os ||
    (aifwInfo?.os_upgrade_required && aifwInfo?.required_os) ||
    null;
  const blockedVersion = aifwInfo?.blocked_version ?? aifwInfo?.latest_version;
  const retryTarget = state?.phase === "failed" ? state.target : null;
  const startTarget = neededTarget ?? retryTarget;

  const active = ["fetching", "installing", "finalizing"].includes(
    state?.phase ?? "",
  );

  // Nothing to say: no upgrade needed, none running, none recorded.
  if (!state && !neededTarget) return null;

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
        <div className="space-y-2">
          <div>
            <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">
              Operating System Upgrade
            </span>
            <p className="text-xl font-semibold text-[var(--text-primary)]">
              {currentOs ?? "Unknown"}
              {startTarget && !active && state?.phase !== "done" && (
                <span className="text-[var(--text-muted)]"> → {startTarget}-RELEASE</span>
              )}
              {state && (active || state.phase === "reboot_required") && (
                <span className="text-[var(--text-muted)]"> → {state.target}-RELEASE</span>
              )}
            </p>
          </div>

          {neededTarget && !state && (
            <p className="text-sm text-[var(--text-secondary)] max-w-xl">
              AiFw v{blockedVersion} requires FreeBSD {neededTarget}.
              Upgrade the operating system first; the AiFw update unlocks
              afterwards.
            </p>
          )}

          {state && (
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span
                className={`inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                  state.phase === "failed"
                    ? "bg-red-500/15 text-red-400 border-red-500/30"
                    : state.phase === "done"
                      ? "bg-green-500/15 text-green-400 border-green-500/30"
                      : state.phase === "reboot_required"
                        ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
                        : "bg-blue-500/15 text-blue-400 border-blue-500/30"
                }`}
              >
                {active && (
                  <div className="w-3 h-3 border-2 border-blue-400/30 border-t-blue-400 rounded-full animate-spin" />
                )}
                {PHASE_LABEL[state.phase] ?? state.phase}
              </span>
              <span className="text-xs text-[var(--text-muted)]">
                {state.detail}
              </span>
            </div>
          )}

          {active && (
            <p className="text-xs text-[var(--text-muted)]">
              This can take a while — the full release is downloaded and
              staged. The firewall keeps filtering throughout.
            </p>
          )}
        </div>

        <div className="flex flex-wrap gap-2 sm:flex-col sm:items-end">
          {startTarget && !active && state?.phase !== "reboot_required" && !confirming && (
            <button
              onClick={() => setConfirming(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md transition-colors"
            >
              {state?.phase === "failed" ? "Retry Upgrade" : `Upgrade to ${startTarget}`}
            </button>
          )}

          {confirming && startTarget && (
            <div className="flex flex-col items-end gap-2">
              <p className="max-w-56 text-xs text-[var(--text-secondary)] text-right">
                Downloads and installs FreeBSD {startTarget}. A reboot is
                required partway through; the rest completes automatically
                after boot.
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setConfirming(false);
                    onStart(startTarget);
                  }}
                  disabled={starting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
                >
                  {starting && (
                    <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  )}
                  {starting ? "Starting..." : "Start Upgrade"}
                </button>
                <button
                  onClick={() => setConfirming(false)}
                  className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {state?.phase === "reboot_required" && !rebootConfirming && (
            <button
              onClick={() => setRebootConfirming(true)}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md transition-colors"
            >
              Reboot to Continue
            </button>
          )}

          {rebootConfirming && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setRebootConfirming(false);
                  onReboot();
                }}
                disabled={rebooting}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
              >
                {rebooting ? "Rebooting..." : "Confirm Reboot"}
              </button>
              <button
                onClick={() => setRebootConfirming(false)}
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
