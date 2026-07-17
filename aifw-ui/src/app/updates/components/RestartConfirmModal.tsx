"use client";

import { RestartPrompt } from "@/hooks/useUpdates";

interface RestartConfirmModalProps {
  prompt: RestartPrompt;
  onLater: () => void;
  onRestartServices: () => void;
  onReboot: () => void;
}

// Restart-confirm modal — shown after install/rollback succeeds when
// the API reports restart_required: true. Three actions:
//   - Reboot (full system reboot via shutdown(8) — 1 min delay)
//   - Restart services (in-place service bounce — ~30s)
//   - Later (defer; the restart-pending banner persists across reloads)
//
// When the release notes contained `[reboot-recommended]` the modal
// surfaces that hint and promotes Reboot to the visually-primary
// action. Reboot is the safer choice for releases that change rc.d /
// libexec / sysrc-managed services, where a service-only bounce can
// race against its own tooling (see commit 5b1b232 for the bug we
// hit twice doing it the other way).
export function RestartConfirmModal({ prompt, onLater, onRestartServices, onReboot }: RestartConfirmModalProps) {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg max-w-lg w-full p-6 space-y-4">
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">
          {prompt.action === "install" ? "Update installed" : "Rollback complete"}
        </h2>
        <p className="text-sm text-[var(--text-muted)]">
          {prompt.action === "install"
            ? `AiFw v${prompt.version} is on disk and ready to activate.`
            : `Rollback to v${prompt.version} is on disk and ready to activate.`}
        </p>
        {prompt.rebootRecommended && (
          <div className="px-3 py-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 text-yellow-200 text-xs">
            <span className="font-semibold">Reboot recommended.</span>{" "}
            {prompt.rebootReason ??
              "This release changes service-supervision tooling — a full reboot avoids edge cases where a service-only restart races against its own changes."}
          </div>
        )}
        <ul className="text-xs text-[var(--text-muted)] space-y-1">
          <li><span className="text-[var(--text-primary)]">Reboot</span> — ~1 min outage, all state reinitialised by init.</li>
          <li><span className="text-[var(--text-primary)]">Restart services</span> — ~30 s outage, only AiFw services bounce.</li>
          <li><span className="text-[var(--text-primary)]">Later</span> — keeps running the previous version. Pending banner stays visible.</li>
        </ul>
        <div className="flex flex-col-reverse sm:flex-row gap-2 sm:justify-end pt-2">
          <button
            onClick={onLater}
            className="px-4 py-2 text-sm rounded-md border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
          >
            Later
          </button>
          <button
            onClick={onRestartServices}
            className={`px-4 py-2 text-sm rounded-md ${
              prompt.rebootRecommended
                ? "border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
                : "bg-[var(--accent)] text-white hover:opacity-90"
            }`}
          >
            Restart services
          </button>
          <button
            onClick={onReboot}
            className={`px-4 py-2 text-sm rounded-md ${
              prompt.rebootRecommended
                ? "bg-yellow-500 text-black font-semibold hover:bg-yellow-400"
                : "border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
            }`}
          >
            Reboot
          </button>
        </div>
      </div>
    </div>
  );
}
