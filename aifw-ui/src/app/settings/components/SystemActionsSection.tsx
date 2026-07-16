"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";

export interface SystemActionsSectionProps {
  visible: boolean;
  confirmReboot: boolean;
  setConfirmReboot: Dispatch<SetStateAction<boolean>>;
  rebooting: boolean;
  feedback: Feedback | null;
  reboot: () => void;
}

export function SystemActionsSection({
  visible,
  confirmReboot,
  setConfirmReboot,
  rebooting,
  feedback,
  reboot,
}: SystemActionsSectionProps) {
  return (
    <section className={`bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden ${visible ? "" : "hidden"}`}>
      <div className="px-6 py-4 border-b border-[var(--border)]">
        <h2 className="text-lg font-semibold">System Actions</h2>
      </div>
      <div className="p-6 space-y-4">
        <FeedbackBanner feedback={feedback} />
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-[var(--text-primary)] font-medium">Reboot System</p>
            <p className="text-xs text-[var(--text-muted)]">
              Restart the firewall appliance. All active connections will be dropped.
            </p>
          </div>
          {!confirmReboot ? (
            <button
              onClick={() => setConfirmReboot(true)}
              className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
            >
              Reboot
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-xs text-red-400">Are you sure?</span>
              <button
                onClick={reboot}
                disabled={rebooting}
                className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors disabled:opacity-50"
              >
                {rebooting ? "Rebooting..." : "Confirm Reboot"}
              </button>
              <button
                onClick={() => setConfirmReboot(false)}
                className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
