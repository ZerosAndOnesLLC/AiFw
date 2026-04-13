"use client";

import { useState } from "react";

type Mode = "reboot" | "shutdown";

export default function RebootPage() {
  const [confirmMode, setConfirmMode] = useState<Mode | null>(null);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    msg: string;
  } | null>(null);

  async function handleAction(mode: Mode) {
    setBusy(true);
    setFeedback(null);
    try {
      const token = localStorage.getItem("aifw_token") || "";
      const path = mode === "reboot" ? "/api/v1/updates/reboot" : "/api/v1/updates/shutdown";
      const res = await fetch(path, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json().catch(() => ({}));
      setFeedback({
        type: "success",
        msg:
          data.message ||
          (mode === "reboot"
            ? "System rebooting in 10 seconds..."
            : "System shutting down in 10 seconds..."),
      });
      setConfirmMode(null);
    } catch {
      setFeedback({
        type: "error",
        msg: `Failed to initiate ${mode}`,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">System Power</h1>
        <p className="text-sm text-gray-400 mt-1">
          Reboot or shut down the AiFw firewall appliance. All active connections
          will be dropped. Firewall rules, NAT, and services restore automatically
          on next boot.
        </p>
      </div>

      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      <ActionCard
        mode="reboot"
        title="Reboot System"
        description="The system will reboot in 10 seconds after confirmation. Web UI will be available again once the system fully boots."
        iconPath="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
        accent="orange"
        confirming={confirmMode === "reboot"}
        busy={busy}
        onStart={() => setConfirmMode("reboot")}
        onConfirm={() => handleAction("reboot")}
        onCancel={() => setConfirmMode(null)}
        confirmLabel="Confirm Reboot"
        busyLabel="Rebooting..."
      />

      <ActionCard
        mode="shutdown"
        title="Shut Down System"
        description="The system will power off in 10 seconds after confirmation. You will need physical or out-of-band access to power the appliance back on."
        iconPath="M5.636 5.636a9 9 0 1012.728 0M12 3v9"
        accent="red"
        confirming={confirmMode === "shutdown"}
        busy={busy}
        onStart={() => setConfirmMode("shutdown")}
        onConfirm={() => handleAction("shutdown")}
        onCancel={() => setConfirmMode(null)}
        confirmLabel="Confirm Shutdown"
        busyLabel="Shutting down..."
      />
    </div>
  );
}

function ActionCard({
  mode,
  title,
  description,
  iconPath,
  accent,
  confirming,
  busy,
  onStart,
  onConfirm,
  onCancel,
  confirmLabel,
  busyLabel,
}: {
  mode: Mode;
  title: string;
  description: string;
  iconPath: string;
  accent: "orange" | "red";
  confirming: boolean;
  busy: boolean;
  onStart: () => void;
  onConfirm: () => void;
  onCancel: () => void;
  confirmLabel: string;
  busyLabel: string;
}) {
  const colors = {
    orange: {
      bg: "bg-orange-500/15",
      icon: "text-orange-400",
      btn: "bg-orange-600 hover:bg-orange-700",
      warn: "text-orange-400",
    },
    red: {
      bg: "bg-red-500/15",
      icon: "text-red-400",
      btn: "bg-red-600 hover:bg-red-700",
      warn: "text-red-400",
    },
  }[accent];

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
      <div className="flex items-start gap-4">
        <div
          className={`w-10 h-10 rounded-lg ${colors.bg} flex items-center justify-center flex-shrink-0`}
        >
          <svg
            className={`w-5 h-5 ${colors.icon}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d={iconPath} />
          </svg>
        </div>
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <p className="text-xs text-gray-400 mt-1">{description}</p>
          <div className="mt-4">
            {!confirming ? (
              <button
                onClick={onStart}
                disabled={busy}
                className={`px-4 py-2 text-sm font-medium rounded-md ${colors.btn} text-white transition-colors disabled:opacity-50`}
              >
                {mode === "reboot" ? "Reboot Now" : "Shut Down Now"}
              </button>
            ) : (
              <div className="flex items-center gap-3">
                <span className={`text-xs ${colors.warn} font-medium`}>
                  Are you sure? This will interrupt all traffic.
                </span>
                <button
                  onClick={onConfirm}
                  disabled={busy}
                  className={`px-4 py-2 text-sm font-medium rounded-md ${colors.btn} text-white transition-colors disabled:opacity-50`}
                >
                  {busy ? busyLabel : confirmLabel}
                </button>
                <button
                  onClick={onCancel}
                  className="px-3 py-2 text-sm text-gray-400 hover:text-white"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
