"use client";

import { useState } from "react";

export default function RebootPage() {
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  const handleReboot = async () => {
    setRebooting(true);
    setFeedback(null);
    try {
      const token = localStorage.getItem("aifw_token") || "";
      const res = await fetch("/api/v1/updates/reboot", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json().catch(() => ({}));
      setFeedback({ type: "success", msg: data.message || "System rebooting in 10 seconds..." });
      setConfirmReboot(false);
    } catch {
      setFeedback({ type: "error", msg: "Failed to initiate reboot" });
    } finally {
      setRebooting(false);
    }
  };

  return (
    <div className="max-w-xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">System Reboot</h1>
        <p className="text-sm text-gray-400 mt-1">
          Restart the AiFw firewall appliance. All active connections will be dropped during reboot.
          Firewall rules, NAT, and services will be restored automatically on boot.
        </p>
      </div>

      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success"
            ? "bg-green-500/10 border-green-500/30 text-green-400"
            : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>
          {feedback.msg}
        </div>
      )}

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-red-500/15 flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </div>
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-white">Reboot System</h3>
            <p className="text-xs text-gray-400 mt-1">
              The system will reboot in 10 seconds after confirmation. SSH connections will be terminated.
              The web UI will become available again once the system has fully booted.
            </p>
            <div className="mt-4">
              {!confirmReboot ? (
                <button
                  onClick={() => setConfirmReboot(true)}
                  className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
                >
                  Reboot Now
                </button>
              ) : (
                <div className="flex items-center gap-3">
                  <span className="text-xs text-red-400 font-medium">Are you sure? This will interrupt all traffic.</span>
                  <button
                    onClick={handleReboot}
                    disabled={rebooting}
                    className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors disabled:opacity-50"
                  >
                    {rebooting ? "Rebooting..." : "Confirm Reboot"}
                  </button>
                  <button
                    onClick={() => setConfirmReboot(false)}
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
    </div>
  );
}
