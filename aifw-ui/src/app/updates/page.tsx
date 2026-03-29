"use client";

import { useState, useEffect, useCallback } from "react";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

interface UpdateStatus {
  os_version: string;
  last_check: string;
  pending_os_updates: boolean;
  pending_pkg_count: number;
  pending_packages: string[];
  needs_reboot: boolean;
  checking: boolean;
  installing: boolean;
}

interface MaintenanceWindow {
  enabled: boolean;
  day_of_week: string;
  time: string;
  auto_install: boolean;
  auto_reboot: boolean;
  auto_check: boolean;
  auto_update_aifw?: boolean;
}

interface UpdateHistoryEntry {
  id: string;
  action: string;
  details: string;
  status: string;
  created_at: string;
}

interface AifwUpdateInfo {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_notes: string;
  published_at: string;
  tarball_url: string | null;
  checksum_url: string | null;
  has_backup: boolean;
  backup_version: string | null;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export default function UpdatesPage() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [schedule, setSchedule] = useState<MaintenanceWindow>({
    enabled: false,
    day_of_week: "Sunday",
    time: "03:00",
    auto_install: false,
    auto_reboot: false,
    auto_check: true,
  });
  const [history, setHistory] = useState<UpdateHistoryEntry[]>([]);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [pkgsExpanded, setPkgsExpanded] = useState(false);
  const [rebootConfirm, setRebootConfirm] = useState(false);
  const [loading, setLoading] = useState(true);

  // AiFw firmware update state
  const [aifwInfo, setAifwInfo] = useState<AifwUpdateInfo | null>(null);
  const [aifwChecking, setAifwChecking] = useState(false);
  const [aifwInstalling, setAifwInstalling] = useState(false);
  const [aifwRollingBack, setAifwRollingBack] = useState(false);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/updates/status", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: UpdateStatus = await res.json();
      setStatus(data);
      if (data.checking) setChecking(true);
      else setChecking(false);
      if (data.installing) setInstalling(true);
      else setInstalling(false);
    } catch {
      // silent on status poll
    }
  }, []);

  const fetchSchedule = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/updates/schedule", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: MaintenanceWindow = await res.json();
      setSchedule(data);
    } catch {
      // use defaults
    }
  }, []);

  const fetchAifwStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/updates/aifw/status", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: AifwUpdateInfo = await res.json();
      setAifwInfo(data);
    } catch {
      // silent
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/updates/history", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHistory((data.data || []).slice(0, 50));
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    Promise.all([fetchStatus(), fetchSchedule(), fetchHistory(), fetchAifwStatus()]).finally(() => setLoading(false));
  }, [fetchStatus, fetchSchedule, fetchHistory, fetchAifwStatus]);

  // Poll status while checking or installing
  useEffect(() => {
    if (!checking && !installing) return;
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, [checking, installing, fetchStatus]);

  const handleCheck = async () => {
    setChecking(true);
    try {
      const res = await fetch("/api/v1/updates/check", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Update check complete");
      setChecking(false);
      fetchStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to check for updates");
      setChecking(false);
    }
  };

  const handleInstall = async () => {
    setInstalling(true);
    try {
      const res = await fetch("/api/v1/updates/install", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Updates installed");
      setInstalling(false);
      fetchStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to install updates");
      setInstalling(false);
    }
  };

  const handleReboot = async () => {
    setRebooting(true);
    setRebootConfirm(false);
    try {
      const res = await fetch("/api/v1/updates/reboot", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Reboot scheduled");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to schedule reboot");
    } finally {
      setRebooting(false);
    }
  };

  const handleSaveSchedule = async () => {
    setSavingSchedule(true);
    try {
      const res = await fetch("/api/v1/updates/schedule", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(schedule),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Maintenance window saved");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save schedule");
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleAifwCheck = async () => {
    setAifwChecking(true);
    try {
      const res = await fetch("/api/v1/updates/aifw/check", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: AifwUpdateInfo = await res.json();
      setAifwInfo(data);
      showFeedback("success", data.update_available
        ? `AiFw v${data.latest_version} is available`
        : `AiFw v${data.current_version} is the latest`);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to check for AiFw updates");
    } finally {
      setAifwChecking(false);
    }
  };

  const handleAifwInstall = async () => {
    setAifwInstalling(true);
    try {
      const res = await fetch("/api/v1/updates/aifw/install", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "AiFw updated");
      fetchAifwStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to install AiFw update");
    } finally {
      setAifwInstalling(false);
    }
  };

  const handleAifwRollback = async () => {
    setAifwRollingBack(true);
    try {
      const res = await fetch("/api/v1/updates/aifw/rollback", { method: "POST", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "AiFw rolled back");
      fetchAifwStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to rollback AiFw");
    } finally {
      setAifwRollingBack(false);
    }
  };

  const statusBadgeColor = (s: string) => {
    switch (s.toLowerCase()) {
      case "success":
      case "completed":
        return "bg-green-500/15 text-green-400 border-green-500/30";
      case "failed":
      case "error":
        return "bg-red-500/15 text-red-400 border-red-500/30";
      case "running":
      case "in_progress":
        return "bg-blue-500/15 text-blue-400 border-blue-500/30";
      default:
        return "bg-gray-500/15 text-gray-400 border-gray-500/30";
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold">System Updates</h1>
        <p className="text-sm text-[var(--text-muted)]">Manage AiFw firmware, operating system, and package updates</p>
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

      {/* AiFw Firmware Card */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="space-y-2">
            <div>
              <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">AiFw Firmware</span>
              <p className="text-xl font-semibold text-[var(--text-primary)]">
                v{aifwInfo?.current_version || "unknown"}
              </p>
            </div>
            {aifwInfo?.latest_version && (
              <div className="text-xs text-[var(--text-muted)]">
                Latest: v{aifwInfo.latest_version}
                {aifwInfo.published_at && ` (${new Date(aifwInfo.published_at).toLocaleDateString()})`}
              </div>
            )}
            <div className="flex flex-wrap gap-2 pt-1">
              {aifwInfo?.update_available ? (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400 border border-yellow-500/30">
                  v{aifwInfo.latest_version} available
                </span>
              ) : aifwInfo?.latest_version ? (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                  Up to date
                </span>
              ) : null}
              {aifwInfo?.has_backup && (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-500/15 text-gray-400 border border-gray-500/30">
                  Backup: v{aifwInfo.backup_version}
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap gap-2 sm:flex-col sm:items-end">
            <button
              onClick={handleAifwCheck}
              disabled={aifwChecking}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              {aifwChecking && (
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              )}
              {aifwChecking ? "Checking..." : "Check for Update"}
            </button>

            {aifwInfo?.update_available && aifwInfo?.tarball_url && (
              <button
                onClick={handleAifwInstall}
                disabled={aifwInstalling}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
              >
                {aifwInstalling && (
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                )}
                {aifwInstalling ? "Installing..." : `Update to v${aifwInfo.latest_version}`}
              </button>
            )}

            {aifwInfo?.has_backup && (
              <button
                onClick={handleAifwRollback}
                disabled={aifwRollingBack}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
              >
                {aifwRollingBack ? "Rolling back..." : `Rollback to v${aifwInfo.backup_version}`}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* OS Status Card */}
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
              onClick={handleCheck}
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
                onClick={handleInstall}
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
                onClick={() => setRebootConfirm(true)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
              >
                Reboot
              </button>
            )}

            {rebootConfirm && (
              <div className="flex items-center gap-2">
                <button
                  onClick={handleReboot}
                  disabled={rebooting}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
                >
                  {rebooting ? "Rebooting..." : "Confirm Reboot"}
                </button>
                <button
                  onClick={() => setRebootConfirm(false)}
                  className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Pending Packages */}
      {status && status.pending_pkg_count > 0 && status.pending_packages.length > 0 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          <button
            onClick={() => setPkgsExpanded(!pkgsExpanded)}
            className="w-full flex items-center justify-between p-4 text-left hover:bg-[var(--bg-secondary)] transition-colors rounded-lg"
          >
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">Pending Packages</h2>
              <span className="text-xs text-[var(--text-muted)]">({status.pending_pkg_count})</span>
            </div>
            <svg
              className={`w-4 h-4 text-[var(--text-muted)] transition-transform duration-200 ${pkgsExpanded ? "rotate-180" : ""}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {pkgsExpanded && (
            <div className="px-4 pb-4 border-t border-[var(--border)]">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1 pt-3">
                {status.pending_packages.map((pkg) => (
                  <div
                    key={pkg}
                    className="text-xs text-[var(--text-secondary)] font-mono bg-[var(--bg-secondary)] rounded px-2 py-1"
                  >
                    {pkg}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Maintenance Window */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-1">Maintenance Window</h2>
        <p className="text-sm text-[var(--text-muted)] mb-4">
          Configure an automatic maintenance window. When enabled, the system will check for and optionally install updates on the scheduled day and time.
        </p>

        <div className="space-y-4">
          {/* Enable Toggle */}
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">Enable maintenance window</label>
            <button
              onClick={() => setSchedule({ ...schedule, enabled: !schedule.enabled })}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                schedule.enabled ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  schedule.enabled ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {schedule.enabled && (
            <>
              {/* Day + Time */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Day of Week</label>
                  <select
                    value={schedule.day_of_week}
                    onChange={(e) => setSchedule({ ...schedule, day_of_week: e.target.value })}
                    className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                  >
                    {DAYS.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Time (HH:MM)</label>
                  <input
                    type="time"
                    value={schedule.time}
                    onChange={(e) => setSchedule({ ...schedule, time: e.target.value })}
                    className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>

              {/* Checkboxes */}
              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={schedule.auto_check}
                    onChange={(e) => setSchedule({ ...schedule, auto_check: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <span className="text-sm text-[var(--text-secondary)]">Auto check for updates</span>
                    <p className="text-xs text-[var(--text-muted)]">Automatically check for available updates at the scheduled time</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={schedule.auto_install}
                    onChange={(e) => setSchedule({ ...schedule, auto_install: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <span className="text-sm text-[var(--text-secondary)]">Auto install updates</span>
                    <p className="text-xs text-[var(--text-muted)]">Automatically install all pending updates after checking</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={schedule.auto_update_aifw ?? false}
                    onChange={(e) => setSchedule({ ...schedule, auto_update_aifw: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <span className="text-sm text-[var(--text-secondary)]">Auto update AiFw firmware</span>
                    <p className="text-xs text-[var(--text-muted)]">Automatically check and install AiFw firmware updates from GitHub</p>
                  </div>
                </label>

                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={schedule.auto_reboot}
                    onChange={(e) => setSchedule({ ...schedule, auto_reboot: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <div>
                    <span className="text-sm text-[var(--text-secondary)]">Auto reboot after install</span>
                    <p className="text-xs text-[var(--text-muted)]">Automatically reboot the system if required after installing updates</p>
                  </div>
                </label>
              </div>
            </>
          )}

          <button
            onClick={handleSaveSchedule}
            disabled={savingSchedule}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
          >
            {savingSchedule ? "Saving..." : "Save Schedule"}
          </button>
        </div>
      </div>

      {/* Update History */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold">Update History</h2>
          <p className="text-xs text-[var(--text-muted)]">Last 50 update operations</p>
        </div>

        {history.length === 0 ? (
          <div className="p-8 text-center text-sm text-[var(--text-muted)]">No update history yet</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border)]">
                  <th className="text-left px-4 py-3 font-medium">Action</th>
                  <th className="text-left px-4 py-3 font-medium">Details</th>
                  <th className="text-left px-4 py-3 font-medium">Status</th>
                  <th className="text-left px-4 py-3 font-medium">Date</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry) => (
                  <tr
                    key={entry.id}
                    className="border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-secondary)] transition-colors"
                  >
                    <td className="px-4 py-3 text-[var(--text-primary)] font-medium whitespace-nowrap">
                      {entry.action}
                    </td>
                    <td className="px-4 py-3 text-[var(--text-secondary)] max-w-xs truncate">
                      {entry.details}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${statusBadgeColor(entry.status)}`}
                      >
                        {entry.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[var(--text-muted)] whitespace-nowrap text-xs">
                      {new Date(entry.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
