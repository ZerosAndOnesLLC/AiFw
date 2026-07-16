"use client";

import { MaintenanceWindow } from "@/lib/api/updates";

const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

interface MaintenanceWindowCardProps {
  schedule: MaintenanceWindow;
  saving: boolean;
  onChange: (schedule: MaintenanceWindow) => void;
  onSave: () => void;
}

export function MaintenanceWindowCard({ schedule, saving, onChange, onSave }: MaintenanceWindowCardProps) {
  return (
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
            onClick={() => onChange({ ...schedule, enabled: !schedule.enabled })}
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
                  onChange={(e) => onChange({ ...schedule, day_of_week: e.target.value })}
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
                  onChange={(e) => onChange({ ...schedule, time: e.target.value })}
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
                  onChange={(e) => onChange({ ...schedule, auto_check: e.target.checked })}
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
                  onChange={(e) => onChange({ ...schedule, auto_install: e.target.checked })}
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
                  onChange={(e) => onChange({ ...schedule, auto_update_aifw: e.target.checked })}
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
                  onChange={(e) => onChange({ ...schedule, auto_reboot: e.target.checked })}
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
          onClick={onSave}
          disabled={saving}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
        >
          {saving ? "Saving..." : "Save Schedule"}
        </button>
      </div>
    </div>
  );
}
