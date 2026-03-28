"use client";

import { useEffect, useState, useCallback } from "react";

interface Schedule {
  id: string;
  name: string;
  description?: string;
  time_ranges: string[];
  days_of_week?: string[];
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

interface ScheduleForm {
  name: string;
  description: string;
  time_ranges: string[];
  days_of_week: string[];
  enabled: boolean;
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

const defaultForm: ScheduleForm = {
  name: "",
  description: "",
  time_ranges: ["08:00-17:00"],
  days_of_week: [],
  enabled: true,
};

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("aifw_token");
      window.location.href = "/login";
    }
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<ScheduleForm>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fetchSchedules = useCallback(async () => {
    try {
      setError(null);
      const res = await apiFetch<{ data: Record<string, unknown>[] }>("/api/v1/schedules");
      // Normalize: API returns time_ranges/days_of_week as comma-separated strings
      const normalized: Schedule[] = (res.data || []).map((s) => ({
        ...s,
        time_ranges: Array.isArray(s.time_ranges) ? s.time_ranges as string[] : String(s.time_ranges || "").split(",").filter(Boolean),
        days_of_week: Array.isArray(s.days_of_week) ? s.days_of_week as string[] : String(s.days_of_week || "").split(",").filter(Boolean),
      } as Schedule));
      setSchedules(normalized);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch schedules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSchedules();
  }, [fetchSchedules]);

  const handleSubmit = async () => {
    if (submitting) return;
    if (!form.name.trim()) {
      setError("Name is required");
      return;
    }
    setSubmitting(true);
    setError(null);

    try {
      const body = {
        name: form.name.trim(),
        description: form.description.trim() || undefined,
        time_ranges: form.time_ranges.filter((r) => r.trim()),
        days_of_week: form.days_of_week.length > 0 ? form.days_of_week : undefined,
        enabled: form.enabled,
      };

      if (editingId) {
        await apiFetch(`/api/v1/schedules/${editingId}`, { method: "PUT", body: JSON.stringify(body) });
      } else {
        await apiFetch("/api/v1/schedules", { method: "POST", body: JSON.stringify(body) });
      }

      setForm(defaultForm);
      setEditingId(null);
      setShowModal(false);
      await fetchSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save schedule");
    } finally {
      setSubmitting(false);
    }
  };

  const handleEdit = (schedule: Schedule) => {
    setForm({
      name: schedule.name,
      description: schedule.description || "",
      time_ranges: schedule.time_ranges.length > 0 ? [...schedule.time_ranges] : ["08:00-17:00"],
      days_of_week: schedule.days_of_week ? [...schedule.days_of_week] : [],
      enabled: schedule.enabled,
    });
    setEditingId(schedule.id);
    setShowModal(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this schedule?")) return;
    setError(null);
    try {
      await apiFetch(`/api/v1/schedules/${id}`, { method: "DELETE" });
      await fetchSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete schedule");
    }
  };

  const handleToggleEnabled = async (schedule: Schedule) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/schedules/${schedule.id}`, {
        method: "PUT",
        body: JSON.stringify({
          name: schedule.name,
          description: schedule.description || undefined,
          time_ranges: schedule.time_ranges,
          days_of_week: schedule.days_of_week,
          enabled: !schedule.enabled,
        }),
      });
      await fetchSchedules();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle schedule");
    }
  };

  const handleCancel = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowModal(false);
  };

  const addTimeRange = () => {
    setForm((f) => ({ ...f, time_ranges: [...f.time_ranges, ""] }));
  };

  const removeTimeRange = (idx: number) => {
    setForm((f) => ({
      ...f,
      time_ranges: f.time_ranges.filter((_, i) => i !== idx),
    }));
  };

  const updateTimeRange = (idx: number, value: string) => {
    setForm((f) => ({
      ...f,
      time_ranges: f.time_ranges.map((r, i) => (i === idx ? value : r)),
    }));
  };

  const toggleDay = (day: string) => {
    setForm((f) => ({
      ...f,
      days_of_week: f.days_of_week.includes(day)
        ? f.days_of_week.filter((d) => d !== day)
        : [...f.days_of_week, day],
    }));
  };

  const inputClass =
    "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
  const labelClass = "block text-xs font-medium text-gray-400 mb-1";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Schedules</h1>
          <p className="text-sm text-gray-400">
            {schedules.length} schedule{schedules.length !== 1 ? "s" : ""}
          </p>
        </div>
        <button
          onClick={() => {
            setForm(defaultForm);
            setEditingId(null);
            setShowModal(true);
          }}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Schedule
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* ─── Schedules Table ───────────────────────────────────────── */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        {loading ? (
          <div className="text-center py-12 text-gray-400">Loading schedules...</div>
        ) : schedules.length === 0 ? (
          <div className="text-center py-12 text-gray-400">No schedules configured</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 bg-gray-800/80">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">Name</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">Time Ranges</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">Days</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Enabled</th>
                  <th className="text-right py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Actions</th>
                </tr>
              </thead>
              <tbody>
                {schedules.map((schedule) => (
                  <tr
                    key={schedule.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="py-3 px-4">
                      <div>
                        <span className="text-white font-medium">{schedule.name}</span>
                        {schedule.description && (
                          <p className="text-xs text-gray-500 mt-0.5">{schedule.description}</p>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {schedule.time_ranges.map((range, i) => (
                          <span
                            key={i}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-700 text-gray-300"
                          >
                            {range}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex gap-1">
                        {DAYS.map((day) => {
                          const isActive = schedule.days_of_week?.includes(day);
                          return (
                            <span
                              key={day}
                              className={`inline-flex items-center justify-center w-7 h-6 rounded text-[10px] font-medium ${
                                isActive
                                  ? "bg-blue-600/30 text-blue-400 border border-blue-500/30"
                                  : "bg-gray-700/50 text-gray-600 border border-gray-700"
                              }`}
                            >
                              {day.charAt(0)}
                            </span>
                          );
                        })}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleToggleEnabled(schedule)}
                        className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                        style={{ backgroundColor: schedule.enabled ? "#22c55e" : "#4b5563" }}
                        title={schedule.enabled ? "Disable schedule" : "Enable schedule"}
                      >
                        <span
                          className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                          style={{ transform: schedule.enabled ? "translateX(16px)" : "translateX(0)" }}
                        />
                      </button>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handleEdit(schedule)}
                          className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
                          title="Edit schedule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleDelete(schedule.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700"
                          title="Delete schedule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ─── Modal Overlay ─────────────────────────────────────────── */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-sm"
            onClick={handleCancel}
          />
          {/* Modal content */}
          <div className="relative w-full max-w-lg max-h-[90vh] overflow-y-auto bg-gray-800 border border-gray-700 rounded-xl shadow-2xl m-4">
            <div className="sticky top-0 bg-gray-800 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
              <h3 className="text-lg font-semibold text-white">
                {editingId ? "Edit Schedule" : "Add Schedule"}
              </h3>
              <button
                onClick={handleCancel}
                className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 space-y-5">
              {/* Name */}
              <div>
                <label className={labelClass}>Name *</label>
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="Business Hours"
                  className={inputClass}
                />
              </div>

              {/* Description */}
              <div>
                <label className={labelClass}>Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="Optional description"
                  className={inputClass}
                />
              </div>

              {/* Time Ranges */}
              <div>
                <label className={labelClass}>Time Ranges</label>
                <div className="space-y-2">
                  {form.time_ranges.map((range, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <input
                        type="text"
                        value={range}
                        onChange={(e) => updateTimeRange(idx, e.target.value)}
                        placeholder="08:00-17:00"
                        className={inputClass}
                      />
                      {form.time_ranges.length > 1 && (
                        <button
                          onClick={() => removeTimeRange(idx)}
                          className="p-2 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700 flex-shrink-0"
                          title="Remove time range"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    onClick={addTimeRange}
                    className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                    </svg>
                    Add time range
                  </button>
                </div>
              </div>

              {/* Days of Week */}
              <div>
                <label className={labelClass}>Days of Week</label>
                <div className="flex gap-2 flex-wrap">
                  {DAYS.map((day) => {
                    const isActive = form.days_of_week.includes(day);
                    return (
                      <button
                        key={day}
                        onClick={() => toggleDay(day)}
                        className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors border ${
                          isActive
                            ? "bg-blue-600 text-white border-blue-500"
                            : "bg-gray-900 text-gray-400 border-gray-700 hover:border-gray-600 hover:text-gray-300"
                        }`}
                      >
                        {day}
                      </button>
                    );
                  })}
                </div>
                <p className="text-[10px] text-gray-500 mt-1">Leave empty for all days</p>
              </div>

              {/* Enabled */}
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setForm((f) => ({ ...f, enabled: !f.enabled }))}
                  className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                  style={{ backgroundColor: form.enabled ? "#22c55e" : "#4b5563" }}
                >
                  <span
                    className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                    style={{ transform: form.enabled ? "translateX(16px)" : "translateX(0)" }}
                  />
                </button>
                <span className="text-sm text-gray-300">Enabled</span>
              </div>
            </div>

            {/* Modal footer */}
            <div className="sticky bottom-0 bg-gray-800 border-t border-gray-700 px-6 py-4 flex items-center justify-end gap-3">
              <button
                onClick={handleCancel}
                className="px-4 py-2 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="px-5 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
              >
                {submitting ? "Saving..." : editingId ? "Save Changes" : "Add Schedule"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
