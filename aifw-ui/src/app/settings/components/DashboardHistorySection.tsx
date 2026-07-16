"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { HistoryMode } from "@/lib/api/settings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface DashboardHistorySectionProps {
  visible: boolean;
  mode: HistoryMode;
  setMode: Dispatch<SetStateAction<HistoryMode>>;
  minutes: number;
  setMinutes: Dispatch<SetStateAction<number>>;
  ramMb: number;
  setRamMb: Dispatch<SetStateAction<number>>;
  entries: number;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function DashboardHistorySection({
  visible,
  mode,
  setMode,
  minutes,
  setMinutes,
  ramMb,
  setRamMb,
  entries,
  loading,
  saving,
  feedback,
  save,
}: DashboardHistorySectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">Dashboard History</h2>
        <span className="text-xs text-[var(--text-muted)] font-mono">
          {entries.toLocaleString()} entries buffered
        </span>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        {loading ? (
          <p className="text-sm text-[var(--text-muted)]">Loading...</p>
        ) : (
          <>
            {/* Mode toggle */}
            <div>
              <label className={labelCls}>Limit by</label>
              <div className="flex gap-1 bg-[var(--bg-primary)] rounded-lg p-1 border border-[var(--border)] w-fit">
                {(["duration", "ram"] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all ${
                      mode === m
                        ? "bg-[var(--accent)] text-white"
                        : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    {m === "duration" ? "Duration" : "RAM Budget"}
                  </button>
                ))}
              </div>
            </div>

            {/* Duration input */}
            {mode === "duration" && (
              <div>
                <label className={labelCls}>History Duration (minutes)</label>
                <input
                  type="number"
                  value={minutes}
                  onChange={(e) => setMinutes(Math.max(5, Number(e.target.value)))}
                  className={inputCls}
                  min={5}
                  max={43200}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  How many minutes of dashboard metrics to keep. Default: 30 min. Max: 43,200 (30 days).
                </p>
              </div>
            )}

            {/* RAM budget input */}
            {mode === "ram" && (
              <div>
                <label className={labelCls}>RAM Budget (MB)</label>
                <input
                  type="number"
                  value={ramMb}
                  onChange={(e) => setRamMb(Math.max(1, Number(e.target.value)))}
                  className={inputCls}
                  min={1}
                  max={8192}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Maximum RAM to use for dashboard history. The system calculates how much history fits.
                  Each entry is ~2 KB. Example: 1024 MB = ~6 days of history.
                </p>
              </div>
            )}

            {/* Summary */}
            <div className="flex items-center gap-4 p-3 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md">
              <div className="flex-1 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <span className="text-[var(--text-muted)] uppercase tracking-wider">Duration</span>
                  <p className="font-mono mt-0.5">
                    {(() => {
                      const mins = mode === "ram"
                        ? Math.round((ramMb * 1024 * 1024) / 2048 / 60)
                        : minutes;
                      return mins < 60
                        ? `${mins} min`
                        : mins < 1440
                        ? `${(mins / 60).toFixed(1)} hours`
                        : `${(mins / 1440).toFixed(1)} days`;
                    })()}
                  </p>
                </div>
                <div>
                  <span className="text-[var(--text-muted)] uppercase tracking-wider">Entries</span>
                  <p className="font-mono mt-0.5">
                    {(() => {
                      const calcEntries = mode === "ram"
                        ? Math.round((ramMb * 1024 * 1024) / 2048)
                        : minutes * 60;
                      return calcEntries.toLocaleString();
                    })()}
                  </p>
                </div>
                <div>
                  <span className="text-[var(--text-muted)] uppercase tracking-wider">Est. RAM</span>
                  <p className="font-mono mt-0.5">
                    {(() => {
                      const mb = mode === "ram"
                        ? ramMb
                        : (minutes * 60 * 2) / 1024;
                      return mb < 1
                        ? `${Math.round(mb * 1024)} KB`
                        : mb >= 1024
                        ? `${(mb / 1024).toFixed(2)} GB`
                        : `${mb.toFixed(1)} MB`;
                    })()}
                  </p>
                </div>
              </div>
            </div>
          </>
        )}

        <div className="flex justify-end">
          <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
            {saving ? "Saving..." : "Save History"}
          </button>
        </div>
      </div>
    </section>
  );
}
