"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface ConfigHistorySectionProps {
  visible: boolean;
  maxVersions: number;
  setMaxVersions: Dispatch<SetStateAction<number>>;
  currentCount: number;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function ConfigHistorySection({
  visible,
  maxVersions,
  setMaxVersions,
  currentCount,
  loading,
  saving,
  feedback,
  save,
}: ConfigHistorySectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">Config History</h2>
        <span className="text-xs text-[var(--text-muted)]">
          {loading ? "Loading…" : `${currentCount.toLocaleString()} versions stored`}
        </span>
      </div>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-[var(--text-muted)] mb-3">
        Every successful change (rules, NAT, VPN, DNS, firewall settings, etc.) is
        auto-versioned. You can restore, diff, or compare any of the retained versions
        from the <a className="text-blue-400 underline" href="/backup">Backup</a> page.
        Oldest versions are pruned when this limit is exceeded; the currently-applied
        version is always kept even if it falls outside the window.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Maximum versions to keep</label>
          <input
            type="number"
            min={5}
            max={10000}
            value={maxVersions}
            onChange={(e) => setMaxVersions(Math.max(5, Math.min(10000, Number(e.target.value) || 0)))}
            className={inputCls}
          />
          <p className="text-xs text-[var(--text-muted)] mt-1">Range: 5–10000. Default 200.</p>
        </div>
      </div>
      <div className="flex justify-end mt-4">
        <button
          onClick={save}
          disabled={saving || loading}
          className={saveBtnCls}
        >
          {saving ? "Saving..." : "Save Retention"}
        </button>
      </div>
    </section>
  );
}
