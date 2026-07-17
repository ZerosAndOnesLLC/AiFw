"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface PfStateTableSectionProps {
  visible: boolean;
  maxStates: number;
  setMaxStates: Dispatch<SetStateAction<number>>;
  configured: number;
  live: number | null;
  current: number;
  min: number;
  max: number;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function PfStateTableSection({
  visible,
  maxStates,
  setMaxStates,
  configured,
  live,
  current,
  min,
  max,
  loading,
  saving,
  feedback,
  save,
}: PfStateTableSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">pf State Table</h2>
        <span className="text-xs text-[var(--text-muted)]">
          {loading ? "Loading…" :
            `${current.toLocaleString()} active / ${(live ?? configured).toLocaleString()} max (${
              live ? Math.round((current / live) * 100) : 0
            }%)`}
        </span>
      </div>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-[var(--text-muted)] mb-3">
        pf tracks every connection in the state table. The default cap is 100,000;
        high-throughput appliances or NAT-heavy workloads (lots of short-lived
        connections) can exhaust it, after which pf drops new states until old ones
        expire. Raise the limit if <code>pfctl -ss | wc -l</code> approaches the cap.
        Memory cost is roughly 300 bytes per state — 1M states ≈ 300 MB of wired RAM.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Maximum states</label>
          <input
            type="number"
            min={min}
            max={max}
            step={1000}
            value={maxStates}
            onChange={(e) => setMaxStates(Math.max(min, Math.min(max, Number(e.target.value) || 0)))}
            className={inputCls}
          />
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Range: {min.toLocaleString()}–{max.toLocaleString()}.
          </p>
        </div>
        <div>
          <label className={labelCls}>Live limit</label>
          <div className={`${inputCls} font-mono`}>{live !== null ? live.toLocaleString() : "(pf unavailable)"}</div>
          {live !== null && live !== configured && (
            <p className="text-xs text-yellow-300 mt-1">
              ⚠ Live limit doesn&apos;t match configured ({configured.toLocaleString()}). Click save to re-apply.
            </p>
          )}
        </div>
      </div>
      <div className="flex justify-end mt-4">
        <button
          onClick={save}
          disabled={saving || loading}
          className={saveBtnCls}
        >
          {saving ? "Applying…" : "Apply (no rule reload)"}
        </button>
      </div>
    </section>
  );
}
