"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface MetricsSectionProps {
  visible: boolean;
  backend: string;
  setBackend: Dispatch<SetStateAction<string>>;
  postgresUrl: string;
  setPostgresUrl: Dispatch<SetStateAction<string>>;
  collectionInterval: string;
  setCollectionInterval: Dispatch<SetStateAction<string>>;
  retentionDays: string;
  setRetentionDays: Dispatch<SetStateAction<string>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function MetricsSection({
  visible,
  backend,
  setBackend,
  postgresUrl,
  setPostgresUrl,
  collectionInterval,
  setCollectionInterval,
  retentionDays,
  setRetentionDays,
  saving,
  feedback,
  save,
}: MetricsSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">Metrics Storage</h2>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        <div>
          <label className={labelCls}>Backend</label>
          <select
            value={backend}
            onChange={(e) => setBackend(e.target.value)}
            className={inputCls}
          >
            <option value="local">Local (In-Memory RRD + SQLite)</option>
            <option value="postgres">PostgreSQL</option>
          </select>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Local: ring buffers with 4-tier consolidation. Postgres: full time-series with configurable retention.
          </p>
        </div>

        {backend === "postgres" && (
          <div>
            <label className={labelCls}>PostgreSQL URL</label>
            <input
              type="text"
              value={postgresUrl}
              onChange={(e) => setPostgresUrl(e.target.value)}
              placeholder="postgresql://user:pass@host:5432/aifw_metrics"
              className={`${inputCls} font-mono`}
            />
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>Collection Interval (sec)</label>
            <input
              type="number"
              value={collectionInterval}
              onChange={(e) => setCollectionInterval(e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Retention (days)</label>
            <input
              type="number"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              className={inputCls}
            />
          </div>
        </div>

        <div className="flex justify-end">
          <button onClick={save} disabled={saving} className={saveBtnCls}>
            {saving ? "Saving..." : "Save Metrics"}
          </button>
        </div>
      </div>
    </section>
  );
}
