"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface ValkeySectionProps {
  visible: boolean;
  enabled: boolean;
  setEnabled: Dispatch<SetStateAction<boolean>>;
  url: string;
  setUrl: Dispatch<SetStateAction<string>>;
  retention: number;
  setRetention: Dispatch<SetStateAction<number>>;
  status: string;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function ValkeySection({
  visible,
  enabled,
  setEnabled,
  url,
  setUrl,
  retention,
  setRetention,
  status,
  loading,
  saving,
  feedback,
  save,
}: ValkeySectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-medium">Metrics Persistence (Valkey)</h2>
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
          status === "connected" ? "bg-green-500/20 text-green-400" :
          status === "disabled" ? "bg-gray-500/20 text-gray-400" :
          "bg-red-500/20 text-red-400"
        }`}>
          {status}
        </span>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        {loading ? (
          <p className="text-sm text-[var(--text-muted)]">Loading...</p>
        ) : (
          <>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="rounded border-[var(--border)]"
                />
                Enable Valkey persistence
              </label>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className={labelCls}>Valkey URL</label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className={inputCls}
                  disabled={!enabled}
                  placeholder="redis://127.0.0.1:6379"
                />
              </div>
              <div>
                <label className={labelCls}>Retention (minutes)</label>
                <input
                  type="number"
                  value={retention}
                  onChange={(e) => setRetention(Number(e.target.value))}
                  className={inputCls}
                  disabled={!enabled}
                  min={5}
                  max={1440}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  How many minutes of metrics to keep. Default: 30. Max: 1440 (24h).
                </p>
              </div>
            </div>

            <p className="text-xs text-[var(--text-muted)]">
              When enabled, metrics are persisted to Valkey so dashboard graphs survive API restarts.
              Without Valkey, graphs reset when the API restarts but still work via in-memory buffer.
            </p>
          </>
        )}

        <div className="flex justify-end">
          <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
            {saving ? "Saving..." : "Save Valkey"}
          </button>
        </div>
      </div>
    </section>
  );
}
