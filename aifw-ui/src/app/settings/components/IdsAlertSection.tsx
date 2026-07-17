"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { IdsAlertStats } from "@/lib/api/settings";
import { inputCls, labelCls, sectionCls } from "./sectionStyles";

export interface IdsAlertSectionProps {
  visible: boolean;
  maxMb: number;
  setMaxMb: Dispatch<SetStateAction<number>>;
  maxAge: number;
  setMaxAge: Dispatch<SetStateAction<number>>;
  stats: IdsAlertStats | null;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function IdsAlertSection({
  visible,
  maxMb,
  setMaxMb,
  maxAge,
  setMaxAge,
  stats,
  saving,
  feedback,
  save,
}: IdsAlertSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-medium">IDS Alert Storage</h2>
          <p className="text-xs text-[var(--text-muted)]">In-memory alert buffer — no disk I/O</p>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Max Memory (MB)</label>
          <input type="number" value={maxMb}
            onChange={e => setMaxMb(Math.max(8, Math.min(512, parseInt(e.target.value) || 64)))}
            className={inputCls} min={8} max={512} />
          <p className="text-[10px] text-[var(--text-muted)] mt-1">8–512 MB. Each alert ≈ 512 bytes.</p>
        </div>
        <div>
          <label className={labelCls}>Max Age (hours)</label>
          <input type="number" value={Math.round(maxAge / 3600)}
            onChange={e => setMaxAge(Math.max(1, Math.min(168, parseInt(e.target.value) || 24)) * 3600)}
            className={inputCls} min={1} max={168} />
          <p className="text-[10px] text-[var(--text-muted)] mt-1">1–168 hours (7 days). Older alerts auto-evicted.</p>
        </div>
      </div>
      {stats && (
        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
          <div className="bg-[var(--bg-primary)] rounded-lg p-3">
            <div className="text-[10px] text-[var(--text-muted)] uppercase">Alerts</div>
            <div className="text-lg font-bold text-cyan-400">{stats.count.toLocaleString()}</div>
          </div>
          <div className="bg-[var(--bg-primary)] rounded-lg p-3">
            <div className="text-[10px] text-[var(--text-muted)] uppercase">Memory</div>
            <div className="text-lg font-bold text-blue-400">{stats.estimated_mb.toFixed(1)} MB</div>
          </div>
          <div className="bg-[var(--bg-primary)] rounded-lg p-3">
            <div className="text-[10px] text-[var(--text-muted)] uppercase">Usage</div>
            <div className="text-lg font-bold" style={{ color: stats.usage_pct > 80 ? "#ef4444" : "#22c55e" }}>
              {stats.usage_pct.toFixed(0)}%
            </div>
            <div className="w-full h-1 bg-gray-700 rounded-full mt-1">
              <div className="h-full rounded-full transition-all" style={{ width: `${stats.usage_pct}%`, backgroundColor: stats.usage_pct > 80 ? "#ef4444" : "#22c55e" }} />
            </div>
          </div>
          <div className="bg-[var(--bg-primary)] rounded-lg p-3">
            <div className="text-[10px] text-[var(--text-muted)] uppercase">Classifications</div>
            <div className="flex flex-wrap gap-1 mt-1 justify-center">
              {(stats.by_classification || []).map((c: { classification: string; count: number }) => (
                <span key={c.classification} className={`text-[9px] px-1.5 py-0.5 rounded ${
                  c.classification === "confirmed" ? "bg-red-500/15 text-red-400" :
                  c.classification === "false_positive" ? "bg-green-500/15 text-green-400" :
                  c.classification === "investigating" ? "bg-yellow-500/15 text-yellow-400" :
                  "bg-gray-700 text-gray-400"
                }`}>{c.classification}: {c.count}</span>
              ))}
            </div>
          </div>
        </div>
      )}
      <div className="flex items-center gap-3 mt-4">
        <button onClick={save} disabled={saving} className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 transition-colors">
          {saving ? "Saving..." : "Save"}
        </button>
        {feedback && (
          <span className={feedback.type === "success" ? "text-green-400 text-xs" : "text-red-400 text-xs"}>
            {feedback.msg}
          </span>
        )}
      </div>
    </section>
  );
}
