"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface DnsSectionProps {
  visible: boolean;
  servers: string[];
  newDns: string;
  setNewDns: Dispatch<SetStateAction<string>>;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  addServer: () => void;
  removeServer: (index: number) => void;
  save: () => void;
}

export function DnsSection({
  visible,
  servers,
  newDns,
  setNewDns,
  loading,
  saving,
  feedback,
  addServer,
  removeServer,
  save,
}: DnsSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">DNS Configuration</h2>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        <div>
          <label className={labelCls}>Nameservers</label>
          {loading ? (
            <p className="text-sm text-[var(--text-muted)]">Loading...</p>
          ) : servers.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">No DNS servers configured.</p>
          ) : (
            <ul className="space-y-2">
              {servers.map((server, idx) => (
                <li
                  key={idx}
                  className="flex items-center justify-between bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2"
                >
                  <span className="font-mono text-sm">{server}</span>
                  <button
                    onClick={() => removeServer(idx)}
                    className="text-red-400 hover:text-red-300 transition-colors text-sm font-bold px-2"
                    title="Remove server"
                  >
                    X
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={newDns}
            onChange={(e) => setNewDns(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addServer();
              }
            }}
            placeholder="e.g. 8.8.8.8"
            className={`${inputCls} font-mono`}
          />
          <button
            onClick={addServer}
            className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-bold transition-colors flex-shrink-0"
            title="Add server"
          >
            +
          </button>
        </div>

        <div className="flex justify-end">
          <button onClick={save} disabled={saving} className={saveBtnCls}>
            {saving ? "Saving..." : "Save DNS"}
          </button>
        </div>
      </div>
    </section>
  );
}
