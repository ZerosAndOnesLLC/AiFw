"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface TlsPolicySectionProps {
  visible: boolean;
  minVersion: string;
  setMinVersion: Dispatch<SetStateAction<string>>;
  blockExpired: boolean;
  setBlockExpired: Dispatch<SetStateAction<boolean>>;
  blockWeakKeys: boolean;
  setBlockWeakKeys: Dispatch<SetStateAction<boolean>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function TlsPolicySection({
  visible,
  minVersion,
  setMinVersion,
  blockExpired,
  setBlockExpired,
  blockWeakKeys,
  setBlockWeakKeys,
  saving,
  feedback,
  save,
}: TlsPolicySectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">TLS Policy</h2>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        <div>
          <label className={labelCls}>Minimum TLS Version</label>
          <select
            value={minVersion}
            onChange={(e) => setMinVersion(e.target.value)}
            className={inputCls}
          >
            <option value="ssl30">SSLv3 (not recommended)</option>
            <option value="tls10">TLS 1.0 (deprecated)</option>
            <option value="tls11">TLS 1.1 (deprecated)</option>
            <option value="tls12">TLS 1.2 (recommended)</option>
            <option value="tls13">TLS 1.3 (strict)</option>
          </select>
        </div>
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={blockExpired}
              onChange={(e) => setBlockExpired(e.target.checked)}
              className="rounded border-[var(--border)]"
            />
            Block expired certificates
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={blockWeakKeys}
              onChange={(e) => setBlockWeakKeys(e.target.checked)}
              className="rounded border-[var(--border)]"
            />
            Block weak keys (&lt; 2048 bits)
          </label>
        </div>

        <div className="flex justify-end">
          <button onClick={save} disabled={saving} className={saveBtnCls}>
            {saving ? "Saving..." : "Save TLS"}
          </button>
        </div>
      </div>
    </section>
  );
}
