"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface BannerSectionProps {
  visible: boolean;
  loginBanner: string;
  setLoginBanner: Dispatch<SetStateAction<string>>;
  motd: string;
  setMotd: Dispatch<SetStateAction<string>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function BannerSection({
  visible,
  loginBanner,
  setLoginBanner,
  motd,
  setMotd,
  saving,
  feedback,
  save,
}: BannerSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <h2 className="font-medium mb-4">Login Banner &amp; MOTD</h2>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-[var(--text-muted)] mb-3">
        Banner shows before login (SSH / console). MOTD shows after login.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Login Banner (/etc/issue)</label>
          <textarea className={`${inputCls} font-mono`} rows={8} value={loginBanner} onChange={e => setLoginBanner(e.target.value)} />
        </div>
        <div>
          <label className={labelCls}>MOTD (/etc/motd.template)</label>
          <textarea className={`${inputCls} font-mono`} rows={8} value={motd} onChange={e => setMotd(e.target.value)} />
        </div>
      </div>
      <div className="flex justify-end mt-4">
        <button onClick={save} disabled={saving} className={saveBtnCls}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </section>
  );
}
