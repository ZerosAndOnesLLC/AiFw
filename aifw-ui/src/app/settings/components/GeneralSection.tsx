"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface GeneralSectionProps {
  visible: boolean;
  hostname: string;
  setHostname: Dispatch<SetStateAction<string>>;
  domain: string;
  setDomain: Dispatch<SetStateAction<string>>;
  timezone: string;
  setTimezone: Dispatch<SetStateAction<string>>;
  timezoneList: string[];
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function GeneralSection({
  visible,
  hostname,
  setHostname,
  domain,
  setDomain,
  timezone,
  setTimezone,
  timezoneList,
  saving,
  feedback,
  save,
}: GeneralSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">General</h2>
        <a href="/system/info" className="text-xs text-[var(--accent)] hover:underline">View live system info →</a>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className={labelCls}>Hostname</label>
          <input className={inputCls} value={hostname} onChange={e => setHostname(e.target.value)} />
        </div>
        <div>
          <label className={labelCls}>Domain</label>
          <input className={inputCls} value={domain} onChange={e => setDomain(e.target.value)} placeholder="home.lan" />
        </div>
        <div>
          <label className={labelCls}>Timezone</label>
          <input
            list="tz-list"
            className={inputCls}
            value={timezone}
            onChange={e => setTimezone(e.target.value)}
          />
          <datalist id="tz-list">
            {timezoneList.map(tz => <option key={tz} value={tz} />)}
          </datalist>
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
