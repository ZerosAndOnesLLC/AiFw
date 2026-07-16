"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface ApiServerSectionProps {
  visible: boolean;
  port: string;
  setPort: Dispatch<SetStateAction<string>>;
  corsOrigins: string;
  setCorsOrigins: Dispatch<SetStateAction<string>>;
  jwtSecret: string;
  setJwtSecret: Dispatch<SetStateAction<string>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function ApiServerSection({
  visible,
  port,
  setPort,
  corsOrigins,
  setCorsOrigins,
  jwtSecret,
  setJwtSecret,
  saving,
  feedback,
  save,
}: ApiServerSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">API Server</h2>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>Listen Port</label>
            <input
              type="text"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>CORS Origins</label>
            <input
              type="text"
              value={corsOrigins}
              onChange={(e) => setCorsOrigins(e.target.value)}
              className={inputCls}
            />
          </div>
        </div>
        <div>
          <label className={labelCls}>JWT Secret</label>
          <input
            type="password"
            value={jwtSecret}
            onChange={(e) => setJwtSecret(e.target.value)}
            className={inputCls}
          />
        </div>

        <div className="flex justify-end">
          <button onClick={save} disabled={saving} className={saveBtnCls}>
            {saving ? "Saving..." : "Save API"}
          </button>
        </div>
      </div>
    </section>
  );
}
