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
  trustedProxies: string;
  setTrustedProxies: Dispatch<SetStateAction<string>>;
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
  trustedProxies,
  setTrustedProxies,
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
          <label className={labelCls}>Trusted Proxies</label>
          <input
            type="text"
            value={trustedProxies}
            onChange={(e) => setTrustedProxies(e.target.value)}
            placeholder="e.g. 10.0.0.5, 192.168.10.0/24 — empty = none"
            className={inputCls}
          />
          <p className="text-[11px] text-[var(--text-muted)] mt-1">
            Only when a request arrives from one of these addresses is its
            <code className="mx-1">X-Forwarded-For</code>header used as the client IP
            (login / refresh rate limiting, plugin hooks). Leave empty unless AiFw sits
            behind your own reverse proxy or load balancer. Applied at the next API restart;
            <code className="mx-1">--trusted-proxies</code>/
            <code className="mx-1">AIFW_TRUSTED_PROXIES</code>are merged in.
          </p>
        </div>
        <p className="text-[11px] text-[var(--text-muted)]">
          The JWT signing secret lives in <code>/var/db/aifw/jwt.key</code> (not editable here).
        </p>

        <div className="flex justify-end">
          <button onClick={save} disabled={saving} className={saveBtnCls}>
            {saving ? "Saving..." : "Save API"}
          </button>
        </div>
      </div>
    </section>
  );
}
