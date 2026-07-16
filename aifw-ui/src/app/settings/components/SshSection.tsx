"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface SshSectionProps {
  visible: boolean;
  enabled: boolean;
  setEnabled: Dispatch<SetStateAction<boolean>>;
  port: number;
  setPort: Dispatch<SetStateAction<number>>;
  passwordAuth: boolean;
  setPasswordAuth: Dispatch<SetStateAction<boolean>>;
  permitRoot: boolean;
  setPermitRoot: Dispatch<SetStateAction<boolean>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function SshSection({
  visible,
  enabled,
  setEnabled,
  port,
  setPort,
  passwordAuth,
  setPasswordAuth,
  permitRoot,
  setPermitRoot,
  saving,
  feedback,
  save,
}: SshSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <h2 className="font-medium mb-4">SSH Access</h2>
      <FeedbackBanner feedback={feedback} />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
          <span>SSH enabled</span>
        </label>
        <div>
          <label className={labelCls}>Port {port !== 22 && <span className="text-yellow-400">(non-default)</span>}</label>
          <input type="number" min={1} max={65535} className={inputCls} value={port} onChange={e => setPort(Number(e.target.value) || 22)} />
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={passwordAuth} onChange={e => setPasswordAuth(e.target.checked)} />
          <span>Password authentication (insecure)</span>
        </label>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={permitRoot} onChange={e => setPermitRoot(e.target.checked)} />
          <span>Permit root login</span>
        </label>
      </div>
      <div className="flex justify-end mt-4">
        <button onClick={save} disabled={saving} className={saveBtnCls}>
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </section>
  );
}
