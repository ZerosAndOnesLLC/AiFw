"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { ConsoleKind } from "@/lib/api/settings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface ConsoleSectionProps {
  visible: boolean;
  kind: ConsoleKind;
  setKind: Dispatch<SetStateAction<ConsoleKind>>;
  baud: number;
  setBaud: Dispatch<SetStateAction<number>>;
  confirm: boolean;
  setConfirm: Dispatch<SetStateAction<boolean>>;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function ConsoleSection({
  visible,
  kind,
  setKind,
  baud,
  setBaud,
  confirm,
  setConfirm,
  saving,
  feedback,
  save,
}: ConsoleSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <h2 className="font-medium mb-4">Console</h2>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-yellow-300 mb-3">
        Changing the console requires a reboot and can break console access if misconfigured.
        Verify you have access on the selected device before rebooting.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Console</label>
          <div className="flex gap-4 mt-1">
            {(["video","serial","dual"] as const).map(k => (
              <label key={k} className="flex items-center gap-2">
                <input type="radio" checked={kind === k} onChange={() => setKind(k)} />
                <span>{k}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <label className={labelCls}>Baud</label>
          <select className={inputCls} value={baud} onChange={e => setBaud(Number(e.target.value))}>
            {[9600,19200,38400,57600,115200].map(b => <option key={b} value={b}>{b}</option>)}
          </select>
        </div>
      </div>
      <div className="flex justify-end mt-4 gap-2">
        {!confirm ? (
          <button onClick={() => setConfirm(true)} className={saveBtnCls}>Apply</button>
        ) : (
          <>
            <button onClick={() => setConfirm(false)} className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]">Cancel</button>
            <button onClick={save} disabled={saving} className="px-4 py-2 text-sm font-medium rounded-md bg-orange-600 hover:bg-orange-700 text-white">
              {saving ? "Saving…" : "Confirm & Save"}
            </button>
          </>
        )}
      </div>
    </section>
  );
}
