"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface AuthSectionProps {
  visible: boolean;
  sessionTimeout: number;
  setSessionTimeout: Dispatch<SetStateAction<number>>;
  maxLoginAttempts: number;
  setMaxLoginAttempts: Dispatch<SetStateAction<number>>;
  lockoutDuration: number;
  setLockoutDuration: Dispatch<SetStateAction<number>>;
  requireMfa: boolean;
  setRequireMfa: Dispatch<SetStateAction<boolean>>;
  allowRegistration: boolean;
  setAllowRegistration: Dispatch<SetStateAction<boolean>>;
  passwordMinLength: number;
  setPasswordMinLength: Dispatch<SetStateAction<number>>;
  loading: boolean;
  saving: boolean;
  feedback: Feedback | null;
  save: () => void;
}

export function AuthSection({
  visible,
  sessionTimeout,
  setSessionTimeout,
  maxLoginAttempts,
  setMaxLoginAttempts,
  lockoutDuration,
  setLockoutDuration,
  requireMfa,
  setRequireMfa,
  allowRegistration,
  setAllowRegistration,
  passwordMinLength,
  setPasswordMinLength,
  loading,
  saving,
  feedback,
  save,
}: AuthSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">Authentication</h2>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-4 mt-2">
        {loading ? (
          <p className="text-sm text-[var(--text-muted)]">Loading auth settings...</p>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className={labelCls}>Session Timeout (minutes)</label>
                <input
                  type="number"
                  value={sessionTimeout}
                  onChange={(e) => setSessionTimeout(Number(e.target.value))}
                  className={inputCls}
                  min={5}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  How long before you need to login again. Default: 480 (8 hours).
                </p>
              </div>
              <div>
                <label className={labelCls}>Password Min Length</label>
                <input
                  type="number"
                  value={passwordMinLength}
                  onChange={(e) => setPasswordMinLength(Number(e.target.value))}
                  min={4}
                  className={inputCls}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className={labelCls}>Max Login Attempts</label>
                <input
                  type="number"
                  value={maxLoginAttempts}
                  onChange={(e) => setMaxLoginAttempts(Number(e.target.value))}
                  min={1}
                  className={inputCls}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  Failed attempts before lockout.
                </p>
              </div>
              <div>
                <label className={labelCls}>Lockout Duration (sec)</label>
                <input
                  type="number"
                  value={lockoutDuration}
                  onChange={(e) => setLockoutDuration(Number(e.target.value))}
                  className={inputCls}
                />
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  How long the account stays locked.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={requireMfa}
                  onChange={(e) => setRequireMfa(e.target.checked)}
                  className="rounded border-[var(--border)]"
                />
                Require multi-factor authentication (MFA)
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={allowRegistration}
                  onChange={(e) => setAllowRegistration(e.target.checked)}
                  className="rounded border-[var(--border)]"
                />
                Allow self-registration
              </label>
            </div>
          </>
        )}

        <div className="flex justify-end">
          <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
            {saving ? "Saving..." : "Save Auth"}
          </button>
        </div>
      </div>
    </section>
  );
}
