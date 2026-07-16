"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { SmtpTls } from "@/lib/api/settings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface SmtpSectionProps {
  visible: boolean;
  enabled: boolean;
  setEnabled: Dispatch<SetStateAction<boolean>>;
  host: string;
  setHost: Dispatch<SetStateAction<string>>;
  port: number;
  setPort: Dispatch<SetStateAction<number>>;
  tls: SmtpTls;
  setTls: Dispatch<SetStateAction<SmtpTls>>;
  user: string;
  setUser: Dispatch<SetStateAction<string>>;
  pass: string;
  setPass: Dispatch<SetStateAction<string>>;
  hasPass: boolean;
  from: string;
  setFrom: Dispatch<SetStateAction<string>>;
  recipients: string;
  setRecipients: Dispatch<SetStateAction<string>>;
  events: string[];
  setEvents: Dispatch<SetStateAction<string[]>>;
  saving: boolean;
  testing: boolean;
  loading: boolean;
  feedback: Feedback | null;
  save: () => void;
  test: () => void;
}

export function SmtpSection({
  visible,
  enabled,
  setEnabled,
  host,
  setHost,
  port,
  setPort,
  tls,
  setTls,
  user,
  setUser,
  pass,
  setPass,
  hasPass,
  from,
  setFrom,
  recipients,
  setRecipients,
  events,
  setEvents,
  saving,
  testing,
  loading,
  feedback,
  save,
  test,
}: SmtpSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">Email Notifications (SMTP)</h2>
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>Enabled</span>
        </label>
      </div>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-[var(--text-muted)] mb-3">
        Send email when backup/restore events occur. Defaults subscribe to
        failures only so an active appliance doesn&apos;t flood your inbox;
        opt in to success events as needed.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>SMTP host</label>
          <input type="text" value={host} onChange={(e) => setHost(e.target.value)} className={inputCls} placeholder="smtp.example.com" />
        </div>
        <div>
          <label className={labelCls}>Port</label>
          <input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value) || 587)} className={inputCls} />
        </div>
        <div>
          <label className={labelCls}>Encryption</label>
          <select value={tls} onChange={(e) => setTls(e.target.value as SmtpTls)} className={inputCls}>
            <option value="none">None (plaintext, discouraged)</option>
            <option value="starttls">STARTTLS (port 587)</option>
            <option value="implicit">Implicit TLS (port 465)</option>
          </select>
        </div>
        <div>
          <label className={labelCls}>Username (optional)</label>
          <input type="text" value={user} onChange={(e) => setUser(e.target.value)} className={inputCls} autoComplete="off" />
        </div>
        <div>
          <label className={labelCls}>Password {hasPass && <span className="text-[var(--text-muted)]">(saved)</span>}</label>
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} className={inputCls} placeholder={hasPass ? "••••••••  (leave blank to keep)" : ""} autoComplete="new-password" />
        </div>
        <div>
          <label className={labelCls}>From address</label>
          <input type="text" value={from} onChange={(e) => setFrom(e.target.value)} className={inputCls} placeholder="aifw@yourdomain.com" />
        </div>
        <div className="md:col-span-2">
          <label className={labelCls}>Recipients (comma- or space-separated)</label>
          <input type="text" value={recipients} onChange={(e) => setRecipients(e.target.value)} className={inputCls} placeholder="ops@example.com, oncall@example.com" />
        </div>
      </div>
      <div className="mt-4">
        <label className={labelCls}>Send email for</label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-1 mt-1 text-sm">
          {[
            ["s3_upload_failed",   "S3 upload failed  (recommended)"],
            ["restore_failed",     "Restore failed    (recommended)"],
            ["cert_renew_failed",  "ACME cert renewal failed  (recommended)"],
            ["cert_expiring_soon", "ACME cert expiring soon  (recommended)"],
            ["s3_upload_ok",       "S3 upload succeeded"],
            ["restore_ok",         "Restore succeeded"],
            ["backup_saved",       "Config snapshot saved"],
            ["pruned",             "Old versions pruned"],
            ["cert_renewed_ok",    "ACME cert renewed"],
          ].map(([k, label]) => (
            <label key={k} className="inline-flex items-center gap-2">
              <input
                type="checkbox"
                checked={events.includes(k)}
                onChange={(e) => {
                  setEvents((prev) =>
                    e.target.checked ? [...prev, k] : prev.filter((x) => x !== k)
                  );
                }}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex justify-between items-center mt-4">
        <button
          onClick={test}
          disabled={testing || loading || !host.trim() || !recipients.trim()}
          className="px-4 py-2 text-sm font-medium rounded-md bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
        >
          {testing ? "Sending test…" : "Send test email"}
        </button>
        <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
          {saving ? "Saving…" : "Save SMTP Settings"}
        </button>
      </div>
    </section>
  );
}
