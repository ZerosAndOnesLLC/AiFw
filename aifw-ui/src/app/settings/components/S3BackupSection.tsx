"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { S3TestResult } from "@/lib/api/settings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface S3BackupSectionProps {
  visible: boolean;
  enabled: boolean;
  setEnabled: Dispatch<SetStateAction<boolean>>;
  bucket: string;
  setBucket: Dispatch<SetStateAction<string>>;
  region: string;
  setRegion: Dispatch<SetStateAction<string>>;
  endpoint: string;
  setEndpoint: Dispatch<SetStateAction<string>>;
  prefix: string;
  setPrefix: Dispatch<SetStateAction<string>>;
  pathStyle: boolean;
  setPathStyle: Dispatch<SetStateAction<boolean>>;
  accessKey: string;
  setAccessKey: Dispatch<SetStateAction<string>>;
  secret: string;
  setSecret: Dispatch<SetStateAction<string>>;
  hasSecret: boolean;
  saving: boolean;
  testing: boolean;
  testResult: S3TestResult | null;
  loading: boolean;
  feedback: Feedback | null;
  save: () => void;
  test: () => void;
}

export function S3BackupSection({
  visible,
  enabled,
  setEnabled,
  bucket,
  setBucket,
  region,
  setRegion,
  endpoint,
  setEndpoint,
  prefix,
  setPrefix,
  pathStyle,
  setPathStyle,
  accessKey,
  setAccessKey,
  secret,
  setSecret,
  hasSecret,
  saving,
  testing,
  testResult,
  loading,
  feedback,
  save,
  test,
}: S3BackupSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="font-medium">S3 Backup Sync</h2>
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>Enabled</span>
        </label>
      </div>
      <FeedbackBanner feedback={feedback} />
      <p className="text-xs text-[var(--text-muted)] mb-3">
        When enabled, every auto-snapshot is uploaded to the configured S3 bucket
        under a per-host prefix. Leave access key &amp; secret empty to use the
        machine&apos;s default AWS credential chain (env vars, <code>~/.aws/credentials</code>,
        or the EC2/ECS instance role). S3-compatible providers (MinIO, Backblaze,
        Wasabi) are supported via the optional endpoint field + path-style toggle.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className={labelCls}>Bucket</label>
          <input type="text" value={bucket} onChange={(e) => setBucket(e.target.value)} className={inputCls} placeholder="my-aifw-backups" />
        </div>
        <div>
          <label className={labelCls}>Region</label>
          <input type="text" value={region} onChange={(e) => setRegion(e.target.value)} className={inputCls} placeholder="us-east-1" />
        </div>
        <div>
          <label className={labelCls}>Endpoint (optional)</label>
          <input type="text" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className={inputCls} placeholder="https://minio.example.com" />
        </div>
        <div>
          <label className={labelCls}>Key prefix (optional)</label>
          <input type="text" value={prefix} onChange={(e) => setPrefix(e.target.value)} className={inputCls} placeholder="aifw/production" />
        </div>
        <div>
          <label className={labelCls}>Access Key ID (optional)</label>
          <input type="text" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} className={inputCls} placeholder="(uses default credential chain)" />
        </div>
        <div>
          <label className={labelCls}>Secret Access Key {hasSecret && <span className="text-[var(--text-muted)]">(saved)</span>}</label>
          <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className={inputCls} placeholder={hasSecret ? "••••••••  (leave blank to keep)" : "(optional)"} />
        </div>
      </div>
      <div className="mt-3">
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={pathStyle} onChange={(e) => setPathStyle(e.target.checked)} />
          <span>Force path-style URLs <span className="text-[var(--text-muted)]">(required for most S3-compatible providers)</span></span>
        </label>
      </div>
      {testResult && (
        <div className={`mt-3 rounded border p-3 text-xs ${testResult.ok ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-200" : "border-red-500/40 bg-red-500/5 text-red-200"}`}>
          <div className="flex gap-3 mb-1">
            <span>Write: {testResult.write ? "✓" : "✕"}</span>
            <span>Read: {testResult.read ? "✓" : "✕"}</span>
            <span>Delete: {testResult.delete ? "✓" : "✕"}</span>
          </div>
          <div>{testResult.message}</div>
        </div>
      )}
      <div className="flex justify-between items-center mt-4">
        <button
          onClick={test}
          disabled={testing || loading || !bucket.trim()}
          className="px-4 py-2 text-sm font-medium rounded-md bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-50"
        >
          {testing ? "Testing (write → read → delete)…" : "Test connection"}
        </button>
        <button onClick={save} disabled={saving || loading} className={saveBtnCls}>
          {saving ? "Saving…" : "Save S3 Settings"}
        </button>
      </div>
    </section>
  );
}
