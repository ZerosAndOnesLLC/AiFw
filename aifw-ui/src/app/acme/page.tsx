"use client";

import { useCallback, useEffect, useState } from "react";
import Help, { HelpBanner } from "./Help";

/* ---------- Types ---------- */

interface Account {
  id: number | null;
  directory_url: string;
  contact_email: string;
  registered: boolean;
}

interface CertSummary {
  id: number;
  common_name: string;
  sans: string[];
  challenge_type: "dns-01" | "http-01";
  dns_provider_id: number | null;
  status: "pending" | "active" | "failed" | "renewing" | "expired";
  auto_renew: boolean;
  renew_days_before_expiry: number;
  issued_at: string | null;
  expires_at: string | null;
  days_until_expiry: number | null;
  last_renew_attempt: string | null;
  last_renew_error: string | null;
  has_cert: boolean;
}

interface DnsProvider {
  id: number;
  name: string;
  kind: "cloudflare" | "route53" | "digitalocean" | "rfc2136" | "manual";
  zone: string;
  has_token: boolean;
  has_secret: boolean;
  extra: Record<string, unknown>;
}

interface ExportTarget {
  id: number;
  cert_id: number;
  kind: "file" | "webhook" | "local-tls-store";
  config: Record<string, unknown>;
  last_run_at: string | null;
  last_run_ok: boolean;
  last_run_error: string | null;
}

/* ---------- Helpers ---------- */

function authHeaders(): HeadersInit {
  const t = typeof window !== "undefined" ? localStorage.getItem("aifw_token") || "" : "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${t}` };
}
function authHeadersPlain(): HeadersInit {
  const t = typeof window !== "undefined" ? localStorage.getItem("aifw_token") || "" : "";
  return { Authorization: `Bearer ${t}` };
}
async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? authHeaders() : authHeadersPlain(),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || `HTTP ${res.status}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : (undefined as T);
}

const DOMAIN_RE = /^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
function validateDomain(d: string): string | null {
  return DOMAIN_RE.test(d.trim()) ? null : "must look like example.com or *.example.com";
}
function fmtWhen(s: string | null): string {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}
function expiryColor(days: number | null): string {
  if (days === null) return "text-[var(--text-muted)]";
  if (days < 0)  return "text-red-400";
  if (days < 7)  return "text-red-400";
  if (days < 30) return "text-yellow-300";
  return "text-emerald-400";
}

/* ---------- Page ---------- */

export default function AcmePage() {
  const [tab, setTab] = useState<"certs" | "providers" | "account">("certs");

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2">
        ACME / TLS Certificates
        <Help title="What is this?" size="md">
          Issue and renew TLS certificates from Let&apos;s Encrypt (or any
          ACME v2 CA). Certificates can be exported to other services on
          your network (file paths, webhooks, or AiFw&apos;s own TLS store).
          DNS-01 is the default since it supports wildcard certs without
          requiring the appliance to be reachable from the internet.
        </Help>
      </h1>

      <HelpBanner title="How this fits together" storageKey="acme-overview">
        <p>
          <b>Account:</b> register once with the CA (email + ToS).
          <b> DNS Providers:</b> credentials AiFw uses to publish the
          <code>_acme-challenge</code> TXT record during DNS-01 validation.
          Cloudflare needs an API token with <code>Zone:DNS:Edit</code>
          scope; Route53 needs an IAM access key + secret with
          <code>route53:ChangeResourceRecordSets</code>.
          <b> Certificates:</b> per-cert config + status. Hit
          <i>Renew now</i> to issue immediately; otherwise the daemon
          renews automatically when within the renew window.
          <b> Export targets</b> (per cert): file path, webhook, or
          drop into AiFw&apos;s own TLS store.
        </p>
      </HelpBanner>

      <nav className="flex gap-2 border-b border-[var(--border)]">
        {(["certs", "providers", "account"] as const).map((k) => (
          <button key={k}
            onClick={() => setTab(k)}
            className={`px-4 py-2 text-sm font-semibold border-b-2 -mb-px transition-colors ${
              tab === k ? "border-blue-500 text-white" : "border-transparent text-[var(--text-muted)] hover:text-white"
            }`}>
            {k === "certs" ? "Certificates" : k === "providers" ? "DNS Providers" : "Account"}
          </button>
        ))}
      </nav>

      {tab === "certs"     && <CertsTab />}
      {tab === "providers" && <ProvidersTab />}
      {tab === "account"   && <AccountTab />}
    </div>
  );
}

/* ===================== Certs tab ===================== */

function CertsTab() {
  const [certs, setCerts] = useState<CertSummary[]>([]);
  const [providers, setProviders] = useState<DnsProvider[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);
  const [expandedCert, setExpandedCert] = useState<number | null>(null);

  const reload = useCallback(async () => {
    const [c, p] = await Promise.all([
      api<CertSummary[]>("GET", "/api/v1/acme/certs"),
      api<DnsProvider[]>("GET", "/api/v1/acme/dns-providers"),
    ]);
    setCerts(c); setProviders(p);
  }, []);
  useEffect(() => { reload(); }, [reload]);

  function showToast(ok: boolean, msg: string) {
    setToast({ ok, msg });
    setTimeout(() => setToast(null), 6000);
  }

  async function renewNow(id: number) {
    setBusy(id);
    try {
      const r = await api<{ ok: boolean; message: string }>("POST", `/api/v1/acme/certs/${id}/renew`);
      showToast(r.ok, r.message);
      await reload();
    } catch (e) { showToast(false, String(e)); }
    finally { setBusy(null); }
  }
  async function deleteCert(id: number) {
    if (!confirm("Delete this cert? It will not be revoked at the CA.")) return;
    try {
      await api("DELETE", `/api/v1/acme/certs/${id}`);
      await reload();
    } catch (e) { showToast(false, String(e)); }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm text-[var(--text-muted)]">{certs.length} certificate{certs.length === 1 ? "" : "s"}</div>
        <button onClick={() => setShowAdd(true)}
          className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white">
          + Request certificate
        </button>
      </div>

      {certs.length === 0 && (
        <div className="text-sm text-[var(--text-muted)] border border-dashed border-[var(--border)] rounded p-6 text-center">
          No certificates yet. Configure a DNS provider first, then request one.
        </div>
      )}

      <div className="space-y-2">
        {certs.map((c) => {
          const provider = providers.find((p) => p.id === c.dns_provider_id);
          return (
            <div key={c.id} className="border border-[var(--border)] rounded">
              <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-3 px-3 py-2 items-center text-sm">
                <div>
                  <div className="text-white font-semibold">{c.common_name}</div>
                  {c.sans.length > 0 && (
                    <div className="text-[10px] text-[var(--text-muted)]">SANs: {c.sans.join(", ")}</div>
                  )}
                  {c.last_renew_error && (
                    <div className="text-[10px] text-red-400 mt-0.5">⚠ {c.last_renew_error}</div>
                  )}
                </div>
                <div className="text-xs">
                  <span className={`px-2 py-0.5 rounded text-[10px] ${
                    c.status === "active"   ? "bg-emerald-500/15 text-emerald-300" :
                    c.status === "renewing" ? "bg-blue-500/15 text-blue-300" :
                    c.status === "failed"   ? "bg-red-500/15 text-red-300" :
                    c.status === "expired"  ? "bg-red-500/15 text-red-300" :
                                              "bg-gray-500/15 text-gray-300"
                  }`}>{c.status}</span>
                </div>
                <div className={`text-xs tabular-nums ${expiryColor(c.days_until_expiry)}`}>
                  {c.days_until_expiry === null ? "—" : `${c.days_until_expiry}d`}
                </div>
                <div className="text-xs text-[var(--text-muted)]">{provider?.name || "—"}</div>
                <div className="flex gap-1">
                  <button onClick={() => setExpandedCert(expandedCert === c.id ? null : c.id)}
                    className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]"
                    title="Show export targets">{expandedCert === c.id ? "▾" : "▸"}</button>
                  <button onClick={() => renewNow(c.id)} disabled={busy === c.id}
                    className="px-2 py-1 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
                    {busy === c.id ? "…" : "Renew"}
                  </button>
                  {c.has_cert && (
                    <a href={`/api/v1/acme/certs/${c.id}/cert.pem`}
                      className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">PEM</a>
                  )}
                  <button onClick={() => deleteCert(c.id)}
                    className="px-2 py-1 text-xs rounded hover:bg-red-600 hover:text-white">✕</button>
                </div>
              </div>
              {expandedCert === c.id && <ExportTargetsPanel certId={c.id} />}
            </div>
          );
        })}
      </div>

      {showAdd && <AddCertModal providers={providers}
        onClose={() => setShowAdd(false)}
        onCreated={async () => { setShowAdd(false); await reload(); }} />}

      {toast && (
        <div className={`fixed bottom-6 right-6 px-4 py-2 rounded shadow-lg text-sm max-w-md ${toast.ok ? "bg-emerald-600" : "bg-red-600"} text-white`}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

function AddCertModal({ providers, onClose, onCreated }:
  { providers: DnsProvider[]; onClose: () => void; onCreated: () => void }) {
  const [cn, setCn] = useState("");
  const [sansText, setSansText] = useState("");
  const [providerId, setProviderId] = useState<number | "">("");
  const [autoRenew, setAutoRenew] = useState(true);
  const [renewDays, setRenewDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const sansArr = sansText.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  const cnErr = cn ? validateDomain(cn) : "required";
  const sansErrs = sansArr.map(validateDomain).filter((x): x is string => !!x);
  const valid = !cnErr && sansErrs.length === 0 && providerId !== "";

  async function submit() {
    if (!valid) return;
    setBusy(true); setErr(null);
    try {
      await api("POST", "/api/v1/acme/certs", {
        common_name: cn.trim(),
        sans: sansArr,
        challenge_type: "dns-01",
        dns_provider_id: providerId,
        auto_renew: autoRenew,
        renew_days_before_expiry: renewDays,
      });
      onCreated();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 w-full max-w-md space-y-3" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white">Request certificate</h2>

        <Field label="Common Name (CN)" error={cn ? cnErr : null}>
          <input value={cn} onChange={(e) => setCn(e.target.value)} className="form-input" placeholder="example.com or *.example.com" autoFocus />
        </Field>

        <Field label={<>Subject Alternative Names (SANs) <Help title="SANs" size="xs">
          One per line or comma-separated. Each SAN is also validated via the same DNS-01 flow.
        </Help></>}>
          <textarea value={sansText} onChange={(e) => setSansText(e.target.value)} className="form-input h-20" placeholder="api.example.com&#10;www.example.com" />
          {sansErrs.length > 0 && <div className="text-xs text-red-400 mt-1">{sansErrs.join("; ")}</div>}
        </Field>

        <Field label="DNS provider" error={providerId === "" ? "required" : null}>
          {providers.length === 0 ? (
            <div className="text-xs text-yellow-300">No DNS providers configured. Add one in the DNS Providers tab first.</div>
          ) : (
            <select value={providerId} onChange={(e) => setProviderId(Number(e.target.value) || "")} className="form-input">
              <option value="">— select —</option>
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.kind} → {p.zone})</option>)}
            </select>
          )}
        </Field>

        <div className="flex items-center gap-4">
          <label className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={autoRenew} onChange={(e) => setAutoRenew(e.target.checked)} />
            <span>Auto-renew</span>
          </label>
          <label className="inline-flex items-center gap-2 text-sm">
            <span>Renew when</span>
            <input type="number" min={1} max={89} value={renewDays} onChange={(e) => setRenewDays(Number(e.target.value) || 30)} className="form-input w-16" />
            <span>days from expiry</span>
          </label>
        </div>

        {err && <div className="text-sm text-red-400">⚠ {err}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Cancel</button>
          <button onClick={submit} disabled={!valid || busy}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
            {busy ? "Creating…" : "Save (issue happens on Renew)"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- Export targets sub-panel ---------- */

function ExportTargetsPanel({ certId }: { certId: number }) {
  const [targets, setTargets] = useState<ExportTarget[]>([]);
  const [showAdd, setShowAdd] = useState(false);

  const reload = useCallback(async () => {
    setTargets(await api<ExportTarget[]>("GET", `/api/v1/acme/certs/${certId}/targets`));
  }, [certId]);
  useEffect(() => { reload(); }, [reload]);

  async function remove(id: number) {
    if (!confirm("Delete this export target?")) return;
    await api("DELETE", `/api/v1/acme/export-targets/${id}`);
    await reload();
  }

  return (
    <div className="border-t border-[var(--border)] bg-[var(--bg-card-secondary)]/40 px-3 py-2 space-y-2">
      <div className="flex items-center justify-between">
        <div className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wide">Export targets</div>
        <button onClick={() => setShowAdd(true)}
          className="px-2 py-0.5 text-xs rounded bg-emerald-600 hover:bg-emerald-500 text-white">+ Add</button>
      </div>
      {targets.length === 0 && <div className="text-xs text-[var(--text-muted)]">No export targets. The cert won&apos;t be deployed anywhere automatically.</div>}
      {targets.map((t) => (
        <div key={t.id} className="text-xs flex items-center gap-3 py-1 border-b border-[var(--border)]/30 last:border-0">
          <span className="font-mono text-white">{t.kind}</span>
          <span className="text-[var(--text-muted)] truncate flex-1">{JSON.stringify(t.config)}</span>
          <span className={t.last_run_ok ? "text-emerald-400" : t.last_run_at ? "text-red-400" : "text-[var(--text-muted)]"}>
            {t.last_run_at ? (t.last_run_ok ? "✓" : "✗") : "—"}
          </span>
          {t.last_run_error && <span className="text-red-400 truncate" title={t.last_run_error}>⚠</span>}
          <button onClick={() => remove(t.id)} className="text-[var(--text-muted)] hover:text-red-400">✕</button>
        </div>
      ))}
      {showAdd && <AddExportTargetModal certId={certId} onClose={() => setShowAdd(false)} onCreated={async () => { setShowAdd(false); await reload(); }} />}
    </div>
  );
}

function AddExportTargetModal({ certId, onClose, onCreated }: { certId: number; onClose: () => void; onCreated: () => void }) {
  const [kind, setKind] = useState<"file" | "webhook" | "local-tls-store">("file");
  const [cfg, setCfg] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Sane default config per kind.
  useEffect(() => {
    if (kind === "file") {
      setCfg(JSON.stringify({
        cert_path: "/usr/local/etc/myservice/fullchain.pem",
        key_path: "/usr/local/etc/myservice/key.pem",
        owner: "myservice:myservice",
        mode: "0644",
        key_mode: "0600",
      }, null, 2));
    } else if (kind === "webhook") {
      setCfg(JSON.stringify({
        url: "https://my-config-server.example.com/cert-renewed",
        auth_header: "Bearer ...",
      }, null, 2));
    } else {
      setCfg(JSON.stringify({ reload_service: "aifw_api" }, null, 2));
    }
  }, [kind]);

  async function submit() {
    setBusy(true); setErr(null);
    try {
      const parsed = JSON.parse(cfg);
      await api("POST", `/api/v1/acme/certs/${certId}/targets`, { kind, config: parsed });
      onCreated();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 w-full max-w-lg space-y-3" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white">Add export target</h2>
        <Field label="Kind">
          <select value={kind} onChange={(e) => setKind(e.target.value as "file" | "webhook" | "local-tls-store")} className="form-input">
            <option value="file">file (sudo install to a path)</option>
            <option value="webhook">webhook (POST cert+key as JSON)</option>
            <option value="local-tls-store">local-tls-store (drop into AiFw&apos;s own TLS dir)</option>
          </select>
        </Field>
        <Field label="Config (JSON)">
          <textarea value={cfg} onChange={(e) => setCfg(e.target.value)} className="form-input font-mono text-xs h-48" />
        </Field>
        {err && <div className="text-sm text-red-400">⚠ {err}</div>}
        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Cancel</button>
          <button onClick={submit} disabled={busy}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ===================== Providers tab ===================== */

function ProvidersTab() {
  const [providers, setProviders] = useState<DnsProvider[]>([]);
  const [editing, setEditing] = useState<DnsProvider | "new" | null>(null);
  const [testing, setTesting] = useState<number | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);

  const reload = useCallback(async () => {
    setProviders(await api<DnsProvider[]>("GET", "/api/v1/acme/dns-providers"));
  }, []);
  useEffect(() => { reload(); }, [reload]);

  function showToast(ok: boolean, msg: string) {
    setToast({ ok, msg }); setTimeout(() => setToast(null), 6000);
  }

  async function test(id: number) {
    setTesting(id);
    try {
      const r = await api<{ ok: boolean; message: string }>("POST", `/api/v1/acme/dns-providers/${id}/test`);
      showToast(r.ok, r.message);
    } catch (e) { showToast(false, String(e)); }
    finally { setTesting(null); }
  }

  async function remove(id: number) {
    if (!confirm("Delete this provider? Certs using it will fail to renew.")) return;
    await api("DELETE", `/api/v1/acme/dns-providers/${id}`);
    await reload();
  }

  return (
    <div className="space-y-3">
      <HelpBanner title="DNS providers vs the Certificate Authority" storageKey="acme-providers-vs-ca">
        <p>
          A <b>DNS provider</b> here is who AiFw asks to <i>publish a TXT record</i>
          (<code>_acme-challenge.&lt;host&gt;</code>) so the CA can prove you control
          the domain. Today: Cloudflare, AWS Route 53, or Manual.
        </p>
        <p>
          <b>Let&apos;s Encrypt is not listed</b> — it&apos;s the CA that <i>issues</i>
          your cert, not a DNS host. It&apos;s configured on the
          <a className="text-blue-400 underline mx-1" href="#" onClick={(e) => { e.preventDefault(); /* tab nav handled by parent */ document.querySelectorAll("button").forEach(b => { if (b.textContent === "Account") (b as HTMLButtonElement).click(); }); }}>Account</a>
          tab (default URL: <code>https://acme-v02.api.letsencrypt.org/directory</code>).
        </p>
        <p>
          So the typical setup is: Cloudflare or Route 53 here as the
          DNS provider, Let&apos;s Encrypt on the Account tab as the CA.
        </p>
      </HelpBanner>

      <div className="flex items-center justify-between">
        <div className="text-sm text-[var(--text-muted)]">{providers.length} provider{providers.length === 1 ? "" : "s"}</div>
        <button onClick={() => setEditing("new")}
          className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white">+ Add provider</button>
      </div>
      {providers.length === 0 && (
        <div className="text-sm text-[var(--text-muted)] border border-dashed border-[var(--border)] rounded p-6 text-center">
          No DNS providers. Add one before requesting a certificate.
        </div>
      )}
      <div className="space-y-2">
        {providers.map((p) => (
          <div key={p.id} className="border border-[var(--border)] rounded px-3 py-2 grid grid-cols-[1fr_auto_auto] gap-3 items-center text-sm">
            <div>
              <div className="text-white font-semibold">{p.name} <span className="text-xs text-[var(--text-muted)]">({p.kind})</span></div>
              <div className="text-[11px] text-[var(--text-muted)]">zone <span className="font-mono">{p.zone}</span> · token {p.has_token ? "✓" : "—"}{p.kind === "route53" && ` · secret ${p.has_secret ? "✓" : "—"}`}</div>
            </div>
            <button onClick={() => test(p.id)} disabled={testing === p.id}
              className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-blue-600 hover:text-white disabled:opacity-50">
              {testing === p.id ? "Testing…" : "Test"}
            </button>
            <div className="flex gap-1">
              <button onClick={() => setEditing(p)}
                className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Edit</button>
              <button onClick={() => remove(p.id)}
                className="px-2 py-1 text-xs rounded hover:bg-red-600 hover:text-white">✕</button>
            </div>
          </div>
        ))}
      </div>
      {editing && <ProviderModal initial={editing === "new" ? null : editing}
        onClose={() => setEditing(null)}
        onSaved={async () => { setEditing(null); await reload(); }} />}
      {toast && (
        <div className={`fixed bottom-6 right-6 px-4 py-2 rounded shadow-lg text-sm max-w-md ${toast.ok ? "bg-emerald-600" : "bg-red-600"} text-white`}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

/* DNS provider catalog — each entry drives the picker tile + the per-kind
   form layout. Adding a new provider here means: (1) add an entry, (2)
   add the matching backend implementation in aifw-core::acme_dns. */
const PROVIDER_CATALOG: {
  kind: DnsProvider["kind"];
  label: string;
  blurb: string;
  /** Concrete instructions to find/create the credential. */
  setup: React.ReactNode;
  /** Field labels override — defaults are "API token" / "Secret access key". */
  tokenLabel?: string;
  secretLabel?: string;
  needsToken: boolean;
  needsSecret: boolean;
  /** Optional extra fields (region, etc.) keyed into the `extra` JSON. */
  extraFields?: { key: string; label: string; placeholder?: string; help?: string }[];
}[] = [
  {
    kind: "cloudflare",
    label: "Cloudflare",
    blurb: "REST API. Issue an API token scoped to one zone.",
    needsToken: true,
    needsSecret: false,
    tokenLabel: "API Token",
    setup: (
      <>
        <p>1. Go to <a className="text-blue-400 underline" href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noreferrer">Cloudflare → My Profile → API Tokens</a>.</p>
        <p>2. <b>Create Token</b> → use the <i>Edit zone DNS</i> template.</p>
        <p>3. Under <b>Zone Resources</b>, restrict to the single zone you&apos;ll be issuing certs for.</p>
        <p>4. Permissions must include <code>Zone:DNS:Edit</code> and <code>Zone:Zone:Read</code>.</p>
        <p>5. Copy the token (it&apos;s shown once) and paste it below.</p>
      </>
    ),
  },
  {
    kind: "route53",
    label: "AWS Route 53",
    blurb: "Uses the AWS SDK. IAM access key + secret with ChangeResourceRecordSets on the hosted zone.",
    needsToken: true,
    needsSecret: true,
    tokenLabel: "Access Key ID",
    secretLabel: "Secret Access Key",
    extraFields: [
      { key: "region", label: "AWS region", placeholder: "us-east-1", help: "Route53 is global; this only matters if your IAM policy is region-scoped." },
      { key: "zone_id", label: "Hosted zone ID (optional)", placeholder: "Z2ABCDEFGHIJKL", help: "Auto-resolved from the zone name on first use if left blank." },
    ],
    setup: (
      <>
        <p>1. AWS Console → IAM → <b>Users</b> → create a user with programmatic access.</p>
        <p>2. Attach this minimal policy (replace <code>Z2ABCDEFGHIJKL</code> with your hosted zone ID):</p>
        <pre className="text-[10px] bg-black/40 rounded p-2 overflow-x-auto whitespace-pre">{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:GetChange",
        "route53:ChangeResourceRecordSets",
        "route53:ListResourceRecordSets",
        "route53:ListHostedZones",
        "route53:ListHostedZonesByName"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/Z2ABCDEFGHIJKL",
        "arn:aws:route53:::change/*"
      ]
    }
  ]
}`}</pre>
        <p>3. Save the access key + secret somewhere safe — AWS only shows the secret once.</p>
      </>
    ),
  },
  {
    kind: "manual",
    label: "Manual",
    blurb: "Paste the TXT record into your DNS by hand. Useful when no API exists.",
    needsToken: false,
    needsSecret: false,
    setup: (
      <>
        <p>When you click <b>Renew now</b> on a cert that uses this provider, AiFw will surface the
        <code>_acme-challenge.&lt;host&gt;</code> name + value in the cert&apos;s <i>Last error</i> field.</p>
        <p>Add the TXT to your DNS, wait for it to propagate, then click <b>Renew now</b> again to finalize.</p>
        <p className="text-yellow-300/80">Auto-renewal won&apos;t work with this provider — pick Cloudflare or Route53 if you want hands-off operation.</p>
      </>
    ),
  },
];

function ProviderModal({ initial, onClose, onSaved }: { initial: DnsProvider | null; onClose: () => void; onSaved: () => void }) {
  const isNew = !initial;
  const [name, setName] = useState(initial?.name || "");
  const [kind, setKind] = useState<DnsProvider["kind"]>(initial?.kind || "cloudflare");
  const [zone, setZone] = useState(initial?.zone || "");
  const [token, setToken] = useState("");                         // empty = unchanged
  const [secret, setSecret] = useState("");                       // empty = unchanged
  const initialExtra: Record<string, string> = (initial?.extra ?? {}) as Record<string, string>;
  const [extraVals, setExtraVals] = useState<Record<string, string>>(
    Object.fromEntries(Object.entries(initialExtra).map(([k, v]) => [k, String(v ?? "")]))
  );
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [zoneErr, setZoneErr] = useState<string | null>(null);

  const spec = PROVIDER_CATALOG.find((p) => p.kind === kind)!;
  const valid = name.trim() && zone.trim() && !zoneErr
    && (!spec.needsToken || initial?.has_token || token)
    && (!spec.needsSecret || initial?.has_secret || secret);

  function validateZone(v: string): string | null {
    const z = v.trim().replace(/\.+$/, "");
    if (!z) return null;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(z)) {
      return "must be a valid DNS zone like example.com";
    }
    return null;
  }

  function buildBody(): Record<string, unknown> {
    const extraJson: Record<string, unknown> = {};
    for (const f of spec.extraFields ?? []) {
      const v = extraVals[f.key];
      if (v && v.trim()) extraJson[f.key] = v.trim();
    }
    return {
      name: name.trim(),
      kind,
      zone: zone.trim(),
      api_token:      spec.needsToken  ? (token  === "" ? null : token)  : null,
      aws_secret_key: spec.needsSecret ? (secret === "" ? null : secret) : null,
      extra: extraJson,
    };
  }

  async function saveAndTest(testAfter: boolean) {
    if (!valid) return;
    setBusy(true); setErr(null); setTestResult(null);
    try {
      const body = buildBody();
      const created: DnsProvider = isNew
        ? await api<DnsProvider>("POST", "/api/v1/acme/dns-providers", body)
        : await api<DnsProvider>("PUT", `/api/v1/acme/dns-providers/${initial!.id}`, body);
      if (testAfter) {
        setTesting(true);
        try {
          const r = await api<{ ok: boolean; message: string }>(
            "POST", `/api/v1/acme/dns-providers/${created.id}/test`,
          );
          setTestResult(r);
          if (!r.ok) { setBusy(false); setTesting(false); return; }
        } finally { setTesting(false); }
      }
      onSaved();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">{isNew ? "Add" : "Edit"} DNS provider</h2>
          <button onClick={onClose} className="text-[var(--text-muted)] hover:text-white text-xl leading-none">✕</button>
        </div>

        <div className="rounded-md border border-blue-500/30 bg-blue-500/5 p-3 text-xs text-[var(--text-muted)]">
          <span className="text-blue-300 font-semibold">Heads up:</span>{" "}
          A DNS provider is who AiFw asks to <i>publish the validation TXT record</i> during a cert
          issue. The certificate itself comes from your ACME CA (Let&apos;s Encrypt by default) —
          configure that under the <b>Account</b> tab, not here.
        </div>

        {/* Provider picker — card grid, not a dropdown */}
        <div>
          <label className="block text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2">Provider</label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {PROVIDER_CATALOG.map((p) => (
              <button
                key={p.kind}
                type="button"
                onClick={() => setKind(p.kind)}
                className={`text-left p-3 rounded-md border transition-colors ${
                  kind === p.kind
                    ? "border-blue-500 bg-blue-500/10 ring-1 ring-blue-500/40"
                    : "border-[var(--border)] hover:border-[var(--text-muted)] bg-[var(--bg-card-secondary)]"
                }`}
              >
                <div className="text-sm font-semibold text-white">{p.label}</div>
                <div className="text-[11px] text-[var(--text-muted)] mt-0.5">{p.blurb}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Per-provider setup instructions */}
        <details open className="rounded-md border border-[var(--border)] bg-[var(--bg-card-secondary)]/40 p-3">
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
            How to set up {spec.label}
          </summary>
          <div className="mt-2 space-y-2 text-xs text-[var(--text-muted)] [&_code]:bg-black/40 [&_code]:px-1 [&_code]:rounded">
            {spec.setup}
          </div>
        </details>

        <Field label="Name" >
          <input value={name} onChange={(e) => setName(e.target.value)} className="form-input" placeholder={`${spec.label.toLowerCase()}-prod`} />
        </Field>

        <Field label="DNS zone" error={zoneErr}>
          <input
            value={zone}
            onChange={(e) => { setZone(e.target.value); setZoneErr(validateZone(e.target.value)); }}
            className="form-input"
            placeholder="example.com"
          />
          <p className="text-[10px] text-[var(--text-muted)] mt-1">
            The base zone you can edit. Certs for any FQDN under this zone can be issued via this provider.
          </p>
        </Field>

        {spec.needsToken && (
          <Field label={<>{spec.tokenLabel ?? "API token"} {initial?.has_token && <span className="text-[var(--text-muted)]">(saved — leave blank to keep)</span>}</>}>
            <input type="password" value={token} onChange={(e) => setToken(e.target.value)} className="form-input" autoComplete="new-password" placeholder={initial?.has_token ? "•••• (unchanged)" : ""} />
          </Field>
        )}
        {spec.needsSecret && (
          <Field label={<>{spec.secretLabel ?? "Secret"} {initial?.has_secret && <span className="text-[var(--text-muted)]">(saved — leave blank to keep)</span>}</>}>
            <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} className="form-input" autoComplete="new-password" placeholder={initial?.has_secret ? "•••• (unchanged)" : ""} />
          </Field>
        )}
        {(spec.extraFields ?? []).map((f) => (
          <Field key={f.key} label={f.label}>
            <input
              value={extraVals[f.key] || ""}
              onChange={(e) => setExtraVals({ ...extraVals, [f.key]: e.target.value })}
              className="form-input"
              placeholder={f.placeholder}
            />
            {f.help && <p className="text-[10px] text-[var(--text-muted)] mt-1">{f.help}</p>}
          </Field>
        ))}

        {testResult && (
          <div className={`rounded-md border p-3 text-xs ${testResult.ok ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-red-500/40 bg-red-500/10 text-red-200"}`}>
            <span className="font-semibold">{testResult.ok ? "Test OK:" : "Test failed:"}</span> {testResult.message}
          </div>
        )}

        {err && <div className="text-sm text-red-400">⚠ {err}</div>}

        <div className="flex justify-between items-center gap-2 pt-2 border-t border-[var(--border)]">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Cancel</button>
          <div className="flex gap-2">
            <button
              onClick={() => saveAndTest(true)}
              disabled={!valid || busy || testing || spec.kind === "manual"}
              className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] border border-[var(--border)] hover:border-blue-500 text-white disabled:opacity-50"
              title={spec.kind === "manual" ? "Manual provider has nothing to test" : "Save and immediately add+remove a TXT record to verify perms"}
            >
              {testing ? "Testing…" : busy ? "Saving…" : "Save & Test"}
            </button>
            <button onClick={() => saveAndTest(false)} disabled={!valid || busy}
              className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
              {busy ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===================== Account tab ===================== */

function AccountTab() {
  const [acct, setAcct] = useState<Account | null>(null);
  const [email, setEmail] = useState("");
  const [dirUrl, setDirUrl] = useState("https://acme-v02.api.letsencrypt.org/directory");
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);

  const reload = useCallback(async () => {
    const a = await api<Account>("GET", "/api/v1/acme/account");
    setAcct(a); setEmail(a.contact_email); setDirUrl(a.directory_url);
  }, []);
  useEffect(() => { reload(); }, [reload]);

  async function save() {
    setBusy(true);
    try {
      await api("PUT", "/api/v1/acme/account", { directory_url: dirUrl, contact_email: email });
      await reload();
      setToast({ ok: true, msg: "Saved. Account is registered with the CA on the first cert issue." });
    } catch (e) { setToast({ ok: false, msg: String(e) }); }
    finally { setBusy(false); setTimeout(() => setToast(null), 6000); }
  }

  return (
    <div className="space-y-4 max-w-xl">
      <p className="text-sm text-[var(--text-muted)]">
        One ACME account is enough for most operators. The account key is generated on the first
        cert issue and persisted; subsequent issues reuse it.
      </p>
      <Field label={<>Directory URL <Help title="ACME directory URL" size="xs">
        <p><b>Production:</b> <code>https://acme-v02.api.letsencrypt.org/directory</code></p>
        <p><b>Staging</b> (untrusted certs, generous rate limits — use for testing): <code>https://acme-staging-v02.api.letsencrypt.org/directory</code></p>
      </Help></>}>
        <input value={dirUrl} onChange={(e) => setDirUrl(e.target.value)} className="form-input font-mono text-xs" />
      </Field>
      <Field label="Contact email">
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="form-input" placeholder="ops@example.com" />
        <p className="text-xs text-[var(--text-muted)] mt-1">CA expiration warnings + ToS notices are sent here.</p>
      </Field>
      <div className="text-xs">
        Status:{" "}
        {acct?.registered
          ? <span className="text-emerald-400">registered</span>
          : <span className="text-yellow-300">not yet registered (will register on first cert issue)</span>}
      </div>
      <div className="flex justify-end">
        <button onClick={save} disabled={busy || !email.includes("@")}
          className="px-4 py-2 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
          {busy ? "Saving…" : "Save account"}
        </button>
      </div>
      {toast && (
        <div className={`fixed bottom-6 right-6 px-4 py-2 rounded shadow-lg text-sm ${toast.ok ? "bg-emerald-600" : "bg-red-600"} text-white`}>{toast.msg}</div>
      )}
    </div>
  );
}

/* ---------- Field shell (tiny; matches blocklists page) ---------- */

function Field({ label, children, error }: { label: React.ReactNode; children: React.ReactNode; error?: string | null }) {
  return (
    <div>
      <label className="block text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1">{label}</label>
      {children}
      {error && <div className="text-xs text-red-400 mt-1">{error}</div>}
    </div>
  );
}
