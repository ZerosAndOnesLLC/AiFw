"use client";

import { useCallback, useEffect, useState } from "react";
import Help, { HelpBanner } from "./Help";

interface DdnsRecord {
  id: number;
  provider_id: number;
  provider_name: string;
  hostname: string;
  record_type: "a" | "aaaa" | "both";
  source: "auto-public" | "interface" | "explicit";
  interface: string | null;
  explicit_ip: string | null;
  ttl: number;
  enabled: boolean;
  last_ip: string | null;
  last_ipv6: string | null;
  last_updated: string | null;
  last_status: string | null;
  last_error: string | null;
}

interface DnsProvider {
  id: number;
  name: string;
  kind: "cloudflare" | "route53" | "digitalocean" | "rfc2136" | "manual";
  zone: string;
}

interface DdnsConfig {
  poll_interval_secs: number;
  ip_echo_url_v4: string;
  ip_echo_url_v6: string;
}

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
function fmtWhen(s: string | null): string {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

export default function DdnsPage() {
  const [records, setRecords] = useState<DdnsRecord[]>([]);
  const [providers, setProviders] = useState<DnsProvider[]>([]);
  const [config, setConfig] = useState<DdnsConfig | null>(null);
  const [editing, setEditing] = useState<DdnsRecord | "new" | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);

  const reload = useCallback(async () => {
    const [r, p, c] = await Promise.all([
      api<DdnsRecord[]>("GET", "/api/v1/ddns/records"),
      api<DnsProvider[]>("GET", "/api/v1/acme/dns-providers"),
      api<DdnsConfig>("GET", "/api/v1/ddns/config"),
    ]);
    setRecords(r);
    // Cloudflare + Route53 only — manual / unimplemented can't auto-update.
    setProviders(p.filter((x) => x.kind === "cloudflare" || x.kind === "route53"));
    setConfig(c);
  }, []);
  useEffect(() => { reload(); }, [reload]);

  function showToast(ok: boolean, msg: string) {
    setToast({ ok, msg });
    setTimeout(() => setToast(null), 6000);
  }

  async function forceUpdate(id: number) {
    setBusy(id);
    try {
      const r = await api<{ ok: boolean; message: string }>("POST", `/api/v1/ddns/records/${id}/update`);
      showToast(r.ok, r.message);
      await reload();
    } catch (e) { showToast(false, String(e)); }
    finally { setBusy(null); }
  }

  async function remove(id: number) {
    if (!confirm("Delete this DDNS record? It will not remove the actual DNS record at the provider.")) return;
    await api("DELETE", `/api/v1/ddns/records/${id}`);
    await reload();
  }

  async function toggleEnabled(rec: DdnsRecord) {
    await api("PUT", `/api/v1/ddns/records/${rec.id}`, {
      provider_id: rec.provider_id,
      hostname: rec.hostname,
      record_type: rec.record_type,
      source: rec.source,
      interface: rec.interface,
      explicit_ip: rec.explicit_ip,
      ttl: rec.ttl,
      enabled: !rec.enabled,
    });
    await reload();
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2">
        Dynamic DNS
        <Help title="What is this?" size="md">
          Keep a hostname pointed at the appliance&apos;s current WAN IP.
          When your ISP changes your IP, AiFw detects it and updates the
          A (and/or AAAA) record at your DNS provider. Uses the same
          provider credentials as ACME, so configure once, use both.
        </Help>
      </h1>

      <HelpBanner title="How DDNS works here" storageKey="ddns-overview">
        <p>
          Each <b>record</b> is a (hostname → provider) binding plus how
          to learn the current IP: <i>auto-public</i> (query a public
          IP-echo service), <i>interface</i> (read the IP off a local NIC),
          or <i>explicit</i> (a fixed IP). The daemon polls every
          <code> poll_interval_secs</code> (default 5 min) and only calls
          the provider when the IP has actually changed.
        </p>
        <p>
          <b>Cloudflare</b> needs <code>Zone:DNS:Edit</code>;
          <b> Route53</b> needs <code>route53:ChangeResourceRecordSets</code>.
          Configure those in <a className="text-blue-400 underline" href="/acme">ACME → DNS Providers</a>.
        </p>
      </HelpBanner>

      {config && (
        <div className="border border-[var(--border)] rounded p-3 grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          <div>
            <div className="text-[var(--text-muted)] uppercase tracking-wider">Poll interval</div>
            <div className="text-white font-mono">{config.poll_interval_secs}s</div>
          </div>
          <div>
            <div className="text-[var(--text-muted)] uppercase tracking-wider">v4 echo</div>
            <div className="text-white font-mono truncate">{config.ip_echo_url_v4}</div>
          </div>
          <div>
            <div className="text-[var(--text-muted)] uppercase tracking-wider">v6 echo</div>
            <div className="text-white font-mono truncate">{config.ip_echo_url_v6}</div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="text-sm text-[var(--text-muted)]">{records.length} record{records.length === 1 ? "" : "s"}</div>
        <button onClick={() => setEditing("new")}
          className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white">+ Add record</button>
      </div>

      {records.length === 0 && (
        <div className="text-sm text-[var(--text-muted)] border border-dashed border-[var(--border)] rounded p-6 text-center">
          No DDNS records yet. Configure a Cloudflare or Route53 provider in <a className="text-blue-400 underline" href="/acme">ACME → DNS Providers</a> first.
        </div>
      )}

      <div className="space-y-2">
        {records.map((r) => (
          <div key={r.id} className="border border-[var(--border)] rounded px-3 py-2 grid grid-cols-[auto_1fr_auto_auto_auto_auto] gap-3 items-center text-sm">
            <input type="checkbox" checked={r.enabled} onChange={() => toggleEnabled(r)} />
            <div>
              <div className="text-white font-semibold">{r.hostname} <span className="text-[10px] text-[var(--text-muted)] uppercase">{r.record_type}</span></div>
              <div className="text-[10px] text-[var(--text-muted)]">
                {r.provider_name} · {r.source}
                {r.source === "interface" && r.interface && <> ({r.interface})</>}
                {r.source === "explicit" && r.explicit_ip && <> ({r.explicit_ip})</>}
                {" · ttl "}{r.ttl}s
              </div>
              {r.last_error && <div className="text-[10px] text-red-400 mt-0.5">⚠ {r.last_error}</div>}
            </div>
            <div className="text-xs">
              <div className="font-mono text-white">{r.last_ip || "—"}</div>
              {r.last_ipv6 && <div className="font-mono text-[10px] text-[var(--text-muted)]">{r.last_ipv6}</div>}
            </div>
            <div className="text-xs text-[var(--text-muted)]">{fmtWhen(r.last_updated)}</div>
            <span className={`px-2 py-0.5 rounded text-[10px] ${
              r.last_status === "updated" ? "bg-emerald-500/15 text-emerald-300" :
              r.last_status === "unchanged" ? "bg-blue-500/15 text-blue-300" :
              r.last_status === "error" ? "bg-red-500/15 text-red-300" :
                                          "bg-gray-500/15 text-gray-300"
            }`}>{r.last_status || "pending"}</span>
            <div className="flex gap-1">
              <button onClick={() => forceUpdate(r.id)} disabled={busy === r.id}
                className="px-2 py-1 text-xs rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
                {busy === r.id ? "…" : "Update"}
              </button>
              <button onClick={() => setEditing(r)}
                className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Edit</button>
              <button onClick={() => remove(r.id)}
                className="px-2 py-1 text-xs rounded hover:bg-red-600 hover:text-white">✕</button>
            </div>
          </div>
        ))}
      </div>

      {config && <ConfigCard config={config} onSaved={reload} />}

      {editing && <RecordModal initial={editing === "new" ? null : editing}
        providers={providers}
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

function ConfigCard({ config, onSaved }: { config: DdnsConfig; onSaved: () => void }) {
  const [interval, setInterval] = useState(config.poll_interval_secs);
  const [v4, setV4] = useState(config.ip_echo_url_v4);
  const [v6, setV6] = useState(config.ip_echo_url_v6);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function save() {
    setBusy(true); setErr(null);
    try {
      await api("PUT", "/api/v1/ddns/config", {
        poll_interval_secs: Number(interval) || 300,
        ip_echo_url_v4: v4.trim(),
        ip_echo_url_v6: v6.trim(),
      });
      onSaved();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <details className="border border-[var(--border)] rounded p-3">
      <summary className="cursor-pointer text-sm text-[var(--text-muted)]">Scheduler settings</summary>
      <div className="mt-3 space-y-3 max-w-xl">
        <Field label={<>Poll interval (seconds) <Help title="Cadence" size="xs">60..86400. Lower = faster reaction to IP changes; higher = fewer API calls.</Help></>}>
          <input type="number" min={60} max={86400} value={interval} onChange={(e) => setInterval(Number(e.target.value) || 300)} className="form-input w-32" />
        </Field>
        <Field label="IPv4 echo URL">
          <input value={v4} onChange={(e) => setV4(e.target.value)} className="form-input font-mono text-xs" />
        </Field>
        <Field label="IPv6 echo URL">
          <input value={v6} onChange={(e) => setV6(e.target.value)} className="form-input font-mono text-xs" />
        </Field>
        {err && <div className="text-xs text-red-400">⚠ {err}</div>}
        <div className="flex justify-end">
          <button onClick={save} disabled={busy}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
            {busy ? "Saving…" : "Save scheduler settings"}
          </button>
        </div>
      </div>
    </details>
  );
}

function RecordModal({ initial, providers, onClose, onSaved }:
  { initial: DdnsRecord | null; providers: DnsProvider[]; onClose: () => void; onSaved: () => void }) {
  const isNew = !initial;
  const [providerId, setProviderId] = useState<number | "">(initial?.provider_id || (providers[0]?.id ?? ""));
  const [hostname, setHostname] = useState(initial?.hostname || "");
  const [recordType, setRecordType] = useState<"a" | "aaaa" | "both">(initial?.record_type || "a");
  const [source, setSource] = useState<"auto-public" | "interface" | "explicit">(initial?.source || "auto-public");
  const [iface, setIface] = useState(initial?.interface || "");
  const [explicitIp, setExplicitIp] = useState(initial?.explicit_ip || "");
  const [ttl, setTtl] = useState(initial?.ttl || 60);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const hostnameErr = hostname && !DOMAIN_RE.test(hostname.trim()) ? "must be a FQDN like home.example.com" : null;
  const valid = !!hostname.trim() && !hostnameErr && providerId !== ""
    && (source !== "interface" || !!iface.trim())
    && (source !== "explicit"  || !!explicitIp.trim());

  async function submit() {
    if (!valid) return;
    setBusy(true); setErr(null);
    try {
      const body = {
        provider_id: providerId,
        hostname: hostname.trim(),
        record_type: recordType,
        source,
        interface: source === "interface" ? iface.trim() : null,
        explicit_ip: source === "explicit" ? explicitIp.trim() : null,
        ttl,
        enabled,
      };
      if (isNew) await api("POST", "/api/v1/ddns/records", body);
      else       await api("PUT", `/api/v1/ddns/records/${initial!.id}`, body);
      onSaved();
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 w-full max-w-md space-y-3" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white">{isNew ? "Add" : "Edit"} DDNS record</h2>

        <Field label="DNS provider">
          {providers.length === 0 ? (
            <div className="text-xs text-yellow-300">No DDNS-capable providers. Add a Cloudflare or Route53 provider in ACME first.</div>
          ) : (
            <select value={providerId} onChange={(e) => setProviderId(Number(e.target.value) || "")} className="form-input">
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.kind} → {p.zone})</option>)}
            </select>
          )}
        </Field>

        <Field label="Hostname (FQDN)" error={hostnameErr}>
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} className="form-input" placeholder="home.example.com" />
        </Field>

        <Field label={<>Record type <Help title="A vs AAAA vs both" size="xs">
          <p><b>A:</b> publish IPv4 only.</p>
          <p><b>AAAA:</b> publish IPv6 only.</p>
          <p><b>Both:</b> publish both — useful for dual-stack appliances.</p>
        </Help></>}>
          <select value={recordType} onChange={(e) => setRecordType(e.target.value as "a" | "aaaa" | "both")} className="form-input">
            <option value="a">A (IPv4)</option>
            <option value="aaaa">AAAA (IPv6)</option>
            <option value="both">Both</option>
          </select>
        </Field>

        <Field label={<>How to learn the IP <Help title="Source" size="xs">
          <p><b>auto-public:</b> ask a public IP-echo service over HTTPS. Use this for the typical "what is my WAN IP" case behind ISP NAT.</p>
          <p><b>interface:</b> read the primary IP off a named local interface. Use this when the appliance has a real public IP on its WAN NIC.</p>
          <p><b>explicit:</b> always publish a fixed IP. Useful for one-off manual records.</p>
        </Help></>}>
          <select value={source} onChange={(e) => setSource(e.target.value as "auto-public" | "interface" | "explicit")} className="form-input">
            <option value="auto-public">auto-public (HTTPS IP echo)</option>
            <option value="interface">interface (read local NIC)</option>
            <option value="explicit">explicit (fixed IP)</option>
          </select>
        </Field>

        {source === "interface" && (
          <Field label="Interface name">
            <input value={iface} onChange={(e) => setIface(e.target.value)} className="form-input" placeholder="vtnet0 / em0 / wan0" />
          </Field>
        )}
        {source === "explicit" && (
          <Field label="Explicit IP">
            <input value={explicitIp} onChange={(e) => setExplicitIp(e.target.value)} className="form-input" placeholder="203.0.113.1 or 2001:db8::1" />
          </Field>
        )}

        <Field label="TTL (seconds)">
          <input type="number" min={60} max={86400} value={ttl} onChange={(e) => setTtl(Number(e.target.value) || 60)} className="form-input w-28" />
        </Field>

        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>Enabled</span>
        </label>

        {err && <div className="text-sm text-red-400">⚠ {err}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Cancel</button>
          <button onClick={submit} disabled={!valid || busy}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children, error }: { label: React.ReactNode; children: React.ReactNode; error?: string | null }) {
  return (
    <div>
      <label className="block text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1">{label}</label>
      {children}
      {error && <div className="text-xs text-red-400 mt-1">{error}</div>}
    </div>
  );
}
