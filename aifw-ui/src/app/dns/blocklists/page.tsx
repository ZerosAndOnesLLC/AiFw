"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import Help, { HelpBanner } from "../Help";

/* ---------- Types ---------- */

interface BlocklistSource {
  id: number;
  name: string;
  category: string;
  url: string;
  format: "hosts" | "domains" | "adblock" | "rpz";
  enabled: boolean;
  action: "nxdomain" | "nodata" | "drop" | "redirect";
  redirect_ip: string | null;
  last_updated: number | null;
  last_sha256: string | null;
  rule_count: number;
  last_error: string | null;
  built_in: boolean;
}

interface BlocklistSchedule {
  cron: string;
  on_boot: boolean;
  concurrency: number;
  enabled: boolean;
}

interface PatternEntry {
  id: number;
  pattern: string;
  note: string | null;
}

interface RefreshOutcome {
  source_id: number;
  ok: boolean;
  rule_count: number;
  bytes: number;
  sha256: string;
  error: string | null;
}

const CATEGORIES = ["ads", "tracking", "malware", "phishing", "crypto", "adult", "social", "custom"];

/* ---------- Helpers ---------- */

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") || "" : "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: authHeaders(),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${res.status}: ${txt || res.statusText}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : (undefined as T);
}

function fmtTime(t: number | null): string {
  if (!t) return "never";
  return new Date(t * 1000).toLocaleString();
}

function fmtNum(n: number): string {
  return new Intl.NumberFormat().format(n);
}

const DOMAIN_RE = /^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const URL_RE = /^https?:\/\/[^\s]+$/i;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-f:]+$/i;

function validateDomainPattern(p: string): string | null {
  if (!p.trim()) return "required";
  if (!DOMAIN_RE.test(p.trim())) return "must look like example.com or *.example.com";
  return null;
}

function validateUrl(u: string): string | null {
  if (!u.trim()) return "required";
  if (!URL_RE.test(u.trim())) return "must be http:// or https://";
  return null;
}

function validateRedirectIp(ip: string): string | null {
  if (!ip.trim()) return "required when action=redirect";
  if (!IPV4_RE.test(ip.trim()) && !IPV6_RE.test(ip.trim())) return "must be a valid IP";
  return null;
}

/* ---------- Page ---------- */

export default function BlocklistsPage() {
  const [tab, setTab] = useState<"sources" | "custom" | "whitelist" | "schedule">("sources");
  const [masterEnabled, setMasterEnabled] = useState<boolean | null>(null);
  const [masterBusy, setMasterBusy] = useState(false);
  const [masterError, setMasterError] = useState<string | null>(null);

  const loadMaster = useCallback(async () => {
    try {
      const s = await api<BlocklistSchedule>("GET", "/api/v1/dns/blocklists/schedule");
      setMasterEnabled(s.enabled);
    } catch (e) {
      setMasterError(String(e));
    }
  }, []);

  useEffect(() => { loadMaster(); }, [loadMaster]);

  async function toggleMaster(next: boolean) {
    if (!next && !confirm("Disable DNS blocklisting? Every blocklist RPZ file will be removed and rDNS will reload. Whitelist and custom blocks are unaffected.")) return;
    setMasterBusy(true);
    setMasterError(null);
    try {
      await api("PUT", "/api/v1/dns/blocklists/enabled", { enabled: next });
      setMasterEnabled(next);
    } catch (e) {
      setMasterError(String(e));
    } finally {
      setMasterBusy(false);
    }
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold text-white flex items-center gap-2">
        DNS Blocklists
        <Help title="What is this?" size="md">
          Block ads, trackers, malware, and more by dropping their domains at the
          DNS layer. Each list is downloaded from the URL you provide, parsed,
          and converted to an RPZ zone for rDNS. rDNS does an O(1) lookup per
          query — performance impact is negligible.
        </Help>
      </h1>

      <div className={`rounded-lg border p-4 flex items-center gap-4 ${masterEnabled ? "border-emerald-500/40 bg-emerald-500/5" : "border-yellow-500/40 bg-yellow-500/5"}`}>
        <div className={`w-3 h-3 rounded-full ${masterEnabled ? "bg-emerald-400 animate-pulse" : "bg-yellow-400"}`} />
        <div className="flex-1">
          <div className="text-sm font-semibold text-white flex items-center gap-2">
            {masterEnabled === null ? "Loading…" : masterEnabled ? "DNS blocklisting is ON" : "DNS blocklisting is OFF"}
            <Help title="Master toggle" size="sm">
              This is the global on/off switch for DNS blocklisting. When OFF,
              no blocklist is enforced even if individual sources below are
              toggled on. Whitelist and custom blocks still apply — they are
              layered above blocklists.
            </Help>
          </div>
          <div className="text-xs text-[var(--text-muted)]">
            {masterEnabled
              ? "Enabled sources below are downloaded and enforced via rDNS RPZ."
              : "All blocklist RPZ files are removed from disk. Flip this on to start blocking."}
          </div>
          {masterError && <div className="text-xs text-red-400 mt-1">⚠ {masterError}</div>}
        </div>
        <label className="inline-flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            className="peer sr-only"
            checked={!!masterEnabled}
            disabled={masterBusy || masterEnabled === null}
            onChange={(e) => toggleMaster(e.target.checked)}
          />
          <span className="relative w-11 h-6 rounded-full bg-[var(--bg-card-secondary)] peer-checked:bg-emerald-600 transition-colors">
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${masterEnabled ? "translate-x-5" : ""}`} />
          </span>
          <span className="text-sm font-medium text-white">{masterEnabled ? "On" : "Off"}</span>
        </label>
      </div>

      <HelpBanner title="DNS blocklists — quick tour" storageKey="dns-blocklists">
        <p>
          <b>Sources</b> are the lists you want enforced. Built-in entries cover
          common categories (ads, malware, trackers); you can add your own.
          Toggling one off removes the file from disk and reloads rDNS — no
          restart.
        </p>
        <p>
          <b>Custom blocks</b> are admin-curated extra blocks layered on top.
          <b> Whitelist</b> entries are passthrough rules — they win over any
          blocklist. Both write to <code>custom.rpz</code>.
        </p>
        <p>
          <b>Schedule</b> controls when lists are re-downloaded. The work runs
          in the AiFw daemon, never the API process. Hash-based skip avoids
          re-writing files when upstream content has not changed.
        </p>
        <p>
          <b>Live dashboard</b>: see real-time block rate, top blocked domains,
          and per-list hit counters at <a className="text-blue-400 underline" href="/dns/dashboard">DNS → Live Dashboard</a>.
        </p>
      </HelpBanner>

      <div className="flex gap-2 border-b border-[var(--border)]">
        {([
          ["sources", "Sources"],
          ["custom", "Custom Blocks"],
          ["whitelist", "Whitelist"],
          ["schedule", "Schedule"],
        ] as const).map(([k, label]) => (
          <button
            key={k}
            onClick={() => setTab(k)}
            className={`px-4 py-2 text-sm font-semibold border-b-2 -mb-px transition-colors ${
              tab === k
                ? "border-blue-500 text-white"
                : "border-transparent text-[var(--text-muted)] hover:text-white"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "sources" && <SourcesTab />}
      {tab === "custom" && <PatternsTab kind="customblocks" title="Custom Blocks" hint="One pattern per row. Domains added here are always blocked." />}
      {tab === "whitelist" && <PatternsTab kind="whitelist" title="Whitelist" hint="Patterns added here pass through every blocklist." />}
      {tab === "schedule" && <ScheduleTab />}
    </div>
  );
}

/* ---------- Sources tab ---------- */

function SourcesTab() {
  const [sources, setSources] = useState<BlocklistSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshingId, setRefreshingId] = useState<number | null>(null);
  const [refreshingAll, setRefreshingAll] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api<BlocklistSource[]>("GET", "/api/v1/dns/blocklists");
      setSources(data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  function showToast(msg: string, ok: boolean) {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  }

  async function toggleEnabled(s: BlocklistSource) {
    try {
      await api("PUT", `/api/v1/dns/blocklists/${s.id}`, { enabled: !s.enabled });
      await reload();
    } catch (e) {
      showToast(String(e), false);
    }
  }

  async function changeAction(s: BlocklistSource, action: BlocklistSource["action"]) {
    try {
      const body: Record<string, unknown> = { action };
      if (action === "redirect" && !s.redirect_ip) body.redirect_ip = "0.0.0.0";
      await api("PUT", `/api/v1/dns/blocklists/${s.id}`, body);
      await reload();
    } catch (e) {
      showToast(String(e), false);
    }
  }

  async function refreshOne(id: number) {
    setRefreshingId(id);
    try {
      const out = await api<RefreshOutcome>("POST", `/api/v1/dns/blocklists/${id}/refresh`);
      showToast(out.ok ? `Refreshed: ${fmtNum(out.rule_count)} rules` : `Failed: ${out.error}`, out.ok);
      await reload();
    } catch (e) {
      showToast(String(e), false);
    } finally {
      setRefreshingId(null);
    }
  }

  async function refreshAll() {
    setRefreshingAll(true);
    try {
      const outs = await api<RefreshOutcome[]>("POST", "/api/v1/dns/blocklists/refresh-all");
      const ok = outs.filter((o) => o.ok).length;
      showToast(`Refreshed ${ok}/${outs.length} sources`, ok === outs.length);
      await reload();
    } catch (e) {
      showToast(String(e), false);
    } finally {
      setRefreshingAll(false);
    }
  }

  async function remove(s: BlocklistSource) {
    if (!confirm(`Delete "${s.name}"?`)) return;
    try {
      await api("DELETE", `/api/v1/dns/blocklists/${s.id}`);
      await reload();
    } catch (e) {
      showToast(String(e), false);
    }
  }

  const grouped = useMemo(() => {
    const g: Record<string, BlocklistSource[]> = {};
    for (const s of sources) {
      g[s.category] = g[s.category] || [];
      g[s.category].push(s);
    }
    return g;
  }, [sources]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-[var(--text-muted)]">
          {sources.filter((s) => s.enabled).length} enabled · {fmtNum(sources.reduce((a, s) => a + (s.enabled ? s.rule_count : 0), 0))} total rules
        </div>
        <div className="flex gap-2">
          <button
            onClick={refreshAll}
            disabled={refreshingAll}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
          >
            {refreshingAll ? "Refreshing…" : "Refresh all enabled"}
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white"
          >
            + Add custom list
          </button>
        </div>
      </div>

      {loading && <div className="text-[var(--text-muted)]">Loading…</div>}

      {!loading && Object.keys(grouped).sort().map((cat) => (
        <section key={cat} className="border border-[var(--border)] rounded-lg overflow-hidden">
          <header className="bg-[var(--bg-card-secondary)] px-4 py-2 text-sm font-semibold uppercase tracking-wide text-[var(--text-muted)] flex items-center gap-2">
            {cat}
            <Help title={`${cat} blocklists`} size="xs">
              Lists in the <b>{cat}</b> category. Toggle individual sources on/off.
              Lists keep their per-zone hit counter on the live dashboard.
            </Help>
            <span className="ml-auto text-xs">
              {grouped[cat].filter((s) => s.enabled).length}/{grouped[cat].length} enabled
            </span>
          </header>
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-[var(--text-muted)]">
              <tr>
                <th className="px-3 py-2 w-8"></th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Format</th>
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2 text-right">Rules</th>
                <th className="px-3 py-2">Last update</th>
                <th className="px-3 py-2 w-32"></th>
              </tr>
            </thead>
            <tbody>
              {grouped[cat].map((s) => (
                <tr key={s.id} className="border-t border-[var(--border)]">
                  <td className="px-3 py-2">
                    <input type="checkbox" checked={s.enabled} onChange={() => toggleEnabled(s)} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-white font-medium">{s.name} {s.built_in && <span className="text-[10px] uppercase ml-1 px-1 rounded bg-blue-500/20 text-blue-300">built-in</span>}</div>
                    <div className="text-[10px] text-[var(--text-muted)] truncate max-w-md" title={s.url}>{s.url}</div>
                    {s.last_error && <div className="text-[10px] text-red-400">⚠ {s.last_error}</div>}
                  </td>
                  <td className="px-3 py-2 text-[var(--text-muted)]">{s.format}</td>
                  <td className="px-3 py-2">
                    <select
                      value={s.action}
                      onChange={(e) => changeAction(s, e.target.value as BlocklistSource["action"])}
                      className="bg-transparent border border-[var(--border)] rounded px-1 py-0.5 text-xs"
                    >
                      <option value="nxdomain">NXDOMAIN</option>
                      <option value="nodata">NODATA</option>
                      <option value="redirect">Redirect</option>
                      <option value="drop">Drop</option>
                    </select>
                  </td>
                  <td className="px-3 py-2 text-right tabular-nums">{fmtNum(s.rule_count)}</td>
                  <td className="px-3 py-2 text-xs text-[var(--text-muted)]">{fmtTime(s.last_updated)}</td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => refreshOne(s.id)}
                      disabled={refreshingId === s.id}
                      className="px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-blue-600 hover:text-white disabled:opacity-50"
                      title="Refresh now"
                    >
                      {refreshingId === s.id ? "…" : "↻"}
                    </button>
                    {!s.built_in && (
                      <button
                        onClick={() => remove(s)}
                        className="ml-1 px-2 py-1 text-xs rounded bg-[var(--bg-card-secondary)] hover:bg-red-600 hover:text-white"
                        title="Delete"
                      >
                        ✕
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}

      {showAdd && <AddSourceModal onClose={() => setShowAdd(false)} onCreated={async () => { setShowAdd(false); await reload(); }} />}

      {toast && (
        <div className={`fixed bottom-6 right-6 px-4 py-2 rounded shadow-lg text-sm ${toast.ok ? "bg-emerald-600" : "bg-red-600"} text-white`}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

/* ---------- Add source modal ---------- */

function AddSourceModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [category, setCategory] = useState("ads");
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState<BlocklistSource["format"]>("hosts");
  const [action, setAction] = useState<BlocklistSource["action"]>("nxdomain");
  const [redirectIp, setRedirectIp] = useState("0.0.0.0");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const errors = {
    name: name.trim() ? null : "required",
    url: validateUrl(url),
    redirect_ip: action === "redirect" ? validateRedirectIp(redirectIp) : null,
  };
  const valid = !errors.name && !errors.url && !errors.redirect_ip;

  async function submit() {
    if (!valid) return;
    setBusy(true);
    setErr(null);
    try {
      await api("POST", "/api/v1/dns/blocklists", {
        name: name.trim(),
        category,
        url: url.trim(),
        format,
        enabled: true,
        action,
        redirect_ip: action === "redirect" ? redirectIp.trim() : null,
      });
      onCreated();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5 w-full max-w-md space-y-3" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          Add custom blocklist
          <Help title="Custom blocklists" size="sm">
            Point to any HTTP(S) URL serving one of the supported formats. The
            list is fetched on save and on every scheduled refresh.
          </Help>
        </h2>

        <Field label="Name" error={errors.name}>
          <input value={name} onChange={(e) => setName(e.target.value)} className="form-input" placeholder="My blocklist" />
        </Field>

        <Field label="Category">
          <select value={category} onChange={(e) => setCategory(e.target.value)} className="form-input">
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </Field>

        <Field label="URL" error={errors.url}>
          <input value={url} onChange={(e) => setUrl(e.target.value)} className="form-input" placeholder="https://example.com/list.txt" />
        </Field>

        <Field label={<span>Format <Help title="Format options" size="xs">
          <p><b>hosts</b> — <code>0.0.0.0 example.com</code> per line</p>
          <p><b>domains</b> — bare domains, one per line</p>
          <p><b>adblock</b> — <code>||example.com^</code> filter syntax</p>
          <p><b>rpz</b> — already an RPZ zone file</p>
        </Help></span>}>
          <select value={format} onChange={(e) => setFormat(e.target.value as BlocklistSource["format"])} className="form-input">
            <option value="hosts">hosts</option>
            <option value="domains">domains</option>
            <option value="adblock">adblock</option>
            <option value="rpz">rpz</option>
          </select>
        </Field>

        <Field label={<span>Action <Help title="Action when matched" size="xs">
          <p><b>NXDOMAIN</b> — no such domain (browser shows error fastest)</p>
          <p><b>NODATA</b> — domain exists, no records (silent stall)</p>
          <p><b>Redirect</b> — point to an IP you control (sinkhole)</p>
          <p><b>Drop</b> — silent drop, no response at all</p>
        </Help></span>}>
          <select value={action} onChange={(e) => setAction(e.target.value as BlocklistSource["action"])} className="form-input">
            <option value="nxdomain">NXDOMAIN</option>
            <option value="nodata">NODATA</option>
            <option value="redirect">Redirect</option>
            <option value="drop">Drop</option>
          </select>
        </Field>

        {action === "redirect" && (
          <Field label="Redirect IP" error={errors.redirect_ip}>
            <input value={redirectIp} onChange={(e) => setRedirectIp(e.target.value)} className="form-input" placeholder="0.0.0.0" />
          </Field>
        )}

        {err && <div className="text-sm text-red-400">⚠ {err}</div>}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="px-3 py-1.5 text-sm rounded bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)]">Cancel</button>
          <button
            onClick={submit}
            disabled={!valid || busy}
            className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ---------- Patterns (whitelist / customblocks) tabs ---------- */

function PatternsTab({ kind, title, hint }: { kind: "whitelist" | "customblocks"; title: string; hint: string }) {
  const [items, setItems] = useState<PatternEntry[]>([]);
  const [pattern, setPattern] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const data = await api<PatternEntry[]>("GET", `/api/v1/dns/${kind}`);
    setItems(data);
  }, [kind]);

  useEffect(() => { reload(); }, [reload]);

  const validationError = pattern ? validateDomainPattern(pattern) : null;

  async function add() {
    if (!pattern || validationError) return;
    setBusy(true);
    setErr(null);
    try {
      await api("POST", `/api/v1/dns/${kind}`, { pattern: pattern.trim(), note: note.trim() || null });
      setPattern("");
      setNote("");
      await reload();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number) {
    if (!confirm("Delete this entry?")) return;
    try {
      await api("DELETE", `/api/v1/dns/${kind}/${id}`);
      await reload();
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <h2 className="text-lg font-semibold text-white">{title}</h2>
        <Help title={title} size="sm">{hint}</Help>
      </div>
      <p className="text-sm text-[var(--text-muted)]">{hint}</p>

      <div className="border border-[var(--border)] rounded p-3 space-y-2">
        <div className="grid grid-cols-[1fr_1fr_auto] gap-2 items-start">
          <div>
            <input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="example.com or *.example.com"
              className="form-input w-full"
            />
            {validationError && <div className="text-xs text-red-400 mt-1">{validationError}</div>}
          </div>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Optional note"
            className="form-input w-full"
          />
          <button
            onClick={add}
            disabled={busy || !pattern || !!validationError}
            className="px-3 py-1.5 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50"
          >
            Add
          </button>
        </div>
        {err && <div className="text-sm text-red-400">⚠ {err}</div>}
      </div>

      <div className="border border-[var(--border)] rounded">
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-[var(--text-muted)]">
            <tr>
              <th className="px-3 py-2">Pattern</th>
              <th className="px-3 py-2">Note</th>
              <th className="px-3 py-2 w-16"></th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={3} className="px-3 py-4 text-center text-[var(--text-muted)]">No entries yet</td></tr>
            )}
            {items.map((it) => (
              <tr key={it.id} className="border-t border-[var(--border)]">
                <td className="px-3 py-2 font-mono text-white">{it.pattern}</td>
                <td className="px-3 py-2 text-[var(--text-muted)]">{it.note || "—"}</td>
                <td className="px-3 py-2 text-right">
                  <button onClick={() => remove(it.id)} className="px-2 py-1 text-xs rounded hover:bg-red-600 hover:text-white">✕</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------- Schedule tab ---------- */

function ScheduleTab() {
  const [sched, setSched] = useState<BlocklistSchedule | null>(null);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);

  useEffect(() => {
    (async () => setSched(await api<BlocklistSchedule>("GET", "/api/v1/dns/blocklists/schedule")))();
  }, []);

  if (!sched) return <div className="text-[var(--text-muted)]">Loading…</div>;

  const cronError = !sched.cron.trim() ? "required" : null;
  const concurrencyError = sched.concurrency < 1 || sched.concurrency > 32 ? "must be 1..32" : null;
  const valid = !cronError && !concurrencyError;

  async function save() {
    if (!valid) return;
    setSaving(true);
    setErr(null);
    setOkMsg(null);
    try {
      const next = await api<BlocklistSchedule>("PUT", "/api/v1/dns/blocklists/schedule", sched);
      setSched(next);
      setOkMsg("Saved");
      setTimeout(() => setOkMsg(null), 2000);
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function runNow() {
    setSaving(true);
    setErr(null);
    try {
      await api("POST", "/api/v1/dns/blocklists/refresh-all");
      setOkMsg("Refresh kicked off");
      setTimeout(() => setOkMsg(null), 2000);
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4 max-w-xl">
      <p className="text-sm text-[var(--text-muted)]">
        The blocklist scheduler runs in the AiFw daemon. The API is never blocked
        by downloads.
      </p>

      <Field label={<span>Cron expression <Help title="Cron format" size="xs">
        <p>6-field cron (sec min hour dom mon dow). Examples:</p>
        <ul className="list-disc list-inside">
          <li><code>0 0 3 * * *</code> — every day at 03:00</li>
          <li><code>0 0 */6 * * *</code> — every 6 hours</li>
          <li><code>0 0 4 * * SUN</code> — Sundays at 04:00</li>
        </ul>
      </Help></span>} error={cronError}>
        <input value={sched.cron} onChange={(e) => setSched({ ...sched, cron: e.target.value })} className="form-input font-mono" />
      </Field>

      <Field label="Concurrency" error={concurrencyError}>
        <input
          type="number"
          min={1}
          max={32}
          value={sched.concurrency}
          onChange={(e) => setSched({ ...sched, concurrency: Number(e.target.value) })}
          className="form-input w-32"
        />
        <span className="text-xs text-[var(--text-muted)] ml-2">simultaneous downloads</span>
      </Field>

      <Field label={<span>Run on boot <Help title="On-boot refresh" size="xs">When enabled, the daemon refreshes all enabled lists ~15s after start.</Help></span>}>
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={sched.on_boot} onChange={(e) => setSched({ ...sched, on_boot: e.target.checked })} />
          <span className="text-sm">Enabled</span>
        </label>
      </Field>

      {err && <div className="text-sm text-red-400">⚠ {err}</div>}
      {okMsg && <div className="text-sm text-emerald-400">✓ {okMsg}</div>}

      <div className="flex gap-2 pt-2">
        <button onClick={save} disabled={!valid || saving} className="px-4 py-2 text-sm rounded bg-blue-600 hover:bg-blue-500 text-white disabled:opacity-50">
          {saving ? "Saving…" : "Save schedule"}
        </button>
        <button onClick={runNow} disabled={saving} className="px-4 py-2 text-sm rounded bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-50">
          Run now
        </button>
      </div>
    </div>
  );
}

/* ---------- Field shell ---------- */

function Field({ label, children, error }: { label: React.ReactNode; children: React.ReactNode; error?: string | null }) {
  return (
    <div>
      <label className="block text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1">{label}</label>
      {children}
      {error && <div className="text-xs text-red-400 mt-1">{error}</div>}
    </div>
  );
}
