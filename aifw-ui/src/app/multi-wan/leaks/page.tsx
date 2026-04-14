"use client";

import { useState, useEffect, useCallback } from "react";
import Help, { HelpBanner } from "../Help";
import {
  api,
  RouteLeak,
  RoutingInstance,
  validateCidr,
  validateName,
  validatePortSpec,
} from "../lib";

const DIRECTIONS = [
  { value: "bidirectional", label: "Bidirectional" },
  { value: "one_way", label: "One-way (src → dst only)" },
];
const PROTOS = ["any", "tcp", "udp", "icmp"];

export default function LeaksPage() {
  const [leaks, setLeaks] = useState<RouteLeak[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState({
    name: "",
    src_instance_id: "",
    dst_instance_id: "",
    prefix: "any",
    protocol: "any",
    ports: "",
    direction: "bidirectional",
    enabled: true,
  });
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [l, i] = await Promise.all([
        api<{ data: RouteLeak[] }>("GET", "/api/v1/multiwan/leaks"),
        api<{ data: RoutingInstance[] }>("GET", "/api/v1/multiwan/instances"),
      ]);
      setLeaks(l.data);
      setInstances(i.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function validate() {
    const e: Record<string, string> = {};
    const n = validateName(form.name);
    if (n) e.name = n;
    if (!form.src_instance_id) e.src_instance_id = "required";
    if (!form.dst_instance_id) e.dst_instance_id = "required";
    if (form.src_instance_id === form.dst_instance_id && form.src_instance_id !== "")
      e.dst_instance_id = "must differ from source";
    const c = validateCidr(form.prefix);
    if (c) e.prefix = c;
    const p = validatePortSpec(form.ports);
    if (p) e.ports = p;
    setErrs(e);
    return Object.keys(e).length === 0;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api("POST", "/api/v1/multiwan/leaks", {
        ...form,
        ports: form.ports || null,
      });
      setForm({
        name: "",
        src_instance_id: "",
        dst_instance_id: "",
        prefix: "any",
        protocol: "any",
        ports: "",
        direction: "bidirectional",
        enabled: true,
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function deleteLeak(id: string) {
    if (!confirm("Delete route leak? This may break connectivity.")) return;
    try {
      await api("DELETE", `/api/v1/multiwan/leaks/${id}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
    }
  }

  async function seedMgmt() {
    if (!confirm("Seed management-escape leaks for all instances?")) return;
    try {
      await api("POST", "/api/v1/multiwan/leaks/seed-mgmt", {});
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "seed failed");
    }
  }

  function instanceLabel(id: string): string {
    const i = instances.find((x) => x.id === id);
    return i ? `${i.name} (FIB ${i.fib_number})` : id;
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Route Leaks
            <Help title="Route leaks" size="md">
              <p>
                FIBs are isolated by default — traffic in FIB 2 can&apos;t reach
                FIB 0. That&apos;s great for segmentation, bad for shared
                services like DNS, NTP, and the admin API.
              </p>
              <p>
                A <b>leak</b> is an explicit pf pass rule that lets specified
                traffic cross from one FIB to another. It&apos;s the declarative
                equivalent of Juniper&apos;s <i>rib-groups</i>.
              </p>
              <p>
                Each leak compiles into a <code>pass ... rtable N</code> rule in
                the <code>aifw-mwan-leak</code> anchor.
              </p>
            </Help>
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Cross-FIB passthrough for shared services (DNS, mgmt). Juniper rib-groups analogue.
          </p>
        </div>
        <button
          onClick={seedMgmt}
          className="px-3 py-2 rounded bg-purple-600 hover:bg-purple-700 text-white text-sm"
        >
          Auto-seed mgmt escapes
        </button>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      <HelpBanner title="Why leaks matter" storageKey="mwan-leaks">
        <p>
          Without leaks, a host in FIB 2 has no path back to the management
          network, can&apos;t resolve DNS against an internal resolver, and
          can&apos;t see the admin API. That usually locks you out.
        </p>
        <p>
          Click <b>Auto-seed mgmt escapes</b> to create safe default leaks from
          every non-default instance back to FIB 0. These are marked so they
          can&apos;t be accidentally deleted (API returns 409).
        </p>
        <p>
          <b>Direction:</b> <code>bidirectional</code> emits reverse-path
          leaks too (needed for stateful services). <code>one_way</code> is
          useful for asymmetric cases like log-shipping out but nothing in.
        </p>
      </HelpBanner>

      <form
        onSubmit={submit}
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3"
      >
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          Create leak
          <Help title="Leak fields">
            <p>
              <b>From / To instance:</b> source and destination FIBs. Traffic
              in source FIB is allowed to reach addresses in dest FIB&apos;s
              prefix.
            </p>
            <p>
              <b>Prefix:</b> the allowed network (e.g. <code>10.0.0.0/24</code>)
              or <code>any</code> for everything. <code>any</code> is how
              auto-seeded mgmt escapes work.
            </p>
            <p>
              <b>Protocol / Ports:</b> narrow to specific services
              (<code>tcp 8080</code>, <code>udp 53,853</code>) to minimize
              attack surface.
            </p>
          </Help>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Field label="Name" err={errs.name}>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className={cls(!!errs.name)}
            />
          </Field>
          <Field label="From instance" err={errs.src_instance_id}>
            <select
              value={form.src_instance_id}
              onChange={(e) => setForm({ ...form, src_instance_id: e.target.value })}
              className={cls(!!errs.src_instance_id)}
            >
              <option value="">Select…</option>
              {instances.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name} (FIB {i.fib_number})
                </option>
              ))}
            </select>
          </Field>
          <Field label="To instance" err={errs.dst_instance_id}>
            <select
              value={form.dst_instance_id}
              onChange={(e) => setForm({ ...form, dst_instance_id: e.target.value })}
              className={cls(!!errs.dst_instance_id)}
            >
              <option value="">Select…</option>
              {instances.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name} (FIB {i.fib_number}){i.mgmt_reachable ? " 🛡️" : ""}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Prefix" err={errs.prefix}>
            <input
              value={form.prefix}
              onChange={(e) => setForm({ ...form, prefix: e.target.value })}
              placeholder="10.0.0.0/24 or any"
              className={cls(!!errs.prefix)}
            />
          </Field>
          <Field label="Protocol">
            <select
              value={form.protocol}
              onChange={(e) => setForm({ ...form, protocol: e.target.value })}
              className={cls(false)}
            >
              {PROTOS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Ports (optional)" err={errs.ports}>
            <input
              value={form.ports}
              onChange={(e) => setForm({ ...form, ports: e.target.value })}
              placeholder="53 or 53,853"
              className={cls(!!errs.ports)}
            />
          </Field>
          <Field label="Direction">
            <select
              value={form.direction}
              onChange={(e) => setForm({ ...form, direction: e.target.value })}
              className={cls(false)}
            >
              {DIRECTIONS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <button
          type="submit"
          disabled={submitting}
          className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
        >
          {submitting ? "Creating…" : "Create leak"}
        </button>
      </form>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : leaks.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">No leaks.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">From</th>
                <th className="text-left px-4 py-2">To</th>
                <th className="text-left px-4 py-2">Prefix</th>
                <th className="text-left px-4 py-2">Proto/Port</th>
                <th className="text-left px-4 py-2">Direction</th>
                <th className="text-right px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {leaks.map((l) => (
                <tr key={l.id} className="border-t border-[var(--border)]">
                  <td className="px-4 py-3 text-white">{l.name}</td>
                  <td className="px-4 py-3 text-cyan-400 text-xs">
                    {instanceLabel(l.src_instance_id)}
                  </td>
                  <td className="px-4 py-3 text-green-400 text-xs">
                    {instanceLabel(l.dst_instance_id)}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{l.prefix}</td>
                  <td className="px-4 py-3 text-xs text-[var(--text-muted)]">
                    {l.protocol}
                    {l.ports && ` :${l.ports}`}
                  </td>
                  <td className="px-4 py-3 text-xs">{l.direction}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => deleteLeak(l.id)}
                      className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                    >
                      Del
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function cls(hasErr: boolean): string {
  return `w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
    hasErr ? "border-red-500" : "border-[var(--border)]"
  }`;
}

function Field({
  label,
  err,
  children,
}: {
  label: string;
  err?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs text-[var(--text-muted)] mb-1">{label}</label>
      {children}
      {err && <p className="text-xs text-red-400 mt-1">{err}</p>}
    </div>
  );
}
