"use client";

import { useState, useEffect, useCallback } from "react";
import Help, { HelpBanner } from "../Help";
import {
  api,
  Gateway,
  RoutingInstance,
  validateInterface,
  validateIpOrHost,
  validateName,
} from "../lib";

const MONITORS = [
  { value: "icmp", label: "ICMP ping" },
  { value: "tcp", label: "TCP connect" },
  { value: "http", label: "HTTP GET" },
  { value: "dns", label: "DNS query" },
];

const stateColor: Record<string, string> = {
  up: "bg-green-500/20 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  down: "bg-red-500/20 text-red-400 border-red-500/30",
  unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

interface FormState {
  name: string;
  instance_id: string;
  interface: string;
  next_hop: string;
  ip_version: string;
  monitor_kind: string;
  monitor_target: string;
  monitor_port: string;
  monitor_expect: string;
  interval_ms: number;
  timeout_ms: number;
  consec_fail_down: number;
  consec_ok_up: number;
  weight: number;
  enabled: boolean;
}

const defaultForm: FormState = {
  name: "",
  instance_id: "",
  interface: "",
  next_hop: "",
  ip_version: "v4",
  monitor_kind: "icmp",
  monitor_target: "",
  monitor_port: "",
  monitor_expect: "",
  interval_ms: 500,
  timeout_ms: 1000,
  consec_fail_down: 3,
  consec_ok_up: 5,
  weight: 1,
  enabled: true,
};

export default function GatewaysPage() {
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [g, i] = await Promise.all([
        api<{ data: Gateway[] }>("GET", "/api/v1/multiwan/gateways"),
        api<{ data: RoutingInstance[] }>("GET", "/api/v1/multiwan/instances"),
      ]);
      setGateways(g.data);
      setInstances(i.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  function validate(): boolean {
    const e: Record<string, string> = {};
    const n = validateName(form.name);
    if (n) e.name = n;
    if (!form.instance_id) e.instance_id = "required";
    const i = validateInterface(form.interface);
    if (i) e.interface = i;
    const nh = validateIpOrHost(form.next_hop);
    if (nh) e.next_hop = nh;
    if (form.interval_ms < 100 || form.interval_ms > 60_000)
      e.interval_ms = "100–60000 ms";
    if (form.timeout_ms < 50 || form.timeout_ms > 10_000)
      e.timeout_ms = "50–10000 ms";
    if (form.timeout_ms >= form.interval_ms)
      e.timeout_ms = "timeout must be < interval";
    if (form.consec_fail_down < 1 || form.consec_fail_down > 100)
      e.consec_fail_down = "1–100";
    if (form.consec_ok_up < 1 || form.consec_ok_up > 100)
      e.consec_ok_up = "1–100";
    if (form.weight < 1 || form.weight > 255) e.weight = "1–255";
    if (form.monitor_kind === "tcp" || form.monitor_kind === "http") {
      if (form.monitor_port) {
        const p = parseInt(form.monitor_port, 10);
        if (!Number.isInteger(p) || p < 1 || p > 65535)
          e.monitor_port = "1–65535";
      }
    }
    setErrs(e);
    return Object.keys(e).length === 0;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;
    setSubmitting(true);
    setError(null);
    try {
      const body = {
        ...form,
        monitor_target: form.monitor_target || form.next_hop,
        monitor_port: form.monitor_port
          ? parseInt(form.monitor_port, 10)
          : null,
        monitor_expect: form.monitor_expect || null,
      };
      await api("POST", "/api/v1/multiwan/gateways", body);
      setForm(defaultForm);
      setShowForm(false);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function deleteGw(id: string) {
    if (!confirm("Delete gateway? This stops monitoring.")) return;
    try {
      await api("DELETE", `/api/v1/multiwan/gateways/${id}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
    }
  }

  async function probeNow(id: string, success: boolean) {
    try {
      await api("POST", `/api/v1/multiwan/gateways/${id}/probe-now`, {
        success,
        rtt_ms: success ? 10.0 : null,
        error: success ? null : "manual fail",
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "probe failed");
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Gateways
            <Help title="Gateways" size="md">
              <p>
                A <b>gateway</b> is an upstream next-hop that AiFw actively
                monitors. Each gateway belongs to one routing instance.
              </p>
              <p>
                Health state (up / warning / down) drives policy routing and
                gateway groups. Probes run every <code>interval_ms</code>.
              </p>
              <p className="text-blue-400">
                Create one gateway per upstream router. Use it in Policies or
                combine into Groups for failover/LB.
              </p>
            </Help>
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Monitored next-hops with live RTT/jitter/loss and MOS scoring.
          </p>
        </div>
        <button
          onClick={() => {
            setShowForm(!showForm);
            if (showForm) {
              setForm(defaultForm);
              setErrs({});
            }
          }}
          className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
        >
          {showForm ? "Cancel" : "+ Add Gateway"}
        </button>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      <HelpBanner title="Gateway health monitoring" storageKey="mwan-gateways">
        <p>
          AiFw sends probes every <code>interval_ms</code> (default 500ms) and
          tracks consecutive successes/failures for hysteresis — so one bad
          probe doesn&apos;t flap a gateway down. Default thresholds:
        </p>
        <ul className="list-disc ml-5 space-y-1">
          <li>3 consecutive failures → <b>down</b> (≤1.5s convergence)</li>
          <li>5 consecutive successes → back to <b>up</b></li>
          <li>
            Recent loss &gt; <code>loss_pct_up</code> while technically up →
            <b> warning</b> (still usable, deprioritized in adaptive groups)
          </li>
        </ul>
        <p>
          <b>MOS</b> (Mean Opinion Score, 1.0–4.5) is a quality estimate derived
          from RTT + jitter + loss. ≥4.0 is excellent, 3.5 acceptable for voice,
          &lt;3.0 poor.
        </p>
        <p>
          Click the ✓/✗ buttons on a row to inject a fake probe outcome (great
          for testing failover before you actually yank a cable).
        </p>
      </HelpBanner>

      {showForm && (
        <form
          onSubmit={submit}
          className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3"
        >
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            New gateway
            <Help title="Monitor types">
              <p>
                <b>ICMP ping</b> — simplest; works for any reachable host. Uses
                setuid <code>/sbin/ping</code>.
              </p>
              <p>
                <b>TCP connect</b> — opens a TCP socket to target:port. Good
                when ICMP is filtered.
              </p>
              <p>
                <b>HTTP GET</b> — full round-trip incl. TLS/layer-7. Set expected
                HTTP status (default 200).
              </p>
              <p>
                <b>DNS query</b> — sends an A lookup for the expect field
                (default <code>example.com</code>).
              </p>
              <p className="text-blue-400">
                If unsure, pick ICMP with target = next-hop. Many ISPs filter
                ICMP to arbitrary internet hosts but not to their own routers.
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
            <Field label="Routing instance" err={errs.instance_id}>
              <select
                value={form.instance_id}
                onChange={(e) => setForm({ ...form, instance_id: e.target.value })}
                className={cls(!!errs.instance_id)}
              >
                <option value="">Select…</option>
                {instances.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name} (FIB {i.fib_number})
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Interface" err={errs.interface}>
              <input
                value={form.interface}
                onChange={(e) => setForm({ ...form, interface: e.target.value })}
                placeholder="em1"
                className={cls(!!errs.interface)}
              />
            </Field>
            <Field label="Next-hop IP" err={errs.next_hop}>
              <input
                value={form.next_hop}
                onChange={(e) => setForm({ ...form, next_hop: e.target.value })}
                placeholder="203.0.113.1"
                className={cls(!!errs.next_hop)}
              />
            </Field>
            <Field label="IP version">
              <select
                value={form.ip_version}
                onChange={(e) => setForm({ ...form, ip_version: e.target.value })}
                className={cls(false)}
              >
                <option value="v4">IPv4</option>
                <option value="v6">IPv6</option>
              </select>
            </Field>
            <Field label="Monitor">
              <select
                value={form.monitor_kind}
                onChange={(e) => setForm({ ...form, monitor_kind: e.target.value })}
                className={cls(false)}
              >
                {MONITORS.map((m) => (
                  <option key={m.value} value={m.value}>
                    {m.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Monitor target (defaults to next-hop)">
              <input
                value={form.monitor_target}
                onChange={(e) =>
                  setForm({ ...form, monitor_target: e.target.value })
                }
                className={cls(false)}
              />
            </Field>
            {(form.monitor_kind === "tcp" || form.monitor_kind === "http") && (
              <Field label="Port" err={errs.monitor_port}>
                <input
                  value={form.monitor_port}
                  onChange={(e) =>
                    setForm({ ...form, monitor_port: e.target.value })
                  }
                  placeholder={form.monitor_kind === "tcp" ? "443" : "80"}
                  className={cls(!!errs.monitor_port)}
                />
              </Field>
            )}
            {form.monitor_kind === "http" && (
              <Field label="Expected HTTP status">
                <input
                  value={form.monitor_expect}
                  onChange={(e) =>
                    setForm({ ...form, monitor_expect: e.target.value })
                  }
                  placeholder="200"
                  className={cls(false)}
                />
              </Field>
            )}
            <Field label="Probe interval (ms)" err={errs.interval_ms}>
              <input
                type="number"
                value={form.interval_ms}
                onChange={(e) =>
                  setForm({
                    ...form,
                    interval_ms: parseInt(e.target.value, 10) || 0,
                  })
                }
                className={cls(!!errs.interval_ms)}
              />
            </Field>
            <Field label="Timeout (ms)" err={errs.timeout_ms}>
              <input
                type="number"
                value={form.timeout_ms}
                onChange={(e) =>
                  setForm({ ...form, timeout_ms: parseInt(e.target.value, 10) || 0 })
                }
                className={cls(!!errs.timeout_ms)}
              />
            </Field>
            <Field label="Consecutive fails → down" err={errs.consec_fail_down}>
              <input
                type="number"
                value={form.consec_fail_down}
                onChange={(e) =>
                  setForm({
                    ...form,
                    consec_fail_down: parseInt(e.target.value, 10) || 0,
                  })
                }
                className={cls(!!errs.consec_fail_down)}
              />
            </Field>
            <Field label="Consecutive oks → up" err={errs.consec_ok_up}>
              <input
                type="number"
                value={form.consec_ok_up}
                onChange={(e) =>
                  setForm({
                    ...form,
                    consec_ok_up: parseInt(e.target.value, 10) || 0,
                  })
                }
                className={cls(!!errs.consec_ok_up)}
              />
            </Field>
            <Field label="Weight" err={errs.weight}>
              <input
                type="number"
                value={form.weight}
                onChange={(e) =>
                  setForm({ ...form, weight: parseInt(e.target.value, 10) || 0 })
                }
                className={cls(!!errs.weight)}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm text-white mt-6">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              />
              Enabled (start monitoring)
            </label>
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
          >
            {submitting ? "Creating…" : "Create gateway"}
          </button>
        </form>
      )}

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : gateways.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">
            No gateways yet.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">State</th>
                <th className="text-left px-4 py-2">Route</th>
                <th className="text-right px-4 py-2">RTT</th>
                <th className="text-right px-4 py-2">Jitter</th>
                <th className="text-right px-4 py-2">Loss</th>
                <th className="text-right px-4 py-2">MOS</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {gateways.map((gw) => (
                <GatewayRow
                  key={gw.id}
                  gw={gw}
                  onProbeSuccess={() => probeNow(gw.id, true)}
                  onProbeFail={() => probeNow(gw.id, false)}
                  onDelete={() => deleteGw(gw.id)}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

interface GatewayRowExtra extends Gateway {
  last_rtt_ms?: number | null;
  last_jitter_ms?: number | null;
  last_loss_pct?: number | null;
  last_mos?: number | null;
  monitor_kind?: string;
  monitor_target?: string | null;
}

function GatewayRow({
  gw,
  onProbeSuccess,
  onProbeFail,
  onDelete,
}: {
  gw: GatewayRowExtra;
  onProbeSuccess: () => void;
  onProbeFail: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="border-t border-[var(--border)]">
      <td className="px-4 py-3 text-white font-medium">{gw.name}</td>
      <td className="px-4 py-3">
        <span
          className={`text-xs px-2 py-1 rounded border ${stateColor[gw.state] || stateColor.unknown}`}
        >
          {gw.state}
        </span>
      </td>
      <td className="px-4 py-3 text-cyan-400 font-mono text-xs">
        {gw.interface} → {gw.next_hop}
      </td>
      <td className="px-4 py-3 text-right font-mono text-[var(--text-muted)]">
        {gw.last_rtt_ms != null ? `${gw.last_rtt_ms.toFixed(1)}ms` : "—"}
      </td>
      <td className="px-4 py-3 text-right font-mono text-[var(--text-muted)]">
        {gw.last_jitter_ms != null ? `${gw.last_jitter_ms.toFixed(1)}ms` : "—"}
      </td>
      <td className="px-4 py-3 text-right font-mono text-[var(--text-muted)]">
        {gw.last_loss_pct != null ? `${gw.last_loss_pct.toFixed(0)}%` : "—"}
      </td>
      <td className="px-4 py-3 text-right font-mono text-[var(--text-muted)]">
        {gw.last_mos != null ? gw.last_mos.toFixed(2) : "—"}
      </td>
      <td className="px-4 py-3 text-right space-x-1">
        <button
          onClick={onProbeSuccess}
          className="text-xs px-2 py-1 rounded bg-green-600/80 hover:bg-green-700 text-white"
          title="Inject success"
        >
          ✓
        </button>
        <button
          onClick={onProbeFail}
          className="text-xs px-2 py-1 rounded bg-yellow-600/80 hover:bg-yellow-700 text-white"
          title="Inject failure"
        >
          ✗
        </button>
        <button
          onClick={onDelete}
          className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
        >
          Del
        </button>
      </td>
    </tr>
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
