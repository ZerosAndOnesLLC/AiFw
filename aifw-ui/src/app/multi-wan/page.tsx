"use client";

import { useState, useEffect, useCallback } from "react";
import Card from "@/components/Card";
import Help, { HelpBanner } from "./Help";
import {
  api,
  InstanceMember,
  RoutingInstance,
  validateFib,
  validateInterface,
  validateName,
} from "./lib";

interface FibInfo {
  net_fibs: number;
  used: number[];
}

interface Feedback {
  type: "success" | "error";
  message: string;
}

export default function MultiWanPage() {
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [fibs, setFibs] = useState<FibInfo | null>(null);
  const [members, setMembers] = useState<Record<string, InstanceMember[]>>({});
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const [form, setForm] = useState({ name: "", fib: 1, description: "" });
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const [memberInputs, setMemberInputs] = useState<Record<string, string>>({});
  const [memberErrs, setMemberErrs] = useState<Record<string, string>>({});

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const [list, f] = await Promise.all([
        api<{ data: RoutingInstance[] }>("GET", "/api/v1/multiwan/instances"),
        api<{ data: FibInfo }>("GET", "/api/v1/multiwan/fibs"),
      ]);
      setInstances(list.data);
      setFibs(f.data);
      const memberMap: Record<string, InstanceMember[]> = {};
      await Promise.all(
        list.data.map(async (inst) => {
          const r = await api<{ data: InstanceMember[] }>(
            "GET",
            `/api/v1/multiwan/instances/${inst.id}/members`,
          );
          memberMap[inst.id] = r.data;
        }),
      );
      setMembers(memberMap);
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "fetch failed",
      });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [clearFeedback]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  function validateInstance(): boolean {
    const e: Record<string, string> = {};
    const n = validateName(form.name);
    if (n) e.name = n;
    const max = fibs?.net_fibs ?? 1;
    const f = validateFib(form.fib, max);
    if (f) e.fib = f;
    if (fibs?.used.includes(form.fib)) e.fib = `FIB ${form.fib} already used`;
    setErrs(e);
    return Object.keys(e).length === 0;
  }

  async function createInstance(e: React.FormEvent) {
    e.preventDefault();
    if (!validateInstance()) return;
    setSubmitting(true);
    try {
      await api("POST", "/api/v1/multiwan/instances", {
        name: form.name,
        fib_number: form.fib,
        description: form.description || null,
      });
      setForm({
        name: "",
        fib: (fibs?.used.length ?? 0) + 1,
        description: "",
      });
      setFeedback({ type: "success", message: "Instance created" });
      clearFeedback();
      await fetchAll();
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "create failed",
      });
      clearFeedback();
    } finally {
      setSubmitting(false);
    }
  }

  async function deleteInstance(id: string) {
    if (!confirm("Delete this routing instance? Member interfaces return to FIB 0."))
      return;
    try {
      await api("DELETE", `/api/v1/multiwan/instances/${id}`);
      setFeedback({ type: "success", message: "Instance deleted" });
      clearFeedback();
      await fetchAll();
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "delete failed",
      });
      clearFeedback();
    }
  }

  async function attachMember(instId: string) {
    const iface = (memberInputs[instId] || "").trim();
    const err = validateInterface(iface);
    if (err) {
      setMemberErrs({ ...memberErrs, [instId]: err });
      return;
    }
    setMemberErrs({ ...memberErrs, [instId]: "" });
    try {
      await api("POST", `/api/v1/multiwan/instances/${instId}/members`, {
        interface: iface,
      });
      setMemberInputs((m) => ({ ...m, [instId]: "" }));
      await fetchAll();
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "attach failed",
      });
      clearFeedback();
    }
  }

  async function detachMember(instId: string, iface: string) {
    try {
      await api(
        "DELETE",
        `/api/v1/multiwan/instances/${instId}/members/${encodeURIComponent(iface)}`,
      );
      await fetchAll();
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "detach failed",
      });
      clearFeedback();
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Multi-WAN
            <Help title="What is multi-WAN?" size="md">
              <p>
                Multi-WAN lets you run multiple internet uplinks on one firewall
                with true traffic isolation, failover, and load-balancing.
              </p>
              <p>
                Under the hood we use <b>FreeBSD FIBs</b> (one routing table per
                WAN) plus pf <code>route-to</code>/<code>rtable</code> rules.
                It&apos;s the enterprise equivalent of Juniper routing-instances
                or Cisco VRFs.
              </p>
              <p className="text-blue-400">
                Start here (Instances) → define Gateways → optionally compose
                them into Groups → write Policies that steer traffic.
              </p>
            </Help>
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Routing instances pin interfaces to FreeBSD FIBs for true WAN isolation.
            The default instance (FIB 0) is reserved for management.
          </p>
        </div>
      </div>

      <HelpBanner title="Routing instances — quick tour" storageKey="mwan-instances">
        <p>
          Each <b>instance</b> maps 1:1 to a FreeBSD FIB (forwarding information
          base = a routing table). An interface can only belong to one instance
          at a time.
        </p>
        <ul className="list-disc ml-5 space-y-1">
          <li>
            <b>default</b> (FIB 0) always exists and is marked mgmt-reachable — you
            can&apos;t delete it. This keeps the admin session alive even if
            policy rules break everything else.
          </li>
          <li>
            Create one instance per WAN uplink: <code>wan1</code> on FIB 1,
            <code>wan2</code> on FIB 2, etc.
          </li>
          <li>
            Attach the WAN interface to the instance — AiFw runs{" "}
            <code>ifconfig &lt;if&gt; fib N</code> for you.
          </li>
          <li>
            <b>Prerequisite:</b> set <code>net.fibs=16</code> in
            <code> /boot/loader.conf</code> and reboot. The
            card below shows how many FIBs the kernel currently offers.
          </li>
        </ul>
      </HelpBanner>

      {feedback && (
        <div
          className={`p-3 text-sm rounded-md border ${
            feedback.type === "error"
              ? "text-red-400 bg-red-500/10 border-red-500/20"
              : "text-green-400 bg-green-500/10 border-green-500/20"
          }`}
        >
          {feedback.message}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Card
          title="Available FIBs"
          value={fibs?.net_fibs ?? "—"}
          subtitle="net.fibs sysctl"
          color="cyan"
        />
        <Card
          title="Instances"
          value={instances.length}
          subtitle={`${fibs?.used?.length ?? 0} FIBs in use`}
          color="blue"
        />
        <Card
          title="Pinned Interfaces"
          value={Object.values(members).reduce((n, m) => n + m.length, 0)}
          subtitle="total across all instances"
          color="green"
        />
      </div>

      <form
        onSubmit={createInstance}
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3"
      >
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          Create routing instance
          <Help title="Instance fields">
            <p>
              <b>Name:</b> short identifier (<code>wan1</code>, <code>isp-a</code>).
              Used in logs and UI.
            </p>
            <p>
              <b>FIB:</b> unique non-zero FIB number. Max is <code>net.fibs - 1</code>.
              Each instance owns exactly one FIB; each interface lives in exactly
              one FIB.
            </p>
            <p>
              <b>Description:</b> free-text note for future you.
            </p>
          </Help>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="wan2"
              className={cls(!!errs.name)}
            />
            {errs.name && <p className="text-xs text-red-400 mt-1">{errs.name}</p>}
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">FIB</label>
            <input
              type="number"
              min={1}
              max={(fibs?.net_fibs ?? 1) - 1}
              value={form.fib}
              onChange={(e) =>
                setForm({ ...form, fib: parseInt(e.target.value, 10) || 0 })
              }
              className={cls(!!errs.fib)}
            />
            {errs.fib && <p className="text-xs text-red-400 mt-1">{errs.fib}</p>}
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Description (optional)
            </label>
            <input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              className={cls(false)}
            />
          </div>
        </div>
        {fibs && fibs.net_fibs <= 1 && (
          <p className="text-xs text-yellow-400">
            Only 1 FIB available. To enable multi-WAN, set{" "}
            <code>net.fibs=16</code> in <code>/boot/loader.conf</code> and reboot.
          </p>
        )}
        <button
          type="submit"
          disabled={submitting || (fibs?.net_fibs ?? 1) <= 1}
          className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
        >
          {submitting ? "Creating…" : "Create"}
        </button>
      </form>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">FIB</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-left px-4 py-2">Mgmt</th>
                <th className="text-left px-4 py-2">Members</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {instances.map((inst) => (
                <tr key={inst.id} className="border-t border-[var(--border)]">
                  <td className="px-4 py-3 text-white font-medium">{inst.name}</td>
                  <td className="px-4 py-3 text-cyan-400 font-mono">
                    {inst.fib_number}
                  </td>
                  <td className="px-4 py-3 text-[var(--text-muted)]">
                    {(inst as { status?: string }).status ?? "—"}
                  </td>
                  <td className="px-4 py-3">
                    {inst.mgmt_reachable ? (
                      <span className="text-green-400">✓</span>
                    ) : (
                      <span className="text-[var(--text-muted)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 items-center">
                      {(members[inst.id] || []).map((m) => (
                        <span
                          key={m.interface}
                          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20"
                        >
                          {m.interface}
                          {!inst.mgmt_reachable && (
                            <button
                              onClick={() => detachMember(inst.id, m.interface)}
                              className="ml-1 text-red-400 hover:text-red-300"
                              title="Detach"
                            >
                              ×
                            </button>
                          )}
                        </span>
                      ))}
                      {!inst.mgmt_reachable && (
                        <span className="inline-flex flex-col">
                          <div className="flex items-center gap-1">
                            <input
                              value={memberInputs[inst.id] || ""}
                              onChange={(e) =>
                                setMemberInputs((m) => ({
                                  ...m,
                                  [inst.id]: e.target.value,
                                }))
                              }
                              placeholder="iface"
                              className={`w-20 px-2 py-1 rounded bg-black/30 border text-white text-xs ${
                                memberErrs[inst.id]
                                  ? "border-red-500"
                                  : "border-[var(--border)]"
                              }`}
                            />
                            <button
                              onClick={() => attachMember(inst.id)}
                              className="text-xs px-2 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white"
                            >
                              +
                            </button>
                          </div>
                          {memberErrs[inst.id] && (
                            <p className="text-xs text-red-400">
                              {memberErrs[inst.id]}
                            </p>
                          )}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!inst.mgmt_reachable && (
                      <button
                        onClick={() => deleteInstance(inst.id)}
                        className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                      >
                        Delete
                      </button>
                    )}
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
