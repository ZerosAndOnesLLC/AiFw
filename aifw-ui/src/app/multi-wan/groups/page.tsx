"use client";

import { useState, useEffect, useCallback } from "react";
import Help, { HelpBanner } from "../Help";
import {
  api,
  Gateway,
  GatewayGroup,
  GroupMember,
  validateName,
  validateWeight,
} from "../lib";

const POLICIES = [
  { value: "failover", label: "Failover (strict tier order)" },
  { value: "weighted_lb", label: "Weighted LB (per-flow hash)" },
  { value: "adaptive", label: "Adaptive (MOS-weighted)" },
  { value: "load_balance", label: "Load Balance (all healthy)" },
];

const STICKY = [
  { value: "none", label: "None" },
  { value: "src", label: "Src-address sticky" },
  { value: "five_tuple", label: "5-tuple (implicit via state)" },
];

interface ActiveResp {
  selection: string;
  gateways: string[];
}

export default function GroupsPage() {
  const [groups, setGroups] = useState<GatewayGroup[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [members, setMembers] = useState<Record<string, GroupMember[]>>({});
  const [active, setActive] = useState<Record<string, ActiveResp>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState({
    name: "",
    policy: "failover",
    preempt: true,
    sticky: "none",
    hysteresis_ms: 2000,
    kill_states_on_failover: true,
  });
  const [formErr, setFormErr] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const [memberForms, setMemberForms] = useState<
    Record<string, { gateway_id: string; tier: number; weight: number }>
  >({});

  const refresh = useCallback(async () => {
    try {
      const [g, gw] = await Promise.all([
        api<{ data: GatewayGroup[] }>("GET", "/api/v1/multiwan/groups"),
        api<{ data: Gateway[] }>("GET", "/api/v1/multiwan/gateways"),
      ]);
      setGroups(g.data);
      setGateways(gw.data);
      const memMap: Record<string, GroupMember[]> = {};
      const actMap: Record<string, ActiveResp> = {};
      await Promise.all(
        g.data.map(async (grp) => {
          const [mem, act] = await Promise.all([
            api<{ data: GroupMember[] }>(
              "GET",
              `/api/v1/multiwan/groups/${grp.id}/members`,
            ),
            api<{ data: ActiveResp }>(
              "GET",
              `/api/v1/multiwan/groups/${grp.id}/active`,
            ).catch(() => ({ data: { selection: "none", gateways: [] } })),
          ]);
          memMap[grp.id] = mem.data;
          actMap[grp.id] = act.data;
        }),
      );
      setMembers(memMap);
      setActive(actMap);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  function validateForm() {
    const errs: Record<string, string> = {};
    const n = validateName(form.name);
    if (n) errs.name = n;
    if (form.hysteresis_ms < 0 || form.hysteresis_ms > 60_000)
      errs.hysteresis_ms = "0–60000 ms";
    setFormErr(errs);
    return Object.keys(errs).length === 0;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!validateForm()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api("POST", "/api/v1/multiwan/groups", form);
      setForm({
        name: "",
        policy: "failover",
        preempt: true,
        sticky: "none",
        hysteresis_ms: 2000,
        kill_states_on_failover: true,
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function addMember(groupId: string) {
    const mf = memberForms[groupId];
    if (!mf?.gateway_id) {
      setError("select a gateway first");
      return;
    }
    const wErr = validateWeight(mf.weight);
    if (wErr) {
      setError(`weight: ${wErr}`);
      return;
    }
    if (!Number.isInteger(mf.tier) || mf.tier < 1 || mf.tier > 16) {
      setError("tier: 1–16");
      return;
    }
    try {
      await api("POST", `/api/v1/multiwan/groups/${groupId}/members`, mf);
      setMemberForms((m) => ({
        ...m,
        [groupId]: { gateway_id: "", tier: 1, weight: 1 },
      }));
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "add failed");
    }
  }

  async function removeMember(groupId: string, gwId: string) {
    try {
      await api("DELETE", `/api/v1/multiwan/groups/${groupId}/members/${gwId}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "remove failed");
    }
  }

  async function deleteGroup(id: string) {
    if (!confirm("Delete gateway group?")) return;
    try {
      await api("DELETE", `/api/v1/multiwan/groups/${id}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          Gateway Groups
          <Help title="Gateway groups" size="md">
            <p>
              A <b>group</b> bundles multiple gateways so policies can target a
              collective (failover set or load-balance pool) instead of one
              specific next-hop.
            </p>
            <p>
              Groups are purely logical — the selection of which gateway wins
              happens at pf-apply time based on live health, and again on every
              failover event.
            </p>
          </Help>
        </h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Compose gateways into ordered tiers with failover, weighted LB, or adaptive policies.
        </p>
      </div>

      <HelpBanner title="Which policy should I pick?" storageKey="mwan-groups">
        <ul className="list-disc ml-5 space-y-1">
          <li>
            <b>Failover</b> — lowest tier with at least one healthy member
            wins. Within a tier, the highest <i>weight</i> wins. Standard
            active/backup setup.
          </li>
          <li>
            <b>Weighted LB</b> — flow-hash across all healthy members in the
            lowest tier, scaled by weight. pf emits{" "}
            <code>route-to &#123; (em1 gw1) weight N, ... &#125; round-robin</code>.
          </li>
          <li>
            <b>Adaptive</b> — like weighted LB but weights auto-scale by live
            MOS (higher quality → more flows). Great for video/voice.
          </li>
          <li>
            <b>Load Balance</b> — simple flow distribution, no weight scaling.
          </li>
        </ul>
        <p>
          <b>Tier</b> = priority band (1 = preferred). <b>Weight</b> = intra-tier
          share (higher = more traffic). <b>Preempt</b> = return to preferred
          tier when it recovers. <b>Sticky</b> = keep the same client on the
          same member (<code>src</code> hashes source IP).
        </p>
      </HelpBanner>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      <form
        onSubmit={submit}
        className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3"
      >
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          Create group
          <Help title="Group fields">
            <p>
              <b>Hysteresis:</b> ms a transition must be stable before the group
              commits to it. Prevents flapping if a probe oscillates.
            </p>
            <p>
              <b>Kill states on failover:</b> when active member goes down,
              drop all pf states on its interface so clients reconnect via the
              new path. Off = let TCP time out naturally.
            </p>
          </Help>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className={`w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
                formErr.name ? "border-red-500" : "border-[var(--border)]"
              }`}
            />
            {formErr.name && (
              <p className="text-xs text-red-400 mt-1">{formErr.name}</p>
            )}
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Policy</label>
            <select
              value={form.policy}
              onChange={(e) => setForm({ ...form, policy: e.target.value })}
              className="w-full px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
            >
              {POLICIES.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Sticky</label>
            <select
              value={form.sticky}
              onChange={(e) => setForm({ ...form, sticky: e.target.value })}
              className="w-full px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
            >
              {STICKY.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Hysteresis (ms)
            </label>
            <input
              type="number"
              min={0}
              max={60000}
              value={form.hysteresis_ms}
              onChange={(e) =>
                setForm({ ...form, hysteresis_ms: parseInt(e.target.value, 10) || 0 })
              }
              className={`w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
                formErr.hysteresis_ms ? "border-red-500" : "border-[var(--border)]"
              }`}
            />
            {formErr.hysteresis_ms && (
              <p className="text-xs text-red-400 mt-1">{formErr.hysteresis_ms}</p>
            )}
          </div>
          <label className="flex items-center gap-2 text-sm text-white">
            <input
              type="checkbox"
              checked={form.preempt}
              onChange={(e) => setForm({ ...form, preempt: e.target.checked })}
            />
            Preempt to preferred tier on recovery
          </label>
          <label className="flex items-center gap-2 text-sm text-white">
            <input
              type="checkbox"
              checked={form.kill_states_on_failover}
              onChange={(e) =>
                setForm({ ...form, kill_states_on_failover: e.target.checked })
              }
            />
            Kill states on failover
          </label>
        </div>
        <button
          type="submit"
          disabled={submitting}
          className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
        >
          {submitting ? "Creating…" : "Create group"}
        </button>
      </form>

      {loading ? (
        <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
      ) : groups.length === 0 ? (
        <div className="p-8 text-center text-[var(--text-muted)] bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          No groups yet.
        </div>
      ) : (
        <div className="space-y-4">
          {groups.map((g) => {
            const mem = members[g.id] || [];
            const act = active[g.id];
            const mf = memberForms[g.id] || { gateway_id: "", tier: 1, weight: 1 };
            const availableGws = gateways.filter(
              (gw) => !mem.some((m) => m.gateway_id === gw.id),
            );
            return (
              <div
                key={g.id}
                className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4"
              >
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-white font-medium">{g.name}</h3>
                      <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                        {g.policy}
                      </span>
                      {g.preempt && (
                        <span className="text-xs px-2 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">
                          preempt
                        </span>
                      )}
                      {g.sticky !== "none" && (
                        <span className="text-xs px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                          sticky:{g.sticky}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-[var(--text-muted)] mt-1">
                      hysteresis {g.hysteresis_ms}ms, kill-states{" "}
                      {g.kill_states_on_failover ? "on" : "off"}
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    {act && (
                      <div className="text-xs text-right">
                        <div className="text-[var(--text-muted)]">Active</div>
                        <div className="text-green-400 font-mono">
                          {act.selection === "none"
                            ? "—"
                            : `${act.selection} (${act.gateways.length})`}
                        </div>
                      </div>
                    )}
                    <button
                      onClick={() => deleteGroup(g.id)}
                      className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                    >
                      Delete
                    </button>
                  </div>
                </div>

                <table className="w-full text-sm">
                  <thead className="text-[var(--text-muted)] text-xs uppercase">
                    <tr>
                      <th className="text-left py-1">Gateway</th>
                      <th className="text-left py-1">State</th>
                      <th className="text-right py-1">Tier</th>
                      <th className="text-right py-1">Weight</th>
                      <th className="text-right py-1"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {mem.map((m) => {
                      const gw = gateways.find((x) => x.id === m.gateway_id);
                      const isActive = act?.gateways.includes(m.gateway_id);
                      return (
                        <tr key={m.gateway_id} className="border-t border-[var(--border)]">
                          <td className="py-2">
                            <span className="text-white">{gw?.name || m.gateway_id}</span>
                            {isActive && (
                              <span className="ml-2 text-xs text-green-400">● active</span>
                            )}
                          </td>
                          <td className="py-2 text-[var(--text-muted)]">
                            {gw?.state || "?"}
                          </td>
                          <td className="py-2 text-right font-mono text-cyan-400">
                            {m.tier}
                          </td>
                          <td className="py-2 text-right font-mono text-cyan-400">
                            {m.weight}
                          </td>
                          <td className="py-2 text-right">
                            <button
                              onClick={() => removeMember(g.id, m.gateway_id)}
                              className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                            >
                              Remove
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {availableGws.length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-2 mt-3">
                    <select
                      value={mf.gateway_id}
                      onChange={(e) =>
                        setMemberForms({
                          ...memberForms,
                          [g.id]: { ...mf, gateway_id: e.target.value },
                        })
                      }
                      className="px-2 py-1 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
                    >
                      <option value="">Add gateway…</option>
                      {availableGws.map((gw) => (
                        <option key={gw.id} value={gw.id}>
                          {gw.name}
                        </option>
                      ))}
                    </select>
                    <input
                      type="number"
                      min={1}
                      max={16}
                      value={mf.tier}
                      onChange={(e) =>
                        setMemberForms({
                          ...memberForms,
                          [g.id]: {
                            ...mf,
                            tier: parseInt(e.target.value, 10) || 1,
                          },
                        })
                      }
                      placeholder="tier (1-16)"
                      className="px-2 py-1 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
                    />
                    <input
                      type="number"
                      min={1}
                      max={255}
                      value={mf.weight}
                      onChange={(e) =>
                        setMemberForms({
                          ...memberForms,
                          [g.id]: {
                            ...mf,
                            weight: parseInt(e.target.value, 10) || 1,
                          },
                        })
                      }
                      placeholder="weight (1-255)"
                      className="px-2 py-1 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
                    />
                    <button
                      onClick={() => addMember(g.id)}
                      className="px-2 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
                    >
                      Add member
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
