"use client";

import { useState, useEffect, useCallback } from "react";
import Card from "@/components/Card";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface RoutingInstance {
  id: string;
  name: string;
  fib_number: number;
  description: string | null;
  mgmt_reachable: boolean;
  status: string;
  created_at: string;
  updated_at: string;
}

interface InstanceMember {
  instance_id: string;
  interface: string;
}

interface FibInfo {
  net_fibs: number;
  used: number[];
}

interface Feedback {
  type: "success" | "error";
  message: string;
}

function FeedbackBanner({ feedback }: { feedback: Feedback | null }) {
  if (!feedback) return null;
  const isError = feedback.type === "error";
  return (
    <div
      className={`p-3 text-sm rounded-md border ${
        isError
          ? "text-red-400 bg-red-500/10 border-red-500/20"
          : "text-green-400 bg-green-500/10 border-green-500/20"
      }`}
    >
      {feedback.message}
    </div>
  );
}

export default function MultiWanPage() {
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [fibs, setFibs] = useState<FibInfo | null>(null);
  const [members, setMembers] = useState<Record<string, InstanceMember[]>>({});
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const [newName, setNewName] = useState("");
  const [newFib, setNewFib] = useState<number>(1);
  const [newDesc, setNewDesc] = useState("");
  const [adding, setAdding] = useState(false);

  const [memberInputs, setMemberInputs] = useState<Record<string, string>>({});

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchInstances = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/multiwan/instances`, {
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`Failed to fetch instances: ${res.status}`);
      const json = await res.json();
      const list: RoutingInstance[] = json.data || [];
      setInstances(list);

      // fetch members for each instance
      const memberMap: Record<string, InstanceMember[]> = {};
      await Promise.all(
        list.map(async (inst) => {
          const r = await fetch(
            `${API}/api/v1/multiwan/instances/${inst.id}/members`,
            { headers: authHeaders() },
          );
          if (r.ok) {
            const j = await r.json();
            memberMap[inst.id] = j.data || [];
          }
        }),
      );
      setMembers(memberMap);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load instances";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [clearFeedback]);

  const fetchFibs = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/multiwan/fibs`, {
        headers: authHeaders(),
      });
      if (!res.ok) return;
      const json = await res.json();
      setFibs(json.data || null);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    fetchInstances();
    fetchFibs();
  }, [fetchInstances, fetchFibs]);

  async function createInstance(e: React.FormEvent) {
    e.preventDefault();
    setAdding(true);
    try {
      const res = await fetch(`${API}/api/v1/multiwan/instances`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          name: newName,
          fib_number: newFib,
          description: newDesc || null,
        }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Create failed: ${res.status}`);
      }
      setNewName("");
      setNewDesc("");
      setNewFib((fibs?.used?.length ?? 0) + 1);
      setFeedback({ type: "success", message: "Routing instance created" });
      clearFeedback();
      await fetchInstances();
      await fetchFibs();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Create failed";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setAdding(false);
    }
  }

  async function deleteInstance(id: string) {
    if (!confirm("Delete this routing instance? Member interfaces will return to FIB 0."))
      return;
    try {
      const res = await fetch(`${API}/api/v1/multiwan/instances/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Delete failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: "Routing instance deleted" });
      clearFeedback();
      await fetchInstances();
      await fetchFibs();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Delete failed";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    }
  }

  async function attachMember(instId: string) {
    const iface = (memberInputs[instId] || "").trim();
    if (!iface) return;
    try {
      const res = await fetch(
        `${API}/api/v1/multiwan/instances/${instId}/members`,
        {
          method: "POST",
          headers: authHeaders(),
          body: JSON.stringify({ interface: iface }),
        },
      );
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Attach failed: ${res.status}`);
      }
      setMemberInputs((m) => ({ ...m, [instId]: "" }));
      await fetchInstances();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Attach failed";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    }
  }

  async function detachMember(instId: string, iface: string) {
    try {
      const res = await fetch(
        `${API}/api/v1/multiwan/instances/${instId}/members/${encodeURIComponent(iface)}`,
        {
          method: "DELETE",
          headers: authHeaders(),
        },
      );
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `Detach failed: ${res.status}`);
      }
      await fetchInstances();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Detach failed";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Multi-WAN</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Routing instances pin interfaces to FreeBSD FIBs for true WAN isolation.
          The default instance (FIB 0) is reserved for management.
        </p>
      </div>

      <FeedbackBanner feedback={feedback} />

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

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h2 className="text-lg font-semibold text-white mb-3">Create routing instance</h2>
        <form onSubmit={createInstance} className="grid grid-cols-1 md:grid-cols-4 gap-2">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="name (e.g. wan2)"
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <input
            type="number"
            min={1}
            max={(fibs?.net_fibs ?? 1) - 1}
            value={newFib}
            onChange={(e) => setNewFib(parseInt(e.target.value, 10) || 0)}
            placeholder="fib"
            required
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <input
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="description (optional)"
            className="px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          <button
            type="submit"
            disabled={adding}
            className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
          >
            {adding ? "Creating…" : "Create"}
          </button>
        </form>
        {fibs && fibs.net_fibs <= 1 && (
          <p className="text-xs text-yellow-400 mt-2">
            Only 1 FIB available. To enable multi-WAN, set <code>net.fibs=16</code> in
            <code> /boot/loader.conf </code>and reboot.
          </p>
        )}
      </div>

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
                  <td className="px-4 py-3 text-cyan-400 font-mono">{inst.fib_number}</td>
                  <td className="px-4 py-3 text-[var(--text-muted)]">{inst.status}</td>
                  <td className="px-4 py-3">
                    {inst.mgmt_reachable ? (
                      <span className="text-green-400">✓</span>
                    ) : (
                      <span className="text-[var(--text-muted)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
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
                        <span className="inline-flex items-center gap-1">
                          <input
                            value={memberInputs[inst.id] || ""}
                            onChange={(e) =>
                              setMemberInputs((m) => ({
                                ...m,
                                [inst.id]: e.target.value,
                              }))
                            }
                            placeholder="iface"
                            className="w-20 px-2 py-1 rounded bg-black/30 border border-[var(--border)] text-white text-xs"
                          />
                          <button
                            onClick={() => attachMember(inst.id)}
                            className="text-xs px-2 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white"
                          >
                            +
                          </button>
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
