"use client";

import { useEffect, useState } from "react";
import StatusBanner from "./components/StatusBanner";

type CarpVip = {
  id: string;
  vhid: number;
  virtual_ip: string;
  prefix: number;
  interface: string;
  password: string;
  status: string;
};
type Pfsync = {
  id: string;
  sync_interface: string;
  sync_peer: string | null;
  defer: boolean;
  enabled: boolean;
  latency_profile: "conservative" | "tight" | "aggressive";
  heartbeat_iface: string | null;
  heartbeat_interval_ms: number | null;
  dhcp_link: boolean;
  created_at: string;
};
type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  health: string;
  last_seen: string;
};

export default function ClusterPage() {
  const [vips, setVips] = useState<CarpVip[]>([]);
  const [pfsync, setPfsync] = useState<Pfsync | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    const [v, p, n] = await Promise.all([
      fetch("/api/v1/cluster/carp", { credentials: "include" }).then((r) =>
        r.ok ? r.json() : []
      ),
      fetch("/api/v1/cluster/pfsync", { credentials: "include" }).then((r) =>
        r.ok ? r.json() : null
      ),
      fetch("/api/v1/cluster/nodes", { credentials: "include" }).then((r) =>
        r.ok ? r.json() : []
      ),
    ]);
    setVips(v);
    setPfsync(p);
    setNodes(n);
  };
  useEffect(() => {
    reload().catch(() => {});
  }, []);

  const promote = async () => {
    setBusy(true);
    try {
      await fetch("/api/v1/cluster/promote", {
        method: "POST",
        credentials: "include",
      });
      await reload();
    } finally {
      setBusy(false);
    }
  };
  const demote = async () => {
    setBusy(true);
    try {
      await fetch("/api/v1/cluster/demote", {
        method: "POST",
        credentials: "include",
      });
      await reload();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">
            Cluster &amp; High Availability
          </h1>
          <p className="text-sm text-[var(--text-muted)]">
            CARP failover, pfsync state synchronization, peer nodes
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={promote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-green-600 hover:bg-green-700 disabled:opacity-50 text-sm"
          >
            Promote
          </button>
          <button
            onClick={demote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-sm"
          >
            Demote
          </button>
        </div>
      </div>

      <StatusBanner />

      <section>
        <h2 className="text-lg font-semibold mb-2">CARP Virtual IPs</h2>
        {vips.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">
            No VIPs configured.
          </div>
        ) : (
          <table className="w-full text-sm border border-[var(--border)] rounded">
            <thead className="bg-[var(--bg-card)]">
              <tr>
                <th className="text-left p-2">VHID</th>
                <th className="text-left p-2">Interface</th>
                <th className="text-left p-2">VIP</th>
                <th className="text-left p-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {vips.map((v) => (
                <tr key={v.id} className="border-t border-[var(--border)]">
                  <td className="p-2">{v.vhid}</td>
                  <td className="p-2 font-mono">{v.interface}</td>
                  <td className="p-2 font-mono">
                    {v.virtual_ip}/{v.prefix}
                  </td>
                  <td className="p-2">{v.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-2">pfsync</h2>
        {pfsync ? (
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded p-3 text-sm space-y-1">
            <div>
              Sync iface:{" "}
              <span className="font-mono">{pfsync.sync_interface}</span>
            </div>
            <div>
              Peer:{" "}
              <span className="font-mono">
                {pfsync.sync_peer ?? "multicast"}
              </span>
            </div>
            <div>Latency profile: {pfsync.latency_profile}</div>
            <div>DHCP link: {pfsync.dhcp_link ? "yes" : "no"}</div>
            <button
              onClick={async () => {
                setBusy(true);
                try {
                  const r = await fetch("/api/v1/cluster/snapshot/force", {
                    method: "POST",
                    credentials: "include",
                  });
                  if (!r.ok) {
                    alert(
                      `Force sync failed: ${r.status} ${r.statusText}`
                    );
                  }
                  await reload();
                } finally {
                  setBusy(false);
                }
              }}
              disabled={busy}
              className="mt-2 px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-sm"
            >
              Force sync from peer
            </button>
          </div>
        ) : (
          <div className="text-sm text-[var(--text-muted)]">
            Not configured.
          </div>
        )}
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-2">Cluster Nodes</h2>
        {nodes.length === 0 ? (
          <div className="text-sm text-[var(--text-muted)]">
            No peer nodes registered.
          </div>
        ) : (
          <table className="w-full text-sm border border-[var(--border)] rounded">
            <thead className="bg-[var(--bg-card)]">
              <tr>
                <th className="text-left p-2">Name</th>
                <th className="text-left p-2">Address</th>
                <th className="text-left p-2">Role</th>
                <th className="text-left p-2">Health</th>
                <th className="text-left p-2">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.id} className="border-t border-[var(--border)]">
                  <td className="p-2">{n.name}</td>
                  <td className="p-2 font-mono">{n.address}</td>
                  <td className="p-2">{n.role}</td>
                  <td className="p-2">{n.health}</td>
                  <td className="p-2">
                    {new Date(n.last_seen).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
