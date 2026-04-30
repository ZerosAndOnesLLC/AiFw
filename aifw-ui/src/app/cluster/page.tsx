"use client";

import { useEffect, useState } from "react";
import { fetchApi } from "@/lib/api";
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
  const [generatedKey, setGeneratedKey] = useState<{
    nodeName: string;
    key: string;
  } | null>(null);

  const reload = async () => {
    const [v, p, n] = await Promise.all([
      fetchApi<CarpVip[]>("/api/v1/cluster/carp").catch(() => [] as CarpVip[]),
      fetchApi<Pfsync>("/api/v1/cluster/pfsync").catch(() => null),
      fetchApi<Node[]>("/api/v1/cluster/nodes").catch(() => [] as Node[]),
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
      await fetchApi("/api/v1/cluster/promote", { method: "POST" });
      await reload();
    } finally {
      setBusy(false);
    }
  };
  const demote = async () => {
    setBusy(true);
    try {
      await fetchApi("/api/v1/cluster/demote", { method: "POST" });
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const generatePeerKey = async (nodeId: string, nodeName: string) => {
    const d = await fetchApi<{ key: string }>(
      `/api/v1/cluster/nodes/${nodeId}/generate-key`,
      { method: "POST" }
    ).catch(() => null);
    if (d) {
      setGeneratedKey({ nodeName, key: d.key });
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

      {generatedKey && (
        <div className="bg-yellow-500/10 border border-yellow-500/40 rounded p-3 text-sm">
          <div className="font-semibold mb-1">
            Peer API key for {generatedKey.nodeName}
          </div>
          <div className="text-xs opacity-80 mb-2">
            This key is shown ONCE. Copy it and register it on the peer node as
            an API key (in the peer&apos;s Users &#x2192; API Keys page) before
            dismissing. This local node will use it to authenticate to{" "}
            {generatedKey.nodeName}.
          </div>
          <code className="block break-all bg-[var(--bg-card)] p-2 rounded mb-2">
            {generatedKey.key}
          </code>
          <button
            onClick={() => navigator.clipboard.writeText(generatedKey.key)}
            className="text-xs underline mr-3"
          >
            copy
          </button>
          <button
            onClick={() => setGeneratedKey(null)}
            className="text-xs underline"
          >
            dismiss
          </button>
        </div>
      )}

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
                  await fetchApi("/api/v1/cluster/snapshot/force", {
                    method: "POST",
                  }).catch(() => {});
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
                <th className="text-left p-2">Peer key</th>
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
                  <td className="p-2">
                    <button
                      onClick={() => generatePeerKey(n.id, n.name)}
                      className="px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-xs text-white"
                    >
                      Generate Peer Key
                    </button>
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
