"use client";

import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

const nodes = [
  { id: "1", name: "fw-primary", address: "10.0.0.1", role: "primary", health: "healthy", configVersion: 42, lastSeen: "1s ago" },
  { id: "2", name: "fw-secondary", address: "10.0.0.2", role: "secondary", health: "healthy", configVersion: 42, lastSeen: "3s ago" },
];

const vips = [
  { id: "1", vhid: 1, virtualIp: "10.0.0.100", prefix: 24, interface: "em0", advskew: 0, status: "master" },
  { id: "2", vhid: 2, virtualIp: "10.0.0.101", prefix: 24, interface: "em0", advskew: 100, status: "backup" },
];

const healthChecks = [
  { name: "peer-ping", type: "ping", target: "10.0.0.2", interval: "10s", status: "passing" },
  { name: "pf-running", type: "pf_status", target: "local", interval: "5s", status: "passing" },
  { name: "api-health", type: "http_get", target: "http://10.0.0.2:8080/api/v1/status", interval: "15s", status: "passing" },
];

export default function ClusterPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Cluster & High Availability</h1>
        <p className="text-sm text-[var(--text-muted)]">CARP failover, pfsync state synchronization, cluster health</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card title="Cluster Nodes" value={nodes.length} color="blue" />
        <Card title="CARP VIPs" value={vips.length} color="cyan" />
        <Card title="This Node" value="primary" color="green" />
        <Card title="Config Version" value="42" color="blue" subtitle="in sync" />
        <Card title="Health Checks" value={`${healthChecks.length}/${healthChecks.length}`} color="green" subtitle="passing" />
      </div>

      {/* Cluster Nodes */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">Cluster Nodes</h2>
          <button className="px-3 py-1.5 text-xs bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md transition-colors">
            Add Node
          </button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-0 divide-y md:divide-y-0 md:divide-x divide-[var(--border)]">
          {nodes.map((node) => (
            <div key={node.id} className="p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${node.health === "healthy" ? "bg-green-400" : "bg-red-400"} animate-pulse`}></div>
                  <span className="font-bold text-lg">{node.name}</span>
                </div>
                <StatusBadge status={node.role} size="md" />
              </div>
              <div className="space-y-1.5 text-sm text-[var(--text-secondary)]">
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Address</span>
                  <span className="font-mono">{node.address}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Health</span>
                  <StatusBadge status={node.health} />
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Config Version</span>
                  <span>{node.configVersion}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Last Seen</span>
                  <span>{node.lastSeen}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CARP VIPs */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">CARP Virtual IPs</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">VHID</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Virtual IP</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Interface</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Advskew</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Status</th>
            </tr>
          </thead>
          <tbody>
            {vips.map((v) => (
              <tr key={v.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                <td className="py-2.5 px-4 font-bold">{v.vhid}</td>
                <td className="py-2.5 px-4 font-mono">{v.virtualIp}/{v.prefix}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{v.interface}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{v.advskew}</td>
                <td className="py-2.5 px-4"><StatusBadge status={v.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Health Checks */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">Health Checks</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Name</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Type</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Target</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Interval</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Status</th>
            </tr>
          </thead>
          <tbody>
            {healthChecks.map((hc) => (
              <tr key={hc.name} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                <td className="py-2.5 px-4 font-medium">{hc.name}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{hc.type}</td>
                <td className="py-2.5 px-4 font-mono text-xs text-[var(--text-secondary)]">{hc.target}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{hc.interval}</td>
                <td className="py-2.5 px-4"><StatusBadge status={hc.status === "passing" ? "healthy" : "error"} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* pfsync Status */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h2 className="font-medium mb-3">pfsync Status</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-[var(--text-muted)] text-xs">Sync Interface</span>
            <div className="font-mono">em1</div>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs">Sync Peer</span>
            <div className="font-mono">10.0.0.2</div>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs">Defer Mode</span>
            <div>Enabled</div>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs">Status</span>
            <div><StatusBadge status="active" /></div>
          </div>
        </div>
      </div>
    </div>
  );
}
