"use client";

import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

const wgTunnels = [
  { id: "1", name: "wg0-office", interface: "wg0", port: 51820, address: "10.0.0.1/24", status: "up", peers: 3, publicKey: "aBcDeFgH..." },
  { id: "2", name: "wg1-remote", interface: "wg1", port: 51821, address: "10.1.0.1/24", status: "down", peers: 1, publicKey: "xYzAbCdE..." },
];

const ipsecSas = [
  { id: "3", name: "office-vpn", src: "203.0.113.1", dst: "198.51.100.1", protocol: "esp", mode: "tunnel", status: "up", spi: "0x1a2b3c4d" },
  { id: "4", name: "partner-link", src: "203.0.113.1", dst: "192.0.2.50", protocol: "esp", mode: "tunnel", status: "down", spi: "0x5e6f7a8b" },
];

const peers = [
  { name: "laptop-alice", endpoint: "1.2.3.4:51820", allowedIps: "10.0.0.2/32", keepalive: 25, lastHandshake: "2 min ago" },
  { name: "phone-bob", endpoint: "5.6.7.8:51820", allowedIps: "10.0.0.3/32", keepalive: 25, lastHandshake: "15 min ago" },
  { name: "server-dc2", endpoint: "9.10.11.12:51820", allowedIps: "10.0.0.0/24", keepalive: 0, lastHandshake: "1 sec ago" },
];

export default function VpnPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">VPN Management</h1>
        <p className="text-sm text-[var(--text-muted)]">WireGuard tunnels and IPsec security associations</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card title="WireGuard Tunnels" value={wgTunnels.length} color="cyan" />
        <Card title="WG Peers" value={peers.length} color="blue" />
        <Card title="IPsec SAs" value={ipsecSas.length} color="green" />
        <Card title="Active VPNs" value={wgTunnels.filter(t => t.status === "up").length + ipsecSas.filter(s => s.status === "up").length} color="green" subtitle="of 4 total" />
      </div>

      {/* WireGuard */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">WireGuard Tunnels</h2>
          <button className="px-3 py-1.5 text-xs bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md transition-colors">
            Add Tunnel
          </button>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {wgTunnels.map((t) => (
            <div key={t.id} className="p-4 hover:bg-[var(--bg-card-hover)] transition-colors">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className="font-medium">{t.name}</span>
                  <StatusBadge status={t.status} />
                </div>
                <span className="text-xs text-[var(--text-muted)]">{t.peers} peer(s)</span>
              </div>
              <div className="grid grid-cols-4 gap-4 text-xs text-[var(--text-secondary)]">
                <div><span className="text-[var(--text-muted)]">Interface:</span> {t.interface}</div>
                <div><span className="text-[var(--text-muted)]">Port:</span> {t.port}</div>
                <div><span className="text-[var(--text-muted)]">Address:</span> {t.address}</div>
                <div><span className="text-[var(--text-muted)]">Key:</span> {t.publicKey}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Peers */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">WireGuard Peers (wg0-office)</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Name</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Endpoint</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Allowed IPs</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Keepalive</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Last Handshake</th>
            </tr>
          </thead>
          <tbody>
            {peers.map((p) => (
              <tr key={p.name} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                <td className="py-2.5 px-4 font-medium">{p.name}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{p.endpoint}</td>
                <td className="py-2.5 px-4 font-mono text-xs text-[var(--text-secondary)]">{p.allowedIps}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{p.keepalive || "off"}s</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{p.lastHandshake}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* IPsec */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between p-4 border-b border-[var(--border)]">
          <h2 className="font-medium">IPsec Security Associations</h2>
          <button className="px-3 py-1.5 text-xs bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md transition-colors">
            Add IPsec SA
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Name</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Source</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Destination</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Protocol</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Mode</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">SPI</th>
              <th className="text-left py-2.5 px-4 text-xs text-[var(--text-muted)] uppercase">Status</th>
            </tr>
          </thead>
          <tbody>
            {ipsecSas.map((sa) => (
              <tr key={sa.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                <td className="py-2.5 px-4 font-medium">{sa.name}</td>
                <td className="py-2.5 px-4 font-mono text-xs text-[var(--text-secondary)]">{sa.src}</td>
                <td className="py-2.5 px-4 font-mono text-xs text-[var(--text-secondary)]">{sa.dst}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)] uppercase">{sa.protocol}</td>
                <td className="py-2.5 px-4 text-[var(--text-secondary)]">{sa.mode}</td>
                <td className="py-2.5 px-4 font-mono text-xs text-[var(--text-secondary)]">{sa.spi}</td>
                <td className="py-2.5 px-4"><StatusBadge status={sa.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
