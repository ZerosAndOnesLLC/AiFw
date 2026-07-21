"use client";

import { useVpn } from "@/hooks/useVpn";
import { HelpBanner } from "./Help";
import { SummaryCard } from "./components/SummaryCard";
import { ErrorBanner } from "./components/ErrorBanner";
import { WireGuardSection } from "./components/WireGuardSection";
import { IpsecSection } from "./components/IpsecSection";
import { ConfigModal } from "./components/ConfigModal";

/* ════════════════════════════════════════════════════════════
   Main Page Component
   ════════════════════════════════════════════════════════════ */

export default function VpnPage() {
  const vpn = useVpn();

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-white">VPN Management</h1>
        <p className="text-sm text-gray-500">
          WireGuard tunnels and IPsec security associations
        </p>
      </div>

      <HelpBanner title="WireGuard in four steps" storageKey="vpn-overview">
        <p>
          <b>1.</b> Create a tunnel — pick a private subnet that doesn&apos;t
          overlap your LAN (e.g. <code>10.10.0.1/24</code>).{" "}
          <b>2.</b> Start it. <b>3.</b> Add a peer for each device.{" "}
          <b>4.</b> Open the peer&apos;s config and import it in the WireGuard
          app on the device.
        </p>
        <p>
          Starting a tunnel handles the plumbing for you: the UDP listen port
          is opened, traffic on the tunnel interface is allowed, and the
          tunnel subnet is NAT&apos;d to the internet through the WAN — no
          manual firewall or NAT rules needed. If the firewall sits behind
          another router, forward the listen port (UDP) to it there.
        </p>
        <p>
          Peers can <i>connect</i> to the firewall over IPv4 or IPv6, but
          traffic <i>inside</i> the tunnel is IPv4-only for now — client
          configs are generated accordingly.
        </p>
      </HelpBanner>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="WG Tunnels" value={vpn.tunnels.length} color="cyan" />
        <SummaryCard
          label="WG Peers"
          value={Object.values(vpn.peersByTunnel).reduce((n, p) => n + p.length, 0)}
          color="blue"
        />
        <SummaryCard label="IPsec Tunnels" value={vpn.ipsecTunnels.length} color="green" />
        <SummaryCard
          label="Active VPNs"
          value={
            vpn.tunnels.filter((t) => t.status === "up").length +
            vpn.ipsecTunnels.filter(
              (t) => vpn.ipsecStatuses[t.id]?.ike_state === "ESTABLISHED",
            ).length
          }
          color="green"
          subtitle={`of ${vpn.tunnels.length + vpn.ipsecTunnels.length} total`}
        />
      </div>

      {/* Error banner */}
      {vpn.error && <ErrorBanner error={vpn.error} onDismiss={() => vpn.setError(null)} />}

      {/* WireGuard section */}
      <WireGuardSection
        tunnels={vpn.tunnels}
        peersByTunnel={vpn.peersByTunnel}
        wgLoading={vpn.wgLoading}
        expandedTunnel={vpn.expandedTunnel}
        vpnStatus={vpn.vpnStatus}
        interfaces={vpn.interfaces}
        showWgForm={vpn.showWgForm}
        wgForm={vpn.wgForm}
        setWgForm={vpn.setWgForm}
        editingWgId={vpn.editingWgId}
        wgSubmitting={vpn.wgSubmitting}
        showPeerForm={vpn.showPeerForm}
        peerForm={vpn.peerForm}
        setPeerForm={vpn.setPeerForm}
        peerSubmitting={vpn.peerSubmitting}
        onAddTunnelClick={vpn.handleAddTunnelClick}
        onSubmitWg={vpn.handleWgSubmit}
        onCancelWg={vpn.handleCancelWg}
        onEditWg={vpn.handleEditWg}
        onDeleteWg={vpn.handleDeleteWg}
        onStartTunnel={vpn.handleStartTunnel}
        onStopTunnel={vpn.handleStopTunnel}
        onExpandTunnel={vpn.handleExpandTunnel}
        onTogglePeerForm={vpn.handleTogglePeerForm}
        onCancelPeerForm={vpn.handleCancelPeerForm}
        onSubmitPeer={vpn.handlePeerSubmit}
        onAutoAssignIp={vpn.handleAutoAssignIp}
        onShowConfig={vpn.handleShowConfig}
        onDeletePeer={vpn.handleDeletePeer}
      />

      {/* IPsec section */}
      <IpsecSection
        ipsecTunnels={vpn.ipsecTunnels}
        ipsecStatuses={vpn.ipsecStatuses}
        ipsecSas={vpn.ipsecSas}
        ipsecLoading={vpn.ipsecLoading}
        showIpsecForm={vpn.showIpsecForm}
        ipsecForm={vpn.ipsecForm}
        setIpsecForm={vpn.setIpsecForm}
        editingIpsecId={vpn.editingIpsecId}
        ipsecSubmitting={vpn.ipsecSubmitting}
        acmeCerts={vpn.acmeCerts}
        onToggleForm={vpn.handleToggleIpsecForm}
        onSubmit={vpn.handleIpsecSubmit}
        onCancel={vpn.handleCancelIpsecForm}
        onEdit={vpn.handleEditIpsec}
        onDeleteTunnel={vpn.handleDeleteIpsecTunnel}
        onStart={vpn.handleStartIpsec}
        onStop={vpn.handleStopIpsec}
        onDeleteLegacySa={vpn.handleDeleteIpsec}
      />

      {/* Peer client-config modal */}
      {vpn.configModal && <ConfigModal config={vpn.configModal} onClose={vpn.closeConfigModal} />}
    </div>
  );
}
