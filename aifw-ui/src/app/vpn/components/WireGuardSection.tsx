"use client";

import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  WgTunnel,
  WgPeer,
  VpnInterface,
  WgLiveTunnelStatus,
  WgFormState,
  PeerFormState,
} from "@/lib/api/vpn";
import { ChevronIcon } from "./ChevronIcon";
import { WgTunnelForm } from "./WgTunnelForm";
import { WgTunnelRow } from "./WgTunnelRow";

interface WireGuardSectionProps {
  tunnels: WgTunnel[];
  peersByTunnel: Record<string, WgPeer[]>;
  wgLoading: boolean;
  expandedTunnel: string | null;
  vpnStatus: WgLiveTunnelStatus[] | undefined;
  interfaces: VpnInterface[];
  showWgForm: boolean;
  wgForm: WgFormState;
  setWgForm: Dispatch<SetStateAction<WgFormState>>;
  editingWgId: string | null;
  wgSubmitting: boolean;
  showPeerForm: string | null;
  peerForm: PeerFormState;
  setPeerForm: Dispatch<SetStateAction<PeerFormState>>;
  peerSubmitting: boolean;
  onAddTunnelClick: () => void;
  onSubmitWg: () => void;
  onCancelWg: () => void;
  onEditWg: (tunnel: WgTunnel) => void;
  onDeleteWg: (id: string) => void;
  onStartTunnel: (id: string) => void;
  onStopTunnel: (id: string) => void;
  onExpandTunnel: (id: string) => void;
  onTogglePeerForm: (tunnelId: string) => void;
  onCancelPeerForm: () => void;
  onSubmitPeer: (tunnelId: string) => void;
  onAutoAssignIp: (tunnelId: string) => void;
  onShowConfig: (tunnelId: string, peer: WgPeer) => void;
  onDeletePeer: (tunnelId: string, peerId: string) => void;
}

/* ═══════════════ WireGuard Section ═══════════════ */

export function WireGuardSection({
  tunnels,
  peersByTunnel,
  wgLoading,
  expandedTunnel,
  vpnStatus,
  interfaces,
  showWgForm,
  wgForm,
  setWgForm,
  editingWgId,
  wgSubmitting,
  showPeerForm,
  peerForm,
  setPeerForm,
  peerSubmitting,
  onAddTunnelClick,
  onSubmitWg,
  onCancelWg,
  onEditWg,
  onDeleteWg,
  onStartTunnel,
  onStopTunnel,
  onExpandTunnel,
  onTogglePeerForm,
  onCancelPeerForm,
  onSubmitPeer,
  onAutoAssignIp,
  onShowConfig,
  onDeletePeer,
}: WireGuardSectionProps) {
  const [wgOpen, setWgOpen] = useState(true);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      {/* Section header */}
      <button
        onClick={() => setWgOpen((o) => !o)}
        className="w-full flex items-center justify-between p-4 hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-white">WireGuard Tunnels</h2>
          <span className="text-xs text-gray-500">{tunnels.length} tunnel(s)</span>
        </div>
        <ChevronIcon open={wgOpen} />
      </button>

      {wgOpen && (
        <div className="border-t border-gray-700">
          {/* Add Tunnel button */}
          <div className="px-4 py-3 flex justify-end border-b border-gray-700/50">
            <button
              onClick={onAddTunnelClick}
              className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add Tunnel
            </button>
          </div>

          {/* Tunnel form */}
          {showWgForm && (
            <WgTunnelForm
              wgForm={wgForm}
              setWgForm={setWgForm}
              editingWgId={editingWgId}
              wgSubmitting={wgSubmitting}
              interfaces={interfaces}
              onSubmit={onSubmitWg}
              onCancel={onCancelWg}
            />
          )}

          {/* Tunnel list */}
          {wgLoading ? (
            <div className="text-center py-12 text-gray-500">Loading tunnels...</div>
          ) : tunnels.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <p>No WireGuard tunnels configured</p>
              <p className="text-xs mt-2 max-w-md mx-auto">
                Click <b>Add Tunnel</b> to get started — firewall rules and
                NAT are set up automatically when the tunnel starts, so
                peers can reach the internet right away.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-700/50">
              {tunnels.map((tunnel) => (
                <WgTunnelRow
                  key={tunnel.id}
                  tunnel={tunnel}
                  isExpanded={expandedTunnel === tunnel.id}
                  peers={peersByTunnel[tunnel.id] || []}
                  vpnStatus={vpnStatus}
                  peerFormOpen={showPeerForm === tunnel.id}
                  peerForm={peerForm}
                  setPeerForm={setPeerForm}
                  peerSubmitting={peerSubmitting}
                  onToggleExpand={() => onExpandTunnel(tunnel.id)}
                  onStart={() => onStartTunnel(tunnel.id)}
                  onStop={() => onStopTunnel(tunnel.id)}
                  onEdit={() => onEditWg(tunnel)}
                  onDelete={() => onDeleteWg(tunnel.id)}
                  onTogglePeerForm={() => onTogglePeerForm(tunnel.id)}
                  onCancelPeerForm={onCancelPeerForm}
                  onSubmitPeer={() => onSubmitPeer(tunnel.id)}
                  onAutoAssignIp={() => onAutoAssignIp(tunnel.id)}
                  onShowConfig={(peer) => onShowConfig(tunnel.id, peer)}
                  onDeletePeer={(peerId) => onDeletePeer(tunnel.id, peerId)}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
