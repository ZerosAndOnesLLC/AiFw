"use client";

import type { Dispatch, SetStateAction } from "react";
import type { WgTunnel, WgPeer, WgLiveTunnelStatus, PeerFormState } from "@/lib/api/vpn";
import { StatusBadge } from "./StatusBadge";
import { EditButton } from "./EditButton";
import { DeleteButton } from "./DeleteButton";
import { WgPeerForm } from "./WgPeerForm";
import { WgPeerTable } from "./WgPeerTable";

interface WgTunnelRowProps {
  tunnel: WgTunnel;
  isExpanded: boolean;
  peers: WgPeer[];
  vpnStatus: WgLiveTunnelStatus[] | undefined;
  peerFormOpen: boolean;
  peerForm: PeerFormState;
  setPeerForm: Dispatch<SetStateAction<PeerFormState>>;
  peerSubmitting: boolean;
  onToggleExpand: () => void;
  onStart: () => void;
  onStop: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onTogglePeerForm: () => void;
  onCancelPeerForm: () => void;
  onSubmitPeer: () => void;
  onAutoAssignIp: () => void;
  onShowConfig: (peer: WgPeer) => void;
  onDeletePeer: (peerId: string) => void;
}

/* ────────────────────────── Tunnel card + peers panel ────────────────────────── */

export function WgTunnelRow({
  tunnel,
  isExpanded,
  peers,
  vpnStatus,
  peerFormOpen,
  peerForm,
  setPeerForm,
  peerSubmitting,
  onToggleExpand,
  onStart,
  onStop,
  onEdit,
  onDelete,
  onTogglePeerForm,
  onCancelPeerForm,
  onSubmitPeer,
  onAutoAssignIp,
  onShowConfig,
  onDeletePeer,
}: WgTunnelRowProps) {
  return (
    <div>
      {/* Tunnel card */}
      <div className="p-4 hover:bg-gray-700/20 transition-colors">
        <div className="flex items-center justify-between mb-2">
          <button
            onClick={onToggleExpand}
            className="flex items-center gap-3 text-left"
          >
            <svg
              className={`w-4 h-4 text-gray-500 transition-transform duration-200 ${
                isExpanded ? "rotate-90" : ""
              }`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
            </svg>
            <span className="font-medium text-white">{tunnel.name}</span>
            <StatusBadge status={tunnel.status} />
          </button>
          <div className="flex items-center gap-1">
            {tunnel.status === "up" ? (
              <button onClick={onStop}
                className="px-2.5 py-1 text-[10px] font-medium rounded bg-red-600 hover:bg-red-700 text-white transition-colors"
                title="Stop tunnel">Stop</button>
            ) : (
              <button onClick={onStart}
                className="px-2.5 py-1 text-[10px] font-medium rounded bg-green-600 hover:bg-green-700 text-white transition-colors"
                title="Start tunnel">Start</button>
            )}
            <EditButton onClick={onEdit} title="Edit tunnel" />
            <DeleteButton onClick={onDelete} title="Delete tunnel" />
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3 text-xs ml-7">
          <div>
            <span className="text-gray-500">Interface:</span>{" "}
            <span className="text-gray-300 font-mono">{tunnel.interface}</span>
          </div>
          <div>
            <span className="text-gray-500">Listen On:</span>{" "}
            <span className="text-gray-300 font-mono">{tunnel.listen_interface || "any"}</span>
          </div>
          <div>
            <span className="text-gray-500">Port:</span>{" "}
            <span className="text-gray-300">{tunnel.listen_port}</span>
          </div>
          <div>
            <span className="text-gray-500">Address:</span>{" "}
            <span className="text-gray-300 font-mono">
              {tunnel.address}
              {tunnel.address6 ? `, ${tunnel.address6}` : ""}
            </span>
          </div>
          <div className="md:col-span-2">
            <span className="text-gray-500">Public Key:</span>{" "}
            <span className="text-gray-300 font-mono truncate">{tunnel.public_key}</span>
          </div>
        </div>
      </div>

      {/* Expanded peers panel */}
      {isExpanded && (
        <div className="bg-gray-900/40 border-t border-gray-700/50 px-4 py-3 ml-4 mr-4 mb-3 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-medium text-gray-300">
              Peers ({peers.length})
            </h4>
            <button
              onClick={onTogglePeerForm}
              className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded bg-green-600 hover:bg-green-700 text-white transition-colors"
            >
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add Peer
            </button>
          </div>

          {/* Add peer form */}
          {peerFormOpen && (
            <WgPeerForm
              peerForm={peerForm}
              setPeerForm={setPeerForm}
              peerSubmitting={peerSubmitting}
              onSubmit={onSubmitPeer}
              onCancel={onCancelPeerForm}
              onAutoAssignIp={onAutoAssignIp}
            />
          )}

          {/* Peer list */}
          <WgPeerTable
            tunnelId={tunnel.id}
            peers={peers}
            vpnStatus={vpnStatus}
            onShowConfig={onShowConfig}
            onDeletePeer={onDeletePeer}
          />
        </div>
      )}
    </div>
  );
}
