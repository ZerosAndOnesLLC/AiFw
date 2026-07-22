"use client";

import type { WgPeer, WgLiveTunnelStatus } from "@/lib/api/vpn";
import { fmtBytes, fmtDuration } from "@/lib/api/vpn";
import { DeleteButton } from "./DeleteButton";

interface WgPeerTableProps {
  tunnelId: string;
  peers: WgPeer[];
  vpnStatus: WgLiveTunnelStatus[] | undefined;
  onShowConfig: (peer: WgPeer) => void;
  onDeletePeer: (peerId: string) => void;
}

/* ────────────────────────── Peer list ────────────────────────── */

export function WgPeerTable({ tunnelId, peers, vpnStatus, onShowConfig, onDeletePeer }: WgPeerTableProps) {
  if (peers.length === 0) {
    return <p className="text-xs text-gray-500 py-2">No peers configured for this tunnel.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-gray-700/50">
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Name
            </th>
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Public Key
            </th>
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Allowed IPs
            </th>
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Endpoint
            </th>
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Handshake
            </th>
            <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
              Transfer
            </th>
            <th className="w-20" />
          </tr>
        </thead>
        <tbody>
          {peers.map((peer) => (
            <tr key={peer.id} className="border-b border-gray-700/30 hover:bg-gray-800/50">
              <td className="py-2 px-2 text-white font-medium">
                {peer.name || "-"}
              </td>
              <td className="py-2 px-2 font-mono text-gray-300 truncate max-w-[160px]">
                {peer.public_key.slice(0, 16)}...
              </td>
              <td className="py-2 px-2 font-mono text-gray-300">
                {peer.allowed_ips.join(", ")}
              </td>
              <td className="py-2 px-2 font-mono text-gray-400">
                {peer.endpoint || "-"}
              </td>
              {(() => {
                const ts = vpnStatus?.find(v => v.id === tunnelId);
                const ps = ts?.peers?.find(p => p.public_key === peer.public_key);
                return (
                  <>
                    <td className="py-2 px-2 text-gray-400">
                      {ps ? (
                        <span className={ps.latest_handshake_secs_ago >= 0 && ps.latest_handshake_secs_ago < 180 ? "text-green-400" : "text-gray-500"}>
                          {fmtDuration(ps.latest_handshake_secs_ago)}
                        </span>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                    <td className="py-2 px-2 text-gray-400">
                      {ps ? (
                        <span className="text-[10px] font-mono">
                          <span className="text-green-400">{fmtBytes(ps.transfer_rx)}</span>
                          {" / "}
                          <span className="text-blue-400">{fmtBytes(ps.transfer_tx)}</span>
                        </span>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                  </>
                );
              })()}
              <td className="py-2 px-1">
                <div className="flex items-center gap-0.5">
                  <button
                    onClick={() => onShowConfig(peer)}
                    className="p-1.5 text-gray-500 hover:text-green-400 transition-colors rounded hover:bg-gray-700"
                    title="Show client config"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                    </svg>
                  </button>
                  <DeleteButton
                    onClick={() => onDeletePeer(peer.id)}
                    title="Delete peer"
                  />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
