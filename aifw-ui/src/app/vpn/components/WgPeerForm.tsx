"use client";

import type { Dispatch, SetStateAction } from "react";
import type { PeerFormState } from "@/lib/api/vpn";
import Help from "../Help";
import { inputCls, labelCls, btnPrimary, btnCancel } from "./styles";

interface WgPeerFormProps {
  peerForm: PeerFormState;
  setPeerForm: Dispatch<SetStateAction<PeerFormState>>;
  peerSubmitting: boolean;
  onSubmit: () => void;
  onCancel: () => void;
  onAutoAssignIp: () => void;
}

/* ────────────────────────── Add peer form ────────────────────────── */

export function WgPeerForm({
  peerForm,
  setPeerForm,
  peerSubmitting,
  onSubmit,
  onCancel,
  onAutoAssignIp,
}: WgPeerFormProps) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 mb-3">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <div>
          <label className={labelCls}>Name</label>
          <input
            type="text"
            value={peerForm.name}
            onChange={(e) => setPeerForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. laptop, phone"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            Client IP{" "}
            <Help title="Client IP" size="xs">
              This device&apos;s address inside the
              tunnel, e.g. <code>10.10.0.2/32</code>.
              Every peer needs its own — <b>Auto</b>{" "}
              picks the next free IP in the tunnel
              subnet.
            </Help>
          </label>
          <div className="flex gap-1">
            <input
              type="text"
              value={peerForm.allowed_ips}
              onChange={(e) => setPeerForm((f) => ({ ...f, allowed_ips: e.target.value }))}
              placeholder="10.10.0.2/32"
              className={inputCls}
            />
            <button type="button" onClick={onAutoAssignIp}
              className="px-2 py-1 text-[10px] font-medium rounded bg-purple-600 hover:bg-purple-700 text-white whitespace-nowrap transition-colors"
              title="Auto-assign next free IP">Auto</button>
          </div>
        </div>
        <div>
          <label className={labelCls}>
            Keepalive (sec){" "}
            <Help title="Persistent keepalive" size="xs">
              Sends a packet every N seconds so NAT
              routers along the way don&apos;t drop
              the connection. Use <b>25</b> for
              phones and laptops; leave empty for
              site-to-site peers with public IPs.
            </Help>
          </label>
          <input
            type="number"
            value={peerForm.keepalive}
            onChange={(e) => setPeerForm((f) => ({ ...f, keepalive: e.target.value }))}
            placeholder="25"
            className={inputCls}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-3">
        <div className="flex items-end pb-0.5">
          <label className="flex items-center gap-2 cursor-pointer select-none text-sm text-gray-300">
            <input
              type="checkbox"
              checked={peerForm.auto_generate_key}
              onChange={(e) => setPeerForm((f) => ({ ...f, auto_generate_key: e.target.checked }))}
              className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
            />
            Auto-generate keypair
          </label>
        </div>
        {!peerForm.auto_generate_key && (
          <div>
            <label className={labelCls}>Public Key</label>
            <input
              type="text"
              value={peerForm.public_key}
              onChange={(e) => setPeerForm((f) => ({ ...f, public_key: e.target.value }))}
              placeholder="Peer public key"
              className={inputCls}
            />
          </div>
        )}
        <div>
          <label className={labelCls}>
            Endpoint (optional){" "}
            <Help title="Peer endpoint" size="xs">
              Only for site-to-site links where the
              firewall should dial <i>out</i> to a
              peer at a fixed address. Leave empty
              for roaming devices (phones, laptops)
              — they connect in to this firewall.
            </Help>
          </label>
          <input
            type="text"
            value={peerForm.endpoint}
            onChange={(e) => setPeerForm((f) => ({ ...f, endpoint: e.target.value }))}
            placeholder="1.2.3.4:51820"
            className={inputCls}
          />
        </div>
      </div>
      {peerForm.auto_generate_key && (
        <p className="text-[10px] text-green-400 mt-2">
          A keypair will be generated automatically. After creating the peer, click the Config button to get a ready-to-use .conf file.
        </p>
      )}
      <div className="flex gap-2 mt-3">
        <button
          onClick={onSubmit}
          disabled={peerSubmitting || (!peerForm.auto_generate_key && !peerForm.public_key.trim()) || !peerForm.allowed_ips.trim()}
          className={btnPrimary}
        >
          {peerSubmitting ? "Adding..." : "Add Peer"}
        </button>
        <button
          onClick={onCancel}
          className={btnCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
