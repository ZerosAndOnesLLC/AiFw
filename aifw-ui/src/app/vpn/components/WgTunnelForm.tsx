"use client";

import type { Dispatch, SetStateAction } from "react";
import type { VpnInterface, WgFormState } from "@/lib/api/vpn";
import Help from "../Help";
import { inputCls, selectCls, labelCls, btnPrimary, btnCancel } from "./styles";

interface WgTunnelFormProps {
  wgForm: WgFormState;
  setWgForm: Dispatch<SetStateAction<WgFormState>>;
  editingWgId: string | null;
  wgSubmitting: boolean;
  interfaces: VpnInterface[];
  onSubmit: () => void;
  onCancel: () => void;
}

/* ────────────────────────── Tunnel form ────────────────────────── */

export function WgTunnelForm({
  wgForm,
  setWgForm,
  editingWgId,
  wgSubmitting,
  interfaces,
  onSubmit,
  onCancel,
}: WgTunnelFormProps) {
  return (
    <div className="px-4 py-4 bg-gray-900/50 border-b border-gray-700">
      <h3 className="text-sm font-semibold text-white mb-3">
        {editingWgId ? "Edit Tunnel" : "New WireGuard Tunnel"}
      </h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <label className={labelCls}>Name</label>
          <input
            type="text"
            value={wgForm.name}
            onChange={(e) => setWgForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. wg0-office"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            Listen Port{" "}
            <Help title="Listen port" size="xs">
              UDP port peers connect to (51820 is the convention).
              It is opened in the firewall automatically when the
              tunnel starts. Behind another router? Forward this
              UDP port to the firewall there.
            </Help>
          </label>
          <input
            type="number"
            value={wgForm.listen_port}
            onChange={(e) => setWgForm((f) => ({ ...f, listen_port: e.target.value }))}
            placeholder="51820"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            IPv4 Address (CIDR){" "}
            <Help title="Tunnel address" size="xs">
              The firewall&apos;s IP <i>inside</i> the VPN, plus the
              tunnel subnet size — e.g. <code>10.10.0.1/24</code>.
              Peers get other IPs from this subnet. Use a private
              range that doesn&apos;t overlap your LAN or any
              network you connect from.
            </Help>
          </label>
          <input
            type="text"
            value={wgForm.address}
            onChange={(e) => setWgForm((f) => ({ ...f, address: e.target.value }))}
            placeholder="10.0.0.1/24"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            IPv6 Address (optional){" "}
            <Help title="IPv6 tunnel address" size="xs">
              Add this to make the tunnel dual-stack: peers get an
              IPv6 address too, and full-tunnel configs route IPv6
              through the VPN. Use a unique-local subnet like{" "}
              <code>fd00:a1f0::1/64</code>. IPv6 egress is NAT&apos;d
              through the WAN automatically (the WAN needs a working
              IPv6 address for peers to reach the v6 internet).
              Leave empty for an IPv4-only tunnel.
            </Help>
          </label>
          <input
            type="text"
            value={wgForm.address6}
            onChange={(e) => setWgForm((f) => ({ ...f, address6: e.target.value }))}
            placeholder="fd00:a1f0::1/64"
            className={inputCls}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
        <div>
          <label className={labelCls}>
            Listen Interface{" "}
            <Help title="Listen interface" size="xs">
              Restricts which interface accepts WireGuard
              handshakes. <b>Any</b> is fine for most setups; pick
              your WAN to be strict.
            </Help>
          </label>
          <select
            value={wgForm.listen_interface}
            onChange={(e) => setWgForm((f) => ({ ...f, listen_interface: e.target.value }))}
            className={selectCls}
          >
            <option value="any">Any (all interfaces)</option>
            {interfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name}{iface.role ? ` (${iface.role})` : ""}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelCls}>
            DNS Servers{" "}
            <Help title="DNS for clients" size="xs">
              Pushed to devices while connected. Use the tunnel
              address (e.g. <code>10.10.0.1</code>) to resolve
              through this firewall&apos;s DNS — including any
              blocklists — or leave empty to keep each
              device&apos;s own DNS.
            </Help>
          </label>
          <input
            type="text"
            value={wgForm.dns}
            onChange={(e) => setWgForm((f) => ({ ...f, dns: e.target.value }))}
            placeholder="1.1.1.1, 8.8.8.8"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            MTU{" "}
            <Help title="MTU" size="xs">
              Leave empty for the default (1420). Lower it (e.g.
              1380) only if large transfers stall while small
              pages load fine — common on PPPoE links.
            </Help>
          </label>
          <input
            type="number"
            value={wgForm.mtu}
            onChange={(e) => setWgForm((f) => ({ ...f, mtu: e.target.value }))}
            placeholder="1420 (default)"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>
            Private Key (optional){" "}
            <Help title="Private key" size="xs">
              Leave empty — a keypair is generated for you. Only
              paste a key here when migrating an existing
              WireGuard server so peers keep working.
            </Help>
          </label>
          <input
            type="password"
            value={wgForm.private_key}
            onChange={(e) => setWgForm((f) => ({ ...f, private_key: e.target.value }))}
            placeholder="Auto-generated if empty"
            className={inputCls}
          />
        </div>
      </div>
      <div className="mt-3">
        <label className={labelCls}>
          Split-tunnel routes{" "}
          <span className="text-gray-500 font-normal">
            (comma-separated CIDRs for the split-tunnel <code>AllowedIPs</code>)
          </span>
        </label>
        <input
          type="text"
          value={wgForm.split_routes}
          onChange={(e) => setWgForm((f) => ({ ...f, split_routes: e.target.value }))}
          placeholder="172.29.0.0/16, 10.0.0.0/8 — leave empty to use tunnel subnet"
          className={inputCls}
        />
        <p className="text-xs text-gray-500 mt-1">
          When a client uses split-tunnel mode, only these networks are
          routed through the VPN. IPv6 CIDRs work too. Empty = just the
          tunnel&apos;s own subnet(s). Use this to reach your whole LAN
          over the VPN.
        </p>
      </div>
      <div className="flex gap-2 mt-3">
        <button
          onClick={onSubmit}
          disabled={wgSubmitting || !wgForm.name.trim() || !wgForm.address.trim() || !wgForm.listen_port}
          className={btnPrimary}
        >
          {wgSubmitting ? "Saving..." : editingWgId ? "Update Tunnel" : "Create Tunnel"}
        </button>
        <button onClick={onCancel} className={btnCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
