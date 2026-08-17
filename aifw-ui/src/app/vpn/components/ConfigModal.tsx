"use client";

import { useState } from "react";
import type { ConfigModalData } from "@/lib/api/vpn";
import { ModalOverlay } from "@/components/ui/ModalOverlay";

interface ConfigModalProps {
  config: ConfigModalData;
  onClose: () => void;
}

/* ═══════════════ Config Modal ═══════════════ */

export function ConfigModal({ config, onClose }: ConfigModalProps) {
  const [configTab, setConfigTab] = useState<"full" | "split">("full");
  const [configCopied, setConfigCopied] = useState(false);

  const handleCopyConfig = () => {
    const text = configTab === "full" ? config.fullTunnel : config.splitTunnel;
    navigator.clipboard.writeText(text);
    setConfigCopied(true);
    setTimeout(() => setConfigCopied(false), 2000);
  };

  return (
    <ModalOverlay onClose={onClose} ariaLabel="WireGuard client configuration"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      panelClassName="relative w-full max-w-2xl bg-gray-800 border border-gray-700 rounded-xl shadow-2xl m-4">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">
            Client Config — {config.peerName}
          </h3>
          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyConfig}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                configCopied
                  ? "bg-green-600 text-white"
                  : "bg-blue-600 hover:bg-blue-700 text-white"
              }`}
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                {configCopied ? (
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" />
                )}
              </svg>
              {configCopied ? "Copied!" : "Copy"}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <div className="p-6">
          {/* Full / Split tabs */}
          <div className="flex gap-2 mb-3">
            <button onClick={() => { setConfigTab("full"); setConfigCopied(false); }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                configTab === "full"
                  ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                  : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"
              }`}>
              Full Tunnel
            </button>
            <button onClick={() => { setConfigTab("split"); setConfigCopied(false); }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                configTab === "split"
                  ? "bg-purple-600/20 border-purple-500/40 text-purple-400"
                  : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"
              }`}>
              Split Tunnel
            </button>
          </div>
          <p className="text-xs text-gray-400 mb-3">
            {configTab === "full"
              ? "Everything goes through the VPN: the device reaches the internet via the firewall\u2019s WAN address. Use this on untrusted networks (public Wi-Fi) or to apply the firewall\u2019s filtering everywhere. IPv6 goes through the VPN too when the tunnel has an IPv6 address; otherwise it stays on the device\u2019s normal connection."
              : "Only the VPN subnet (plus any split-tunnel routes configured on the tunnel) goes through the VPN \u2014 use this to reach home/office devices while everything else uses the device\u2019s normal connection. Faster, but internet traffic is not protected by the VPN."}
          </p>
          <pre className="bg-gray-900 border border-gray-700 rounded-lg p-4 text-sm font-mono text-green-400 whitespace-pre-wrap select-all overflow-x-auto">
            {configTab === "full" ? config.fullTunnel : config.splitTunnel}
          </pre>
          <p className="text-xs text-gray-500 mt-3">
            To use it: copy the config, then in the WireGuard app on the
            device choose <b>Add tunnel</b> and paste (or save it as a{" "}
            <code>.conf</code> file and import). If the tunnel here
            isn&apos;t started yet, start it first \u2014 nothing will connect
            until it is.
          </p>
        </div>
    </ModalOverlay>
  );
}
