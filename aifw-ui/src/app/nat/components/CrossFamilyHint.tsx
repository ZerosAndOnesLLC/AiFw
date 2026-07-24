// Live preview panel for cross-family (af-to) NAT rules (#531): makes the
// RFC 6052 embedded-address behavior visible while the form is filled in.
"use client";

import { embedRfc6052, WELL_KNOWN_PREFIX } from "./crossFamily";

export default function CrossFamilyHint({
  natType,
  dstAddr,
  redirectAddr,
}: {
  natType: string;
  dstAddr: string;
  redirectAddr: string;
}) {
  if (natType === "nat64") {
    const prefix = dstAddr || WELL_KNOWN_PREFIX;
    const example = embedRfc6052(prefix, "10.0.0.1");
    return (
      <div className="mt-3 bg-cyan-500/5 border border-cyan-500/20 rounded-md p-3 text-xs text-gray-400 space-y-1">
        <p className="text-cyan-400 font-medium">NAT64 — IPv6-only clients reaching IPv4 hosts</p>
        <p>
          IPv6 clients reach any IPv4 host through the prefix{" "}
          <span className="font-mono text-white">{prefix}</span>: the IPv4 address is embedded in
          the last 32 bits (RFC 6052).
        </p>
        {example && (
          <p>
            Example: <span className="font-mono text-white">10.0.0.1</span> is reached at{" "}
            <span className="font-mono text-cyan-300">{example}</span>
          </p>
        )}
        {redirectAddr && (
          <p>
            Translated traffic leaves sourced from{" "}
            <span className="font-mono text-white">{redirectAddr}</span>. Point clients&apos; DNS64
            at the same prefix so hostnames resolve automatically.
          </p>
        )}
        <p className="text-gray-500">Requires FreeBSD 15+ (pf af-to). Applied on inbound traffic of the selected interface.</p>
      </div>
    );
  }

  if (natType === "nat46") {
    const embedded =
      dstAddr && redirectAddr ? embedRfc6052(redirectAddr, dstAddr) : null;
    return (
      <div className="mt-3 bg-orange-500/5 border border-orange-500/20 rounded-md p-3 text-xs text-gray-400 space-y-1">
        <p className="text-orange-400 font-medium">NAT46 — IPv4-only clients reaching an IPv6 service</p>
        <p>
          The translated destination is the IPv4 destination embedded in the /96 subnet of the IPv6
          translation source (RFC 6052).
        </p>
        {embedded && (
          <p>
            The IPv6 server must answer on{" "}
            <span className="font-mono text-orange-300">{embedded}</span> (embedding of{" "}
            <span className="font-mono text-white">{dstAddr}</span>).
          </p>
        )}
        <p className="text-gray-500">Requires FreeBSD 15+ (pf af-to). Applied on inbound traffic of the selected interface.</p>
      </div>
    );
  }

  return null;
}
