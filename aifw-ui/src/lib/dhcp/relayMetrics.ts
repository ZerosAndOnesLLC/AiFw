/// DHCPv4 relay counters parsed out of rDHCP's Prometheus text (#159).
///
/// rDHCP exposes `rdhcpd_dhcpv4_relayed_received_total` and
/// `rdhcpd_dhcpv4_relayed_dropped_total{reason="…"}` as *global* counters
/// (no subnet label), so this is a top-level view.

export const RELAY_DROP_REASONS = [
  "accept_relayed_disabled",
  "bad_giaddr",
  "untrusted_relay",
  "rate_limit",
] as const;
export type RelayDropReason = (typeof RELAY_DROP_REASONS)[number];

export interface RelayMetrics {
  received: number;
  dropped: Record<RelayDropReason, number>;
  droppedTotal: number;
  accepted: number;
  /** True when the metrics text carried the relay series at all. */
  present: boolean;
}

/** Reasons that indicate probing/abuse rather than misconfiguration. */
export const RELAY_ABUSE_REASONS: RelayDropReason[] = ["untrusted_relay", "bad_giaddr"];

export const RELAY_REASON_HELP: Record<RelayDropReason, string> = {
  accept_relayed_disabled: "Relayed packets arrived while “Accept relayed requests” is off",
  bad_giaddr: "giaddr is a bogon or matches no configured subnet — a misconfigured or spoofing relay",
  untrusted_relay: "Relay source IP not in the subnet’s trusted-relays list",
  rate_limit: "Per-relay-source rate limiter engaged",
};

const emptyDropped = (): Record<RelayDropReason, number> => ({
  accept_relayed_disabled: 0,
  bad_giaddr: 0,
  untrusted_relay: 0,
  rate_limit: 0,
});

/// Parse the relay series out of a Prometheus exposition body. Tolerates
/// missing series (older rDHCP) — `present` is false and everything is 0.
export function parseRelayMetrics(text: string): RelayMetrics {
  const m: RelayMetrics = { received: 0, dropped: emptyDropped(), droppedTotal: 0, accepted: 0, present: false };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    let match = /^rdhcpd_dhcpv4_relayed_received_total(?:\{[^}]*\})?\s+([0-9.eE+-]+)/.exec(line);
    if (match) {
      m.received = Number(match[1]) || 0;
      m.present = true;
      continue;
    }
    match = /^rdhcpd_dhcpv4_relayed_dropped_total\{([^}]*)\}\s+([0-9.eE+-]+)/.exec(line);
    if (match) {
      const reasonMatch = /reason="([^"]+)"/.exec(match[1]);
      const reason = reasonMatch?.[1] as RelayDropReason | undefined;
      if (reason && reason in m.dropped) {
        m.dropped[reason] = Number(match[2]) || 0;
        m.present = true;
      }
    }
  }
  m.droppedTotal = RELAY_DROP_REASONS.reduce((a, r) => a + m.dropped[r], 0);
  m.accepted = Math.max(0, m.received - m.droppedTotal);
  return m;
}

/// Counter deltas between two samples (0 when the counter reset).
export function relayDelta(prev: RelayMetrics | null, cur: RelayMetrics): RelayMetrics {
  if (!prev) return { ...cur, received: 0, dropped: emptyDropped(), droppedTotal: 0, accepted: 0 };
  const d = (a: number, b: number) => (b >= a ? b - a : 0);
  const dropped = emptyDropped();
  for (const r of RELAY_DROP_REASONS) dropped[r] = d(prev.dropped[r], cur.dropped[r]);
  const droppedTotal = RELAY_DROP_REASONS.reduce((a, r) => a + dropped[r], 0);
  const received = d(prev.received, cur.received);
  return { received, dropped, droppedTotal, accepted: Math.max(0, received - droppedTotal), present: cur.present };
}
