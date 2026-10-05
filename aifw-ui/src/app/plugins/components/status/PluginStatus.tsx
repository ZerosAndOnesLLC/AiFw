import { NotifierStatus, NotifierStatusData } from "./NotifierStatus";
import { ThreatFeedsStatus, ThreatFeedsStatusData } from "./ThreatFeedsStatus";

/** Plugin-specific status view; unknown plugins get a JSON dump. */
export function PluginStatus({ name, status }: { name: string; status: unknown }) {
  if (status === null || status === undefined) return null;
  if (name === "threat-feeds") return <ThreatFeedsStatus s={status as ThreatFeedsStatusData} />;
  if (name === "notifier") return <NotifierStatus s={status as NotifierStatusData} />;
  return (
    <pre className="text-xs p-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] overflow-x-auto text-[var(--text-secondary)]">
      {JSON.stringify(status, null, 2)}
    </pre>
  );
}
