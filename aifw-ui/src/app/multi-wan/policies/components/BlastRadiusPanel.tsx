import { BlastRadius } from "@/lib/api/multiwan-policies";
import { Stat } from "./Stat";

export function BlastRadiusPanel({
  blast,
  onDismiss,
}: {
  blast: BlastRadius;
  onDismiss: () => void;
}) {
  return (
    <div className="bg-[var(--bg-card)] border border-purple-500/30 rounded-lg p-4 space-y-3">
      <div className="flex justify-between items-start">
        <h2 className="text-lg font-semibold text-white">
          Blast radius
          {blast.would_strand_mgmt && (
            <span className="ml-2 text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
              ⚠ would strand management
            </span>
          )}
        </h2>
        <button
          onClick={onDismiss}
          className="text-xs text-[var(--text-muted)] hover:text-white"
        >
          Dismiss
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
        <Stat label="New pf rules" value={blast.new_rules.length.toString()} color="green" />
        <Stat
          label="Removed pf rules"
          value={blast.removed_rules.length.toString()}
          color="yellow"
        />
        <Stat
          label="Affected flows"
          value={blast.affected_flows.length.toString()}
          color="blue"
        />
      </div>
      {blast.validation.length > 0 && (
        <div className="space-y-1">
          {blast.validation.map((v, i) => (
            <div
              key={i}
              className={`text-xs px-2 py-1 rounded ${
                v.severity === "error"
                  ? "bg-red-500/10 text-red-400 border border-red-500/20"
                  : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
              }`}
            >
              [{v.severity}] {v.message}
            </div>
          ))}
        </div>
      )}
      {blast.new_rules.length > 0 && (
        <details className="bg-black/30 rounded p-2">
          <summary className="text-xs text-green-400 cursor-pointer">
            + {blast.new_rules.length} new rules
          </summary>
          <pre className="text-xs font-mono text-green-300 mt-2 whitespace-pre-wrap">
            {blast.new_rules.join("\n")}
          </pre>
        </details>
      )}
      {blast.removed_rules.length > 0 && (
        <details className="bg-black/30 rounded p-2">
          <summary className="text-xs text-yellow-400 cursor-pointer">
            − {blast.removed_rules.length} removed rules
          </summary>
          <pre className="text-xs font-mono text-yellow-300 mt-2 whitespace-pre-wrap">
            {blast.removed_rules.join("\n")}
          </pre>
        </details>
      )}
    </div>
  );
}
