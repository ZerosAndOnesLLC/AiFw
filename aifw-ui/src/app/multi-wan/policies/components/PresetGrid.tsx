import { PRESETS, Preset } from "@/lib/api/multiwan-policies";

export function PresetGrid({ onApply }: { onApply: (p: Preset) => void }) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <h2 className="text-lg font-semibold text-white mb-2">Start with a preset</h2>
      <p className="text-sm text-[var(--text-muted)] mb-4">
        Common policies pre-filled for you. Pick one to open the form, or start blank.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {PRESETS.map((p) => (
          <button
            key={p.name}
            onClick={() => onApply(p)}
            className="text-left p-3 rounded border border-[var(--border)] bg-black/20 hover:bg-black/40 hover:border-blue-500/50 transition-colors"
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xl">{p.icon}</span>
              <span className="text-white font-medium">{p.name}</span>
            </div>
            <p className="text-xs text-[var(--text-muted)]">{p.description}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
