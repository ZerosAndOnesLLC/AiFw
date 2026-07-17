"use client";

interface ToggleRowProps {
  checked: boolean;
  onToggle: () => void;
  label: string;
}

/// Standard labelled on/off pill toggle used throughout the resolver
/// settings tabs.
export function ToggleRow({ checked, onToggle, label }: ToggleRowProps) {
  return (
    <div className="flex items-center gap-3">
      <button
        type="button"
        onClick={onToggle}
        className={`relative w-11 h-6 rounded-full transition-colors ${
          checked ? "bg-blue-600" : "bg-gray-600"
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
            checked ? "translate-x-5" : ""
          }`}
        />
      </button>
      <span className="text-sm text-[var(--text-primary)]">{label}</span>
    </div>
  );
}
