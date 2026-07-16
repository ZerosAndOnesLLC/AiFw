"use client";

/* ── Key-value editor (for headers) ────────────────────────── */

export function KeyValueEditor({
  label,
  value,
  onChange,
}: {
  label: string;
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
}) {
  const entries = Object.entries(value || {});

  function addRow() {
    onChange({ ...value, "": "" });
  }

  function removeRow(key: string) {
    const next = { ...value };
    delete next[key];
    onChange(next);
  }

  function updateRow(oldKey: string, newKey: string, newValue: string) {
    const next: Record<string, string> = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === oldKey) {
        next[newKey] = newValue;
      } else {
        next[k] = v;
      }
    }
    onChange(next);
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <label className="block text-xs text-gray-400">{label}</label>
        <button
          type="button"
          onClick={addRow}
          className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          + Add
        </button>
      </div>
      {entries.length === 0 && (
        <p className="text-xs text-gray-500 italic">No entries</p>
      )}
      <div className="space-y-1.5">
        {entries.map(([k, v], i) => (
          <div key={i} className="flex items-center gap-2">
            <input
              type="text"
              value={k}
              onChange={(e) => updateRow(k, e.target.value, v)}
              placeholder="Header name"
              className="flex-1 bg-gray-900 border border-gray-600 rounded-md px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <input
              type="text"
              value={v}
              onChange={(e) => updateRow(k, k, e.target.value)}
              placeholder="Value"
              className="flex-1 bg-gray-900 border border-gray-600 rounded-md px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <button
              type="button"
              onClick={() => removeRow(k)}
              className="text-gray-500 hover:text-red-400 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
