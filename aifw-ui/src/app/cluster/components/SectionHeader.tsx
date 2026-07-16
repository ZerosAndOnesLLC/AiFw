import { PlusIcon } from "./PlusIcon";

// ============================================================
// Section header with optional Add button
// ============================================================

export function SectionHeader({
  title,
  onAdd,
  addLabel = "Add",
}: {
  title: string;
  onAdd?: () => void;
  addLabel?: string;
}) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-lg font-semibold">{title}</h2>
      {onAdd && (
        <button
          onClick={onAdd}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <PlusIcon />
          {addLabel}
        </button>
      )}
    </div>
  );
}
