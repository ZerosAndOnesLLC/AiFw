import { btnPrimary, btnSecondary } from "./styles";

// ============================================================
// Inline form card (reusable shell)
// ============================================================

export function FormCard({
  title,
  onCancel,
  onSave,
  saving,
  children,
}: {
  title: string;
  onCancel: () => void;
  onSave: () => void;
  saving: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4 mb-4">
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      {children}
      <div className="flex gap-2">
        <button onClick={onSave} disabled={saving} className={btnPrimary}>
          {saving ? "Saving..." : "Save"}
        </button>
        <button onClick={onCancel} className={btnSecondary}>
          Cancel
        </button>
      </div>
    </div>
  );
}
