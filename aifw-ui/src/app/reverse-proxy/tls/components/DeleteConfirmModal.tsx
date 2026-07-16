"use client";

interface DeleteConfirmModalProps {
  targetType: "cert" | "option" | "resolver";
  onCancel: () => void;
  onConfirm: () => void;
}

export function DeleteConfirmModal({ targetType, onCancel, onConfirm }: DeleteConfirmModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          Delete {targetType === "cert" ? "Certificate" : targetType === "option" ? "TLS Option" : "Certificate Resolver"}
        </h3>
        <p className="text-sm text-[var(--text-secondary)]">
          Are you sure you want to delete this {targetType === "cert" ? "certificate" : targetType === "option" ? "TLS option" : "certificate resolver"}? This action cannot be undone.
        </p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}
