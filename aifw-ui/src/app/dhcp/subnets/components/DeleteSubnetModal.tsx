"use client";

export interface DeleteSubnetModalProps {
  onCancel: () => void;
  onConfirm: () => void;
}

export function DeleteSubnetModal({ onCancel, onConfirm }: DeleteSubnetModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
        <h3 className="text-lg font-semibold text-white">Delete Subnet</h3>
        <p className="text-sm text-[var(--text-secondary)]">
          Are you sure you want to delete this subnet? All associated reservations and leases
          will be affected.
        </p>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
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
