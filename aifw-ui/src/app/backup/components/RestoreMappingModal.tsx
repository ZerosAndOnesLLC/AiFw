"use client";

import type { ImportPreview } from "@/lib/api/backup";
import { InterfaceMappingPanel } from "./InterfaceMappingPanel";
import { btnPrimary, btnSecondary } from "./styles";

/* ============ History Restore — NIC mapping modal ============ */

export function RestoreMappingModal({
  pending,
  map,
  onMapChange,
  restoring,
  onCancel,
  onApply,
}: {
  pending: { version: number; preview: ImportPreview };
  map: Record<string, string>;
  onMapChange: (m: Record<string, string>) => void;
  restoring: number | null;
  onCancel: () => void;
  onApply: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-5 border-b border-[var(--border)]">
          <h3 className="text-lg font-semibold">Restore v{pending.version} — Interface Mapping Required</h3>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            This snapshot references {pending.preview.interfaces_missing.length} interface name(s)
            that don&apos;t exist on this system. Map each one to a local interface, keep the name, or drop entries that reference it.
          </p>
        </div>
        <div className="p-5">
          <InterfaceMappingPanel
            preview={pending.preview}
            map={map}
            onMapChange={onMapChange}
          />
        </div>
        <div className="p-5 border-t border-[var(--border)] flex gap-3 justify-end">
          <button
            className={btnSecondary}
            onClick={onCancel}
            disabled={restoring !== null}
          >Cancel</button>
          <button
            className={btnPrimary}
            disabled={restoring !== null}
            onClick={onApply}
          >{restoring !== null ? "Restoring..." : "Apply Mapping & Restore"}</button>
        </div>
      </div>
    </div>
  );
}
