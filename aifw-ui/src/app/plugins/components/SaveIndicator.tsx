import { CircleCheck, LoaderCircle } from "lucide-react";
import { FieldSave } from "@/hooks/usePlugin";

/** Inline per-field auto-save state. Errors render under the input. */
export function SaveIndicator({ save }: { save?: FieldSave }) {
  if (!save || save.state === "error") return null;
  if (save.state === "saving") {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-[var(--text-muted)]">
        <LoaderCircle className="h-3 w-3 animate-spin" aria-hidden /> Saving
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-xs text-green-400">
      <CircleCheck className="h-3 w-3" aria-hidden /> Saved
    </span>
  );
}
