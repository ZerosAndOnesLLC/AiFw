import { X } from "lucide-react";

function show(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (Array.isArray(v)) {
    if (v.length === 0) return "none";
    return v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ");
  }
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

const ACRONYMS: Record<string, string> = { ip: "IP", url: "URL", id: "ID" };

function label(key: string): string {
  return key
    .split("_")
    .map((w, i) => ACRONYMS[w] ?? (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/** Readable rendering of an action's JSON result. */
export function ResultView({
  action,
  result,
  onClose,
}: {
  action: string;
  result: unknown;
  onClose: () => void;
}) {
  const rows =
    result && typeof result === "object" && !Array.isArray(result)
      ? Object.entries(result as Record<string, unknown>)
      : [["result", result] as [string, unknown]];
  // Arrays of {feed, result}-style objects read better as a list.
  const listRows = (v: unknown) =>
    Array.isArray(v) && v.every((x) => x && typeof x === "object")
      ? (v as Record<string, unknown>[])
      : null;

  return (
    <div className="relative p-3 rounded-lg border border-[var(--accent)]/30 bg-[var(--accent)]/5">
      <button
        type="button"
        onClick={onClose}
        aria-label="Dismiss result"
        className="absolute top-2 right-2 p-1 text-[var(--text-muted)] hover:text-white"
      >
        <X className="h-4 w-4" />
      </button>
      <div className="text-xs uppercase tracking-wider text-[var(--text-muted)] mb-2">{action}</div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        {rows.map(([k, v]) => {
          const list = listRows(v);
          return (
            <div key={k} className="contents">
              <dt className="text-[var(--text-muted)]">{label(k)}</dt>
              <dd className="text-[var(--text-primary)] break-words">
                {list ? (
                  <ul className="space-y-0.5">
                    {list.map((item, i) => (
                      <li key={i}>{Object.values(item).map(show).join(" — ")}</li>
                    ))}
                  </ul>
                ) : (
                  show(v)
                )}
              </dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
