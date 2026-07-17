"use client";

/* ────────────────────────── Status badge ────────────────────────── */

export function StatusBadge({ status }: { status: string }) {
  const isUp = status === "up" || status === "active" || status === "established";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border text-[10px] px-2 py-0.5 font-medium uppercase tracking-wider ${
        isUp
          ? "bg-green-500/15 text-green-400 border-green-500/30"
          : "bg-red-500/15 text-red-400 border-red-500/30"
      }`}
    >
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${isUp ? "bg-green-400" : "bg-red-400"}`} />
      {status}
    </span>
  );
}
