"use client";

import { CATEGORY_COLORS, getCategoryForType } from "@/lib/api/reverse-proxy/middlewares";

export function TypeBadge({ mtype }: { mtype: string }) {
  const cat = getCategoryForType(mtype);
  const cls = CATEGORY_COLORS[cat] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} font-medium`}>
      {mtype}
    </span>
  );
}
