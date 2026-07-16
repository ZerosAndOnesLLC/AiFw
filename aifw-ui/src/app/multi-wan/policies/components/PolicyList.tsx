"use client";

import { useState } from "react";
import { PolicyRule, PolicyTargetLabel } from "@/lib/api/multiwan-policies";
import { Badge } from "./Badge";
import { IconButton } from "./IconButton";

/// Ordered, drag-to-reorder rule list. Drag state is local UI state; the
/// actual reorder (index math + persist) happens in the page via `onReorder`.
export function PolicyList({
  rules,
  targetLabelFor,
  onToggle,
  onEdit,
  onDuplicate,
  onDelete,
  onReorder,
}: {
  rules: PolicyRule[];
  targetLabelFor: (p: PolicyRule) => PolicyTargetLabel;
  onToggle: (p: PolicyRule) => void;
  onEdit: (p: PolicyRule) => void;
  onDuplicate: (id: string) => void;
  onDelete: (id: string) => void;
  onReorder: (dragId: string, overId: string) => void;
}) {
  const [dragId, setDragId] = useState<string | null>(null);
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  function handleDrop(overId: string) {
    if (!dragId || dragId === overId) return;
    onReorder(dragId, overId);
    setDragId(null);
    setDragOverId(null);
  }

  return (
    <div className="space-y-2">
      {rules.map((p, idx) => {
        const tgt = targetLabelFor(p);
        const isDragging = dragId === p.id;
        const isDragOver = dragOverId === p.id;
        const enabled = p.status === "active";
        return (
          <div
            key={p.id}
            draggable
            onDragStart={() => setDragId(p.id)}
            onDragEnd={() => {
              setDragId(null);
              setDragOverId(null);
            }}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOverId(p.id);
            }}
            onDragLeave={() => setDragOverId((curr) => (curr === p.id ? null : curr))}
            onDrop={() => handleDrop(p.id)}
            className={`
              bg-[var(--bg-card)] border rounded-lg p-3 flex items-center gap-3
              transition-colors cursor-move
              ${isDragging ? "opacity-40" : ""}
              ${isDragOver ? "border-blue-500" : "border-[var(--border)]"}
              ${!enabled ? "opacity-60" : ""}
            `}
          >
            <div className="text-[var(--text-muted)] text-xs font-mono w-8 flex-shrink-0 text-center">
              ⋮⋮
              <div className="mt-1">{idx + 1}</div>
            </div>

            {/* Enable toggle */}
            <button
              onClick={(e) => {
                e.stopPropagation();
                onToggle(p);
              }}
              className={`flex-shrink-0 w-10 h-5 rounded-full transition-colors ${
                enabled ? "bg-green-600" : "bg-gray-600"
              } relative`}
              title={enabled ? "Disable" : "Enable"}
            >
              <div
                className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${
                  enabled ? "left-5" : "left-0.5"
                }`}
              />
            </button>

            {/* Name + description */}
            <div className="flex-shrink-0 min-w-0 w-48">
              <div className="text-white font-medium truncate">{p.name}</div>
              {p.description && (
                <div className="text-xs text-[var(--text-muted)] truncate">
                  {p.description}
                </div>
              )}
            </div>

            {/* Match badges */}
            <div className="flex flex-wrap gap-1 flex-1 min-w-0">
              {p.iface_in && <Badge color="cyan">in:{p.iface_in}</Badge>}
              {p.ip_version !== "both" && <Badge color="gray">{p.ip_version}</Badge>}
              {p.protocol !== "any" && <Badge color="blue">{p.protocol}</Badge>}
              <Badge color="gray">src:{p.src_addr}</Badge>
              <Badge color="gray">dst:{p.dst_addr}</Badge>
              {p.src_port && <Badge color="yellow">sport:{p.src_port}</Badge>}
              {p.dst_port && <Badge color="yellow">dport:{p.dst_port}</Badge>}
            </div>

            {/* Arrow */}
            <div className="text-[var(--text-muted)] flex-shrink-0">→</div>

            {/* Target */}
            <div className="flex-shrink-0 min-w-0 w-48 text-right">
              <div className={`font-medium truncate ${tgt.color}`}>
                {tgt.text}
                {tgt.health && (
                  <span
                    className={`ml-2 inline-block w-2 h-2 rounded-full ${
                      tgt.health === "up"
                        ? "bg-green-400"
                        : tgt.health === "warning"
                          ? "bg-yellow-400"
                          : tgt.health === "down"
                            ? "bg-red-400"
                            : "bg-gray-400"
                    }`}
                    title={`gateway ${tgt.health}`}
                  />
                )}
              </div>
              <div className="text-xs text-[var(--text-muted)]">{p.action_kind}</div>
            </div>

            {/* Actions */}
            <div className="flex gap-1 flex-shrink-0">
              <IconButton onClick={() => onEdit(p)} title="Edit">
                ✎
              </IconButton>
              <IconButton onClick={() => onDuplicate(p.id)} title="Duplicate">
                ⧉
              </IconButton>
              <IconButton
                onClick={() => onDelete(p.id)}
                title="Delete"
                color="red"
              >
                ✕
              </IconButton>
            </div>
          </div>
        );
      })}
    </div>
  );
}
