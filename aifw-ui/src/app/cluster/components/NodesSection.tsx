"use client";

import { useState } from "react";
import {
  type Node,
  type NodeFormState,
  defaultNodeForm,
} from "@/lib/api/cluster";
import { ConfirmDialog } from "./ConfirmDialog";
import { FormCard } from "./FormCard";
import { PencilIcon } from "./PencilIcon";
import { SectionHeader } from "./SectionHeader";
import { TrashIcon } from "./TrashIcon";
import { btnDanger, btnEdit, inputCls, labelCls, selectCls } from "./styles";

// ============================================================
// Cluster Nodes
// ============================================================

export function NodesSection({
  nodes,
  saving,
  onSave,
  onDelete,
  onGeneratePeerKey,
  onRepin,
}: {
  nodes: Node[];
  saving: boolean;
  /// `onSaved` is invoked only when the save succeeded (before reload).
  onSave: (
    form: NodeFormState,
    editingNodeId: string | null,
    onSaved: () => void
  ) => void;
  /// `onDeleted` is invoked only when the delete succeeded (before reload).
  onDelete: (n: Node, onDeleted: () => void) => void;
  onGeneratePeerKey: (nodeId: string, nodeName: string) => void;
  /// #317: clear the peer's pinned TLS fingerprint so it is re-learned on next contact.
  onRepin: (nodeId: string) => void;
}) {
  const [showNodeForm, setShowNodeForm] = useState(false);
  const [nodeForm, setNodeForm] = useState<NodeFormState>(defaultNodeForm);
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null);
  const [deleteNodeConfirm, setDeleteNodeConfirm] = useState<Node | null>(null);

  const openAddNode = () => {
    setNodeForm(defaultNodeForm);
    setEditingNodeId(null);
    setShowNodeForm(true);
  };

  const openEditNode = (n: Node) => {
    setNodeForm({ name: n.name, address: n.address, role: n.role, api_port: String(n.api_port ?? 8080) });
    setEditingNodeId(n.id);
    setShowNodeForm(true);
  };

  return (
    <section>
      {deleteNodeConfirm && (
        <ConfirmDialog
          message={`Delete node "${deleteNodeConfirm.name}" (${deleteNodeConfirm.address})?`}
          onConfirm={() =>
            onDelete(deleteNodeConfirm, () => setDeleteNodeConfirm(null))
          }
          onCancel={() => setDeleteNodeConfirm(null)}
        />
      )}

      <SectionHeader
        title="Cluster Nodes"
        onAdd={openAddNode}
        addLabel="Add Node"
      />

      {showNodeForm && (
        <FormCard
          title={editingNodeId ? "Edit Cluster Node" : "New Cluster Node"}
          onCancel={() => setShowNodeForm(false)}
          onSave={() =>
            onSave(nodeForm, editingNodeId, () => setShowNodeForm(false))
          }
          saving={saving}
        >
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <label className={labelCls}>Name</label>
              <input
                type="text"
                value={nodeForm.name}
                onChange={(e) =>
                  setNodeForm((f) => ({ ...f, name: e.target.value }))
                }
                placeholder="firewall-b"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Address (IP)</label>
              <input
                type="text"
                value={nodeForm.address}
                onChange={(e) =>
                  setNodeForm((f) => ({ ...f, address: e.target.value }))
                }
                placeholder="10.0.0.2"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Role</label>
              <select
                value={nodeForm.role}
                onChange={(e) =>
                  setNodeForm((f) => ({ ...f, role: e.target.value }))
                }
                className={selectCls}
              >
                <option value="primary">Primary</option>
                <option value="secondary">Secondary</option>
                <option value="standalone">Standalone</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>API port</label>
              <input
                type="number"
                min={1}
                max={65535}
                value={nodeForm.api_port}
                onChange={(e) =>
                  setNodeForm((f) => ({ ...f, api_port: e.target.value }))
                }
                className={inputCls}
              />
              <p className="mt-1 text-[11px] text-[var(--text-muted)]">Port the peer&apos;s API listens on (default 8080).</p>
            </div>
          </div>
        </FormCard>
      )}

      {nodes.length === 0 && !showNodeForm ? (
        <div className="text-sm text-[var(--text-muted)]">
          No peer nodes registered.
        </div>
      ) : nodes.length > 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Name
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Address
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Role
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Health
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Last seen
                </th>
                <th
                  className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider"
                  title="SHA-256 of the peer's API certificate that our HTTPS calls are pinned to. Learned on first contact; reset it if the peer's certificate changed by hand."
                >
                  TLS pin
                </th>
                <th className="w-40"></th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr
                  key={n.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                >
                  <td className="py-2.5 px-4">{n.name}</td>
                  <td className="py-2.5 px-4 font-mono">{n.address}{n.api_port && n.api_port !== 8080 ? `:${n.api_port}` : ""}</td>
                  <td className="py-2.5 px-4">{n.role}</td>
                  <td className="py-2.5 px-4">{n.health}</td>
                  <td className="py-2.5 px-4">
                    {new Date(n.last_seen).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-4">
                    {n.cert_fingerprint ? (
                      <span
                        className="font-mono text-xs text-[var(--text-muted)]"
                        title={n.cert_fingerprint}
                      >
                        {n.cert_fingerprint.slice(0, 16)}…
                        <button
                          onClick={() => onRepin(n.id)}
                          className="ml-2 text-[var(--accent)] hover:underline"
                          title="Forget this pin; the next contact re-learns the peer's current certificate"
                        >
                          Re-pin
                        </button>
                      </span>
                    ) : (
                      <span className="text-xs text-[var(--text-muted)]" title="Not pinned yet — pinned automatically on the first successful contact">
                        learn on first contact
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-2">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => onGeneratePeerKey(n.id, n.name)}
                        className="px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-xs text-white whitespace-nowrap"
                      >
                        Peer Key
                      </button>
                      <button
                        onClick={() => openEditNode(n)}
                        className={btnEdit}
                        title="Edit"
                      >
                        <PencilIcon />
                      </button>
                      <button
                        onClick={() => setDeleteNodeConfirm(n)}
                        className={btnDanger}
                        title="Delete"
                      >
                        <TrashIcon />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
