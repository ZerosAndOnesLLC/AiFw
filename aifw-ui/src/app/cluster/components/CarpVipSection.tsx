"use client";

import { useState } from "react";
import {
  type CarpVip,
  type InterfaceInfo,
  type VipFormState,
  defaultVipForm,
} from "@/lib/api/cluster";
import { ConfirmDialog } from "./ConfirmDialog";
import { FormCard } from "./FormCard";
import { PencilIcon } from "./PencilIcon";
import { SectionHeader } from "./SectionHeader";
import { TrashIcon } from "./TrashIcon";
import { btnDanger, btnEdit, inputCls, labelCls, selectCls } from "./styles";

// ============================================================
// CARP Virtual IPs
// ============================================================

export function CarpVipSection({
  vips,
  ifaces,
  saving,
  onSave,
  onDelete,
}: {
  vips: CarpVip[];
  ifaces: InterfaceInfo[];
  saving: boolean;
  /// `onSaved` is invoked only when the save succeeded (before reload).
  onSave: (
    form: VipFormState,
    editingVipId: string | null,
    onSaved: () => void
  ) => void;
  /// `onDeleted` is invoked only when the delete succeeded (before reload).
  onDelete: (v: CarpVip, onDeleted: () => void) => void;
}) {
  const [showVipForm, setShowVipForm] = useState(false);
  const [vipForm, setVipForm] = useState<VipFormState>(defaultVipForm);
  const [editingVipId, setEditingVipId] = useState<string | null>(null);
  const [deleteVipConfirm, setDeleteVipConfirm] = useState<CarpVip | null>(
    null
  );

  const openAddVip = () => {
    setVipForm(defaultVipForm);
    setEditingVipId(null);
    setShowVipForm(true);
  };

  const openEditVip = (v: CarpVip) => {
    setVipForm({
      vhid: String(v.vhid),
      virtual_ip: v.virtual_ip,
      prefix: String(v.prefix),
      interface: v.interface,
      password: v.password,
    });
    setEditingVipId(v.id);
    setShowVipForm(true);
  };

  return (
    <section>
      {deleteVipConfirm && (
        <ConfirmDialog
          message={`Delete CARP VIP ${deleteVipConfirm.virtual_ip} (VHID ${deleteVipConfirm.vhid})?`}
          onConfirm={() =>
            onDelete(deleteVipConfirm, () => setDeleteVipConfirm(null))
          }
          onCancel={() => setDeleteVipConfirm(null)}
        />
      )}

      <SectionHeader
        title="CARP Virtual IPs"
        onAdd={openAddVip}
        addLabel="Add VIP"
      />

      {showVipForm && (
        <FormCard
          title={editingVipId ? "Edit CARP VIP" : "New CARP VIP"}
          onCancel={() => setShowVipForm(false)}
          onSave={() =>
            onSave(vipForm, editingVipId, () => setShowVipForm(false))
          }
          saving={saving}
        >
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <label className={labelCls}>VHID (1–255)</label>
              <input
                type="number"
                min={1}
                max={255}
                value={vipForm.vhid}
                onChange={(e) =>
                  setVipForm((f) => ({ ...f, vhid: e.target.value }))
                }
                placeholder="1"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Interface</label>
              <select
                value={vipForm.interface}
                onChange={(e) =>
                  setVipForm((f) => ({ ...f, interface: e.target.value }))
                }
                className={selectCls}
              >
                <option value="">-- select --</option>
                {ifaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name}
                    {i.description ? ` (${i.description})` : ""}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Virtual IP</label>
              <input
                type="text"
                value={vipForm.virtual_ip}
                onChange={(e) =>
                  setVipForm((f) => ({ ...f, virtual_ip: e.target.value }))
                }
                placeholder="192.168.1.10"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Prefix length</label>
              <input
                type="number"
                min={1}
                max={128}
                value={vipForm.prefix}
                onChange={(e) =>
                  setVipForm((f) => ({ ...f, prefix: e.target.value }))
                }
                placeholder="24"
                className={inputCls}
              />
            </div>
            <div className="md:col-span-2">
              <label className={labelCls}>
                Password (min 8 chars; avoid shell metacharacters)
              </label>
              <input
                type="password"
                value={vipForm.password}
                onChange={(e) =>
                  setVipForm((f) => ({ ...f, password: e.target.value }))
                }
                placeholder="••••••••"
                className={inputCls}
              />
              {/[|&;`$'"\\!]/.test(vipForm.password) && (
                <p className="text-xs text-yellow-400 mt-0.5">
                  Warning: password contains shell metacharacters. This may
                  cause issues in rc.conf.
                </p>
              )}
            </div>
          </div>
        </FormCard>
      )}

      {vips.length === 0 && !showVipForm ? (
        <div className="text-sm text-[var(--text-muted)]">
          No VIPs configured.
        </div>
      ) : vips.length > 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  VHID
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Interface
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  VIP
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="w-20"></th>
              </tr>
            </thead>
            <tbody>
              {vips.map((v) => (
                <tr
                  key={v.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                >
                  <td className="py-2.5 px-4">{v.vhid}</td>
                  <td className="py-2.5 px-4 font-mono">{v.interface}</td>
                  <td className="py-2.5 px-4 font-mono">
                    {v.virtual_ip}/{v.prefix}
                  </td>
                  <td className="py-2.5 px-4">{v.status}</td>
                  <td className="py-2.5 px-2">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => openEditVip(v)}
                        className={btnEdit}
                        title="Edit"
                      >
                        <PencilIcon />
                      </button>
                      <button
                        onClick={() => setDeleteVipConfirm(v)}
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
