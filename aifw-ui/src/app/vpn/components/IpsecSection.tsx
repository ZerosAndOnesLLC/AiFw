"use client";

import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { IpsecSa, IpsecFormState } from "@/lib/api/vpn";
import { ChevronIcon } from "./ChevronIcon";
import { StatusBadge } from "./StatusBadge";
import { DeleteButton } from "./DeleteButton";
import { IpsecForm } from "./IpsecForm";

interface IpsecSectionProps {
  ipsecSas: IpsecSa[];
  ipsecLoading: boolean;
  showIpsecForm: boolean;
  ipsecForm: IpsecFormState;
  setIpsecForm: Dispatch<SetStateAction<IpsecFormState>>;
  ipsecSubmitting: boolean;
  onToggleForm: () => void;
  onSubmit: () => void;
  onCancel: () => void;
  onDelete: (id: string) => void;
}

/* ═══════════════ IPsec Section ═══════════════ */

export function IpsecSection({
  ipsecSas,
  ipsecLoading,
  showIpsecForm,
  ipsecForm,
  setIpsecForm,
  ipsecSubmitting,
  onSubmit,
  onCancel,
  onDelete,
}: IpsecSectionProps) {
  const [ipsecOpen, setIpsecOpen] = useState(true);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      {/* Section header */}
      <button
        onClick={() => setIpsecOpen((o) => !o)}
        className="w-full flex items-center justify-between p-4 hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-white">IPsec Security Associations</h2>
          <span className="text-xs text-gray-500">{ipsecSas.length} SA(s)</span>
        </div>
        <ChevronIcon open={ipsecOpen} />
      </button>

      {ipsecOpen && (
        <div className="border-t border-gray-700">
          <div className="px-4 py-3 border-b border-gray-700/50 text-sm text-amber-300">
            Creation is disabled: no IKE or kernel SA/SP backend is implemented. Existing records are retained for migration only.
          </div>

          {/* IPsec form */}
          {showIpsecForm && (
            <IpsecForm
              ipsecForm={ipsecForm}
              setIpsecForm={setIpsecForm}
              ipsecSubmitting={ipsecSubmitting}
              onSubmit={onSubmit}
              onCancel={onCancel}
            />
          )}

          {/* IPsec table */}
          {ipsecLoading ? (
            <div className="text-center py-12 text-gray-500">Loading IPsec SAs...</div>
          ) : ipsecSas.length === 0 ? (
            <div className="text-center py-12 text-gray-500">No IPsec security associations configured</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Name
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Local
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Remote
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                      Protocol
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                      Mode
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      SPI In
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                      SPI Out
                    </th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                      Status
                    </th>
                    <th className="w-12" />
                  </tr>
                </thead>
                <tbody>
                  {ipsecSas.map((sa) => (
                    <tr
                      key={sa.id}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                    >
                      <td className="py-2.5 px-3 font-medium text-white">{sa.name}</td>
                      <td className="py-2.5 px-3 font-mono text-xs text-gray-300">{sa.local_addr}</td>
                      <td className="py-2.5 px-3 font-mono text-xs text-gray-300">{sa.remote_addr}</td>
                      <td className="py-2.5 px-3 text-gray-400 uppercase text-xs">{sa.protocol}</td>
                      <td className="py-2.5 px-3 text-gray-400 text-xs">{sa.mode}</td>
                      <td className="py-2.5 px-3 font-mono text-xs text-gray-400">{sa.spi_in}</td>
                      <td className="py-2.5 px-3 font-mono text-xs text-gray-400">{sa.spi_out}</td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={sa.status} />
                      </td>
                      <td className="py-2.5 px-2">
                        <DeleteButton onClick={() => onDelete(sa.id)} title="Delete SA" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
