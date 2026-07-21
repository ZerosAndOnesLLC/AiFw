"use client";

import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  IpsecSa,
  IpsecTunnel,
  IpsecLiveStatus,
  IpsecFormState,
  AcmeCertOption,
} from "@/lib/api/vpn";
import { fmtBytes } from "@/lib/api/vpn";
import { ChevronIcon } from "./ChevronIcon";
import { DeleteButton } from "./DeleteButton";
import { IpsecForm } from "./IpsecForm";

interface IpsecSectionProps {
  ipsecTunnels: IpsecTunnel[];
  ipsecStatuses: Record<string, IpsecLiveStatus>;
  ipsecSas: IpsecSa[];
  ipsecLoading: boolean;
  showIpsecForm: boolean;
  ipsecForm: IpsecFormState;
  setIpsecForm: Dispatch<SetStateAction<IpsecFormState>>;
  editingIpsecId: string | null;
  ipsecSubmitting: boolean;
  acmeCerts: AcmeCertOption[];
  onToggleForm: () => void;
  onSubmit: () => void;
  onCancel: () => void;
  onEdit: (t: IpsecTunnel) => void;
  onDeleteTunnel: (id: string) => void;
  onStart: (id: string) => void;
  onStop: (id: string) => void;
  onDeleteLegacySa: (id: string) => void;
}

/// Colored badge for the live IKE state reported by charon.
function IkeStateBadge({ state }: { state: string }) {
  const cls =
    state === "ESTABLISHED"
      ? "bg-green-900/60 text-green-400"
      : state === "CONNECTING" || state === "REKEYING"
        ? "bg-yellow-900/60 text-yellow-400"
        : "bg-gray-700 text-gray-400";
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {state.toLowerCase()}
    </span>
  );
}

function fmtUptime(secs: number | null): string {
  if (secs == null) return "";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

/* ═══════════════ IPsec Section ═══════════════ */

export function IpsecSection({
  ipsecTunnels,
  ipsecStatuses,
  ipsecSas,
  ipsecLoading,
  showIpsecForm,
  ipsecForm,
  setIpsecForm,
  editingIpsecId,
  ipsecSubmitting,
  acmeCerts,
  onToggleForm,
  onSubmit,
  onCancel,
  onEdit,
  onDeleteTunnel,
  onStart,
  onStop,
  onDeleteLegacySa,
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
          <h2 className="text-lg font-semibold text-white">IPsec Tunnels</h2>
          <span className="text-xs text-gray-500">
            {ipsecTunnels.length} tunnel(s) · IKEv2 site-to-site
          </span>
        </div>
        <ChevronIcon open={ipsecOpen} />
      </button>

      {ipsecOpen && (
        <div className="border-t border-gray-700">
          {/* Add tunnel button */}
          <div className="px-4 py-3 flex justify-end border-b border-gray-700/50">
            <button
              onClick={onToggleForm}
              className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add IPsec Tunnel
            </button>
          </div>

          {/* Tunnel form */}
          {showIpsecForm && (
            <IpsecForm
              ipsecForm={ipsecForm}
              setIpsecForm={setIpsecForm}
              editingIpsecId={editingIpsecId}
              ipsecSubmitting={ipsecSubmitting}
              acmeCerts={acmeCerts}
              onSubmit={onSubmit}
              onCancel={onCancel}
            />
          )}

          {/* Tunnel table */}
          {ipsecLoading ? (
            <div className="text-center py-12 text-gray-500">Loading IPsec tunnels...</div>
          ) : ipsecTunnels.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              No IPsec tunnels configured
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Remote</th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Traffic Selectors</th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-16">Auth</th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-28">IKE State</th>
                    <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">Live</th>
                    <th className="w-36" />
                  </tr>
                </thead>
                <tbody>
                  {ipsecTunnels.map((t) => {
                    const live = ipsecStatuses[t.id];
                    const child = live?.child_sas[0];
                    const established = live?.ike_state === "ESTABLISHED";
                    return (
                      <tr key={t.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                        <td className="py-2.5 px-3 font-medium text-white">
                          {t.name}
                          {!t.enabled && (
                            <span className="ml-2 text-xs text-gray-500">(disabled)</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-300">{t.remote_addr}</td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-400">
                          {t.local_ts.join(",")} ⇄ {t.remote_ts.join(",")}
                        </td>
                        <td className="py-2.5 px-3 text-gray-400 uppercase text-xs">{t.auth_method}</td>
                        <td className="py-2.5 px-3">
                          <IkeStateBadge state={t.enabled ? (live?.ike_state ?? "DOWN") : "DISABLED"} />
                        </td>
                        <td className="py-2.5 px-3 text-xs text-gray-400">
                          {established && child ? (
                            <>
                              ↓{fmtBytes(child.bytes_in)} ↑{fmtBytes(child.bytes_out)}
                              {live.established_secs != null && (
                                <span className="text-gray-500"> · up {fmtUptime(live.established_secs)}</span>
                              )}
                              {child.rekey_in_secs != null && (
                                <span className="text-gray-500"> · rekey {fmtUptime(child.rekey_in_secs)}</span>
                              )}
                            </>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                        <td className="py-2.5 px-2">
                          <div className="flex items-center justify-end gap-1.5">
                            {t.enabled && (established ? (
                              <button
                                onClick={() => onStop(t.id)}
                                className="px-2 py-1 text-xs rounded bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
                              >
                                Stop
                              </button>
                            ) : (
                              <button
                                onClick={() => onStart(t.id)}
                                className="px-2 py-1 text-xs rounded bg-green-700 hover:bg-green-600 text-white transition-colors"
                              >
                                Start
                              </button>
                            ))}
                            <button
                              onClick={() => onEdit(t)}
                              className="px-2 py-1 text-xs rounded bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
                            >
                              Edit
                            </button>
                            <DeleteButton onClick={() => onDeleteTunnel(t.id)} title="Delete tunnel" />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Legacy SA records — read-only leftovers from before the real
              data plane; they never carried traffic. */}
          {ipsecSas.length > 0 && (
            <div className="border-t border-gray-700">
              <div className="px-4 py-2 text-xs text-gray-500 bg-gray-900/40">
                Legacy IPsec SA records (inactive — these predate real IPsec
                support and never carried traffic; delete them or recreate as
                tunnels above)
              </div>
              <table className="w-full text-sm">
                <tbody>
                  {ipsecSas.map((sa) => (
                    <tr key={sa.id} className="border-b border-gray-700/50">
                      <td className="py-2 px-4 text-gray-400">{sa.name}</td>
                      <td className="py-2 px-3 font-mono text-xs text-gray-500">
                        {sa.local_addr} → {sa.remote_addr}
                      </td>
                      <td className="py-2 px-3 text-xs text-gray-500 uppercase">{sa.protocol}</td>
                      <td className="py-2 px-2 w-12">
                        <DeleteButton onClick={() => onDeleteLegacySa(sa.id)} title="Delete legacy record" />
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
