"use client";

import { useState } from "react";
import {
  type InterfaceInfo,
  type Pfsync,
  type PfsyncFormState,
  defaultPfsyncForm,
} from "@/lib/api/cluster";
import { ConfirmDialog } from "./ConfirmDialog";
import { FormCard } from "./FormCard";
import { SectionHeader } from "./SectionHeader";
import { inputCls, labelCls, selectCls } from "./styles";

// ============================================================
// pfsync configuration (singleton)
// ============================================================

export function PfsyncSection({
  pfsync,
  ifaces,
  saving,
  busy,
  onSave,
  onForceSync,
}: {
  pfsync: Pfsync | null;
  ifaces: InterfaceInfo[];
  saving: boolean;
  busy: boolean;
  /// `onSaved` is invoked only when the save succeeded (before reload).
  onSave: (form: PfsyncFormState, onSaved: () => void) => void;
  onForceSync: () => void;
}) {
  const [showPfsyncForm, setShowPfsyncForm] = useState(false);
  const [pfsyncForm, setPfsyncForm] =
    useState<PfsyncFormState>(defaultPfsyncForm);
  const [dhcpLinkConfirm, setDhcpLinkConfirm] = useState(false);
  const [pendingPfsyncSave, setPendingPfsyncSave] = useState(false);

  const openEditPfsync = () => {
    if (pfsync) {
      setPfsyncForm({
        sync_interface: pfsync.sync_interface,
        sync_peer: pfsync.sync_peer ?? "",
        defer: pfsync.defer,
        enabled: pfsync.enabled,
        latency_profile: pfsync.latency_profile,
        heartbeat_iface: pfsync.heartbeat_iface ?? "",
        heartbeat_interval_ms: pfsync.heartbeat_interval_ms
          ? String(pfsync.heartbeat_interval_ms)
          : "",
        dhcp_link: pfsync.dhcp_link,
      });
    } else {
      setPfsyncForm(defaultPfsyncForm);
    }
    setShowPfsyncForm(true);
  };

  const doSavePfsync = () => {
    onSave(pfsyncForm, () => {
      setShowPfsyncForm(false);
      setPendingPfsyncSave(false);
    });
  };

  const savePfsync = () => {
    // If dhcp_link is being turned on (was off before), show confirmation
    const wasDhcpLink = pfsync?.dhcp_link ?? false;
    if (pfsyncForm.dhcp_link && !wasDhcpLink) {
      setDhcpLinkConfirm(true);
      setPendingPfsyncSave(true);
      return;
    }
    doSavePfsync();
  };

  return (
    <section>
      {dhcpLinkConfirm && (
        <ConfirmDialog
          message="This will replace any manually-configured rDHCP HA peer list with the cluster-derived list. The peer list editor on the DHCP HA page will be locked. Continue?"
          onConfirm={() => {
            setDhcpLinkConfirm(false);
            if (pendingPfsyncSave) doSavePfsync();
          }}
          onCancel={() => {
            setDhcpLinkConfirm(false);
            setPendingPfsyncSave(false);
            setPfsyncForm((f) => ({ ...f, dhcp_link: false }));
          }}
        />
      )}

      <SectionHeader
        title="pfsync Configuration"
        onAdd={openEditPfsync}
        addLabel={pfsync ? "Edit" : "Configure"}
      />

      {showPfsyncForm && (
        <FormCard
          title="pfsync Settings"
          onCancel={() => setShowPfsyncForm(false)}
          onSave={savePfsync}
          saving={saving}
        >
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <label className={labelCls}>Sync Interface</label>
              <select
                value={pfsyncForm.sync_interface}
                onChange={(e) =>
                  setPfsyncForm((f) => ({
                    ...f,
                    sync_interface: e.target.value,
                  }))
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
              <label className={labelCls}>
                Sync Peer IP (blank = multicast)
              </label>
              <input
                type="text"
                value={pfsyncForm.sync_peer}
                onChange={(e) =>
                  setPfsyncForm((f) => ({ ...f, sync_peer: e.target.value }))
                }
                placeholder="e.g. 10.0.0.2"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>
                Heartbeat Interface (future use)
              </label>
              <select
                value={pfsyncForm.heartbeat_iface}
                onChange={(e) =>
                  setPfsyncForm((f) => ({
                    ...f,
                    heartbeat_iface: e.target.value,
                  }))
                }
                className={selectCls}
              >
                <option value="">-- none --</option>
                {ifaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>
                Heartbeat Interval ms (future use)
              </label>
              <input
                type="number"
                value={pfsyncForm.heartbeat_interval_ms}
                onChange={(e) =>
                  setPfsyncForm((f) => ({
                    ...f,
                    heartbeat_interval_ms: e.target.value,
                  }))
                }
                placeholder="1000"
                className={inputCls}
              />
            </div>
          </div>

          {/* Latency profile radio */}
          <div>
            <label className={labelCls}>Latency Profile</label>
            <div className="space-y-2">
              {(
                [
                  {
                    value: "conservative",
                    label: "Conservative",
                    desc: "Higher advskew — only promotes after several missed heartbeats. Best for unstable links.",
                  },
                  {
                    value: "tight",
                    label: "Tight",
                    desc: "Balanced — promotes after 2–3 missed heartbeats. Recommended for most deployments.",
                  },
                  {
                    value: "aggressive",
                    label: "Aggressive",
                    desc: "Low advskew — promotes quickly. Use only on very reliable dedicated sync links.",
                  },
                ] as const
              ).map(({ value, label, desc }) => (
                <label
                  key={value}
                  className="flex items-start gap-2 cursor-pointer"
                >
                  <input
                    type="radio"
                    name="latency_profile"
                    value={value}
                    checked={pfsyncForm.latency_profile === value}
                    onChange={() =>
                      setPfsyncForm((f) => ({
                        ...f,
                        latency_profile: value,
                      }))
                    }
                    className="mt-0.5"
                  />
                  <span className="text-sm">
                    <span className="font-medium text-white">{label}</span>
                    <span className="text-gray-400"> — {desc}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Bool toggles */}
          <div className="flex flex-wrap gap-6">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={pfsyncForm.defer}
                onChange={(e) =>
                  setPfsyncForm((f) => ({ ...f, defer: e.target.checked }))
                }
                className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
              />
              <span className="text-sm text-gray-300">Defer</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={pfsyncForm.enabled}
                onChange={(e) =>
                  setPfsyncForm((f) => ({
                    ...f,
                    enabled: e.target.checked,
                  }))
                }
                className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
              />
              <span className="text-sm text-gray-300">Enabled</span>
            </label>
            <div>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={pfsyncForm.dhcp_link}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({
                      ...f,
                      dhcp_link: e.target.checked,
                    }))
                  }
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">DHCP Link</span>
              </label>
              <p className="text-xs text-gray-500 mt-0.5 ml-6">
                Auto-derives the rDHCP HA peer list from the cluster nodes —
                when enabled, you don&apos;t have to enter peer addresses again
                on the DHCP HA page.
              </p>
            </div>
          </div>
        </FormCard>
      )}

      {pfsync && !showPfsyncForm ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-sm space-y-1">
          <div>
            Sync interface:{" "}
            <span className="font-mono">{pfsync.sync_interface}</span>
          </div>
          <div>
            Peer:{" "}
            <span className="font-mono">
              {pfsync.sync_peer ?? "multicast"}
            </span>
          </div>
          <div>Latency profile: {pfsync.latency_profile}</div>
          <div>DHCP link: {pfsync.dhcp_link ? "yes" : "no"}</div>
          <div>Enabled: {pfsync.enabled ? "yes" : "no"}</div>
          <div className="pt-1">
            <button
              onClick={onForceSync}
              disabled={busy}
              className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-sm"
            >
              Force sync from peer
            </button>
          </div>
        </div>
      ) : !pfsync && !showPfsyncForm ? (
        <div className="text-sm text-[var(--text-muted)]">Not configured.</div>
      ) : null}
    </section>
  );
}
