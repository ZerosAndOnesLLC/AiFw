"use client";

import { useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { IpsecFormState, AcmeCertOption } from "@/lib/api/vpn";
import { inputCls, selectCls, labelCls, btnPrimary, btnCancel } from "./styles";

interface IpsecFormProps {
  ipsecForm: IpsecFormState;
  setIpsecForm: Dispatch<SetStateAction<IpsecFormState>>;
  editingIpsecId: string | null;
  ipsecSubmitting: boolean;
  acmeCerts: AcmeCertOption[];
  onSubmit: () => void;
  onCancel: () => void;
}

const textareaCls =
  "w-full px-2.5 py-1.5 bg-gray-800 border border-gray-600 rounded-md text-xs font-mono text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 min-h-20";

/* ────────────────────────── IPsec tunnel form ────────────────────────── */

export function IpsecForm({
  ipsecForm,
  setIpsecForm,
  editingIpsecId,
  ipsecSubmitting,
  acmeCerts,
  onSubmit,
  onCancel,
}: IpsecFormProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const set = (patch: Partial<IpsecFormState>) => setIpsecForm((f) => ({ ...f, ...patch }));

  const tsOk = (s: string) => s.split(",").some((p) => p.trim().length > 0);
  const secretOk =
    ipsecForm.auth_method === "psk"
      ? !!editingIpsecId || ipsecForm.psk.trim().length >= 16
      : ipsecForm.cert_source === "acme"
        ? !!ipsecForm.acme_cert_id
        : !!editingIpsecId || (!!ipsecForm.local_cert_pem.trim() && !!ipsecForm.local_key_pem.trim());
  const canSubmit =
    !ipsecSubmitting &&
    ipsecForm.name.trim() &&
    ipsecForm.remote_addr.trim() &&
    tsOk(ipsecForm.local_ts) &&
    tsOk(ipsecForm.remote_ts) &&
    secretOk;

  return (
    <div className="px-4 py-4 bg-gray-900/50 border-b border-gray-700 space-y-4">
      <h3 className="text-sm font-semibold text-white">
        {editingIpsecId ? "Edit IPsec Tunnel" : "New IPsec Tunnel"}
        <span className="ml-2 text-xs font-normal text-gray-500">
          IKEv2 site-to-site (tunnel mode)
        </span>
      </h3>

      {/* Endpoints */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <label className={labelCls}>Name</label>
          <input
            type="text"
            value={ipsecForm.name}
            onChange={(e) => set({ name: e.target.value })}
            placeholder="e.g. branch-office"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Remote Endpoint</label>
          <input
            type="text"
            value={ipsecForm.remote_addr}
            onChange={(e) => set({ remote_addr: e.target.value })}
            placeholder="198.51.100.1 or vpn.example.com"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Local Subnets</label>
          <input
            type="text"
            value={ipsecForm.local_ts}
            onChange={(e) => set({ local_ts: e.target.value })}
            placeholder="10.0.0.0/24, 10.5.0.0/24"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Remote Subnets</label>
          <input
            type="text"
            value={ipsecForm.remote_ts}
            onChange={(e) => set({ remote_ts: e.target.value })}
            placeholder="10.1.0.0/24"
            className={inputCls}
          />
        </div>
      </div>

      {/* Authentication */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <label className={labelCls}>Authentication</label>
          <select
            value={ipsecForm.auth_method}
            onChange={(e) => set({ auth_method: e.target.value as "psk" | "cert" })}
            className={selectCls}
          >
            <option value="psk">Pre-shared key</option>
            <option value="cert">Certificate (X.509)</option>
          </select>
        </div>

        {ipsecForm.auth_method === "psk" ? (
          <div className="col-span-2">
            <label className={labelCls}>Pre-shared Key</label>
            <input
              type="password"
              value={ipsecForm.psk}
              onChange={(e) => set({ psk: e.target.value })}
              placeholder={editingIpsecId ? "(unchanged)" : "at least 16 characters"}
              className={inputCls}
            />
          </div>
        ) : (
          <>
            <div>
              <label className={labelCls}>Certificate Source</label>
              <select
                value={ipsecForm.cert_source}
                onChange={(e) => set({ cert_source: e.target.value as "acme" | "manual" })}
                className={selectCls}
              >
                <option value="manual">Paste PEM</option>
                <option value="acme">ACME store</option>
              </select>
            </div>
            {ipsecForm.cert_source === "acme" && (
              <div>
                <label className={labelCls}>ACME Certificate</label>
                <select
                  value={ipsecForm.acme_cert_id}
                  onChange={(e) => set({ acme_cert_id: e.target.value })}
                  className={selectCls}
                >
                  <option value="">Select…</option>
                  {acmeCerts.map((c) => (
                    <option key={c.id} value={String(c.id)}>
                      {c.common_name} ({c.status})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </>
        )}
      </div>

      {/* Manual PEM material */}
      {ipsecForm.auth_method === "cert" && ipsecForm.cert_source === "manual" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Local Certificate (PEM)</label>
            <textarea
              value={ipsecForm.local_cert_pem}
              onChange={(e) => set({ local_cert_pem: e.target.value })}
              placeholder="-----BEGIN CERTIFICATE-----"
              className={textareaCls}
            />
          </div>
          <div>
            <label className={labelCls}>Private Key (PEM)</label>
            <textarea
              value={ipsecForm.local_key_pem}
              onChange={(e) => set({ local_key_pem: e.target.value })}
              placeholder={editingIpsecId ? "(unchanged)" : "-----BEGIN PRIVATE KEY-----"}
              className={textareaCls}
            />
          </div>
        </div>
      )}
      {ipsecForm.auth_method === "cert" && (
        <div>
          <label className={labelCls}>Peer CA Certificate (PEM, optional)</label>
          <textarea
            value={ipsecForm.ca_cert_pem}
            onChange={(e) => set({ ca_cert_pem: e.target.value })}
            placeholder="-----BEGIN CERTIFICATE-----  (CA that signed the peer's certificate)"
            className={textareaCls}
          />
        </div>
      )}

      {/* Advanced */}
      <button
        type="button"
        onClick={() => setShowAdvanced((o) => !o)}
        className="text-xs text-blue-400 hover:text-blue-300"
      >
        {showAdvanced ? "▾ Hide advanced options" : "▸ Advanced options"}
      </button>
      {showAdvanced && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div>
            <label className={labelCls}>Local Endpoint (optional)</label>
            <input
              type="text"
              value={ipsecForm.local_addr}
              onChange={(e) => set({ local_addr: e.target.value })}
              placeholder="any local address"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Local IKE ID (optional)</label>
            <input
              type="text"
              value={ipsecForm.local_id}
              onChange={(e) => set({ local_id: e.target.value })}
              placeholder="defaults to endpoint"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Remote IKE ID (optional)</label>
            <input
              type="text"
              value={ipsecForm.remote_id}
              onChange={(e) => set({ remote_id: e.target.value })}
              placeholder="defaults to endpoint"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Start Action</label>
            <select
              value={ipsecForm.start_action}
              onChange={(e) => set({ start_action: e.target.value as "start" | "trap" | "none" })}
              className={selectCls}
            >
              <option value="start">Start immediately</option>
              <option value="trap">On demand (trap)</option>
              <option value="none">Manual only</option>
            </select>
          </div>
          <div>
            <label className={labelCls}>IKE Proposal</label>
            <input
              type="text"
              value={ipsecForm.ike_proposal}
              onChange={(e) => set({ ike_proposal: e.target.value })}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>ESP Proposal</label>
            <input
              type="text"
              value={ipsecForm.esp_proposal}
              onChange={(e) => set({ esp_proposal: e.target.value })}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>IKE Rekey (secs)</label>
            <input
              type="number"
              value={ipsecForm.ike_lifetime_secs}
              onChange={(e) => set({ ike_lifetime_secs: e.target.value })}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>ESP Rekey (secs)</label>
            <input
              type="number"
              value={ipsecForm.esp_lifetime_secs}
              onChange={(e) => set({ esp_lifetime_secs: e.target.value })}
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>DPD Interval (secs, 0 = off)</label>
            <input
              type="number"
              value={ipsecForm.dpd_delay_secs}
              onChange={(e) => set({ dpd_delay_secs: e.target.value })}
              className={inputCls}
            />
          </div>
          <div className="flex items-end pb-1.5">
            <label className="flex items-center gap-2 text-xs text-gray-300">
              <input
                type="checkbox"
                checked={ipsecForm.enabled}
                onChange={(e) => set({ enabled: e.target.checked })}
                className="rounded border-gray-600 bg-gray-800"
              />
              Enabled
            </label>
          </div>
        </div>
      )}

      <div className="flex gap-2">
        <button onClick={onSubmit} disabled={!canSubmit} className={btnPrimary}>
          {ipsecSubmitting
            ? "Saving..."
            : editingIpsecId
              ? "Save Tunnel"
              : "Create Tunnel"}
        </button>
        <button onClick={onCancel} className={btnCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}
