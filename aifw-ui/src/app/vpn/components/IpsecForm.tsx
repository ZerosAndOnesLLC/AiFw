"use client";

import type { Dispatch, SetStateAction } from "react";
import type { IpsecFormState } from "@/lib/api/vpn";
import { inputCls, selectCls, labelCls, btnPrimary, btnCancel } from "./styles";

interface IpsecFormProps {
  ipsecForm: IpsecFormState;
  setIpsecForm: Dispatch<SetStateAction<IpsecFormState>>;
  ipsecSubmitting: boolean;
  onSubmit: () => void;
  onCancel: () => void;
}

/* ────────────────────────── IPsec form ────────────────────────── */

export function IpsecForm({ ipsecForm, setIpsecForm, ipsecSubmitting, onSubmit, onCancel }: IpsecFormProps) {
  return (
    <div className="px-4 py-4 bg-gray-900/50 border-b border-gray-700">
      <h3 className="text-sm font-semibold text-white mb-3">New IPsec SA</h3>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div>
          <label className={labelCls}>Name</label>
          <input
            type="text"
            value={ipsecForm.name}
            onChange={(e) => setIpsecForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. office-vpn"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Local Address</label>
          <input
            type="text"
            value={ipsecForm.local_addr}
            onChange={(e) => setIpsecForm((f) => ({ ...f, local_addr: e.target.value }))}
            placeholder="203.0.113.1"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Remote Address</label>
          <input
            type="text"
            value={ipsecForm.remote_addr}
            onChange={(e) => setIpsecForm((f) => ({ ...f, remote_addr: e.target.value }))}
            placeholder="198.51.100.1"
            className={inputCls}
          />
        </div>
        <div>
          <label className={labelCls}>Protocol</label>
          <select
            value={ipsecForm.protocol}
            onChange={(e) => setIpsecForm((f) => ({ ...f, protocol: e.target.value }))}
            className={selectCls}
          >
            <option value="esp">ESP</option>
            <option value="ah">AH</option>
          </select>
        </div>
        <div>
          <label className={labelCls}>Mode</label>
          <select
            value={ipsecForm.mode}
            onChange={(e) => setIpsecForm((f) => ({ ...f, mode: e.target.value }))}
            className={selectCls}
          >
            <option value="tunnel">Tunnel</option>
            <option value="transport">Transport</option>
          </select>
        </div>
      </div>
      <div className="flex gap-2 mt-3">
        <button
          onClick={onSubmit}
          disabled={
            ipsecSubmitting ||
            !ipsecForm.name.trim() ||
            !ipsecForm.local_addr.trim() ||
            !ipsecForm.remote_addr.trim()
          }
          className={btnPrimary}
        >
          {ipsecSubmitting ? "Creating..." : "Create SA"}
        </button>
        <button
          onClick={onCancel}
          className={btnCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
