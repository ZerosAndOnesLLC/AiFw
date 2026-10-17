"use client";

import { useState } from "react";
import { GeoIpAction, RuleInput } from "@/lib/api/geoip";
import { inputCls, labelCls, saveBtnCls } from "@/app/settings/components/sectionStyles";

export function AddRuleCard({
  busy,
  onAdd,
}: {
  busy: boolean;
  onAdd: (input: RuleInput) => Promise<boolean>;
}) {
  const [country, setCountry] = useState("");
  const [action, setAction] = useState<GeoIpAction>("block");
  const [label, setLabel] = useState("");
  const code = country.trim().toUpperCase();
  const valid = /^[A-Z]{2}$/.test(code);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    if (await onAdd({ country: code, action, label: label.trim() || null })) {
      setCountry("");
      setLabel("");
    }
  };

  return (
    <form onSubmit={submit} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3">
      <div>
        <h3 className="text-sm font-medium">Add a country rule</h3>
        <p className="text-xs text-[var(--text-muted)]">
          Block or allow all inbound traffic from a country. Rules run in the <code>aifw-geoip</code> anchor.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-[6rem_1fr]">
        <div>
          <label htmlFor="geoip-new-country" className={labelCls}>
            Country
          </label>
          <input
            id="geoip-new-country"
            value={country}
            maxLength={2}
            placeholder="FR"
            onChange={(e) => setCountry(e.target.value.toUpperCase().slice(0, 2))}
            className={`${inputCls} font-mono uppercase`}
          />
        </div>
        <div>
          <label htmlFor="geoip-new-action" className={labelCls}>
            Action
          </label>
          <select
            id="geoip-new-action"
            value={action}
            onChange={(e) => setAction(e.target.value as GeoIpAction)}
            className={inputCls}
          >
            <option value="block">Block</option>
            <option value="allow">Allow</option>
          </select>
        </div>
      </div>
      <div>
        <label htmlFor="geoip-new-label" className={labelCls}>
          Label (optional)
        </label>
        <input
          id="geoip-new-label"
          value={label}
          placeholder={valid ? `geoip-${action}-${code}` : "shown in pf logs"}
          onChange={(e) => setLabel(e.target.value)}
          className={inputCls}
        />
      </div>
      <button type="submit" disabled={!valid || busy} className={`${saveBtnCls} w-full`}>
        {busy ? "Adding…" : "Add rule"}
      </button>
      <p className="text-xs text-[var(--text-muted)]">ISO 3166-1 alpha-2 code, e.g. CN, RU, US.</p>
    </form>
  );
}
