"use client";

import { useState } from "react";
import type { Feedback } from "@/hooks/useFeedback";
import type { ApiKeyInfo, CreateApiKeyRequest, CreatedApiKey, RoleOption } from "@/lib/api/apiKeys";

interface Props {
  keys: ApiKeyInfo[];
  roles: RoleOption[];
  loading: boolean;
  creating: boolean;
  revoking: string | null;
  created: CreatedApiKey | null;
  feedback: Feedback | null;
  onCreate: (req: CreateApiKeyRequest) => Promise<boolean>;
  onRevoke: (key: ApiKeyInfo) => void;
  onDismissCreated: () => void;
}

const inputClass =
  "w-full px-3 py-2 text-sm bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:border-blue-500";

const labelClass = "text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1";

const EXPIRY_CHOICES: { label: string; days?: number }[] = [
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year", days: 365 },
  { label: "Never" },
];

function fmt(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

/** Profile → API Keys: mint, list and revoke your own keys for the `aifw` CLI and scripts. */
export default function ApiKeysCard({
  keys,
  roles,
  loading,
  creating,
  revoking,
  created,
  feedback,
  onCreate,
  onRevoke,
  onDismissCreated,
}: Props) {
  const [name, setName] = useState("");
  const [roleId, setRoleId] = useState("");
  const [expiry, setExpiry] = useState("90 days");
  const [copied, setCopied] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const choice = EXPIRY_CHOICES.find((c) => c.label === expiry);
    const ok = await onCreate({
      name: name.trim(),
      role_id: roleId || undefined,
      expires_in_days: choice?.days,
    });
    if (ok) {
      setName("");
      setCopied(false);
    }
  };

  const copy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
      <div>
        <h2 className="text-lg font-semibold">API Keys</h2>
        <p className="text-sm text-[var(--text-muted)]">
          Keys for the <code>aifw</code> CLI and scripts. A key acts as you, optionally narrowed to a role.
        </p>
      </div>

      {feedback && !(created && feedback.type === "success") && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {created && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 space-y-2">
          <p className="text-sm text-yellow-300 font-medium">
            Copy this key now. It won&apos;t be shown again.
          </p>
          <code className="block break-all text-xs bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white">
            {created.key}
          </code>
          <p className="text-xs text-[var(--text-muted)]">
            Use it with <code>aifw login --api-key-stdin</code> or <code>AIFW_TOKEN</code>.
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={copy}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-md"
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              onClick={onDismissCreated}
              className="px-3 py-1.5 text-[var(--text-muted)] hover:text-white text-xs"
            >
              Done
            </button>
          </div>
        </div>
      )}

      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="sm:col-span-2">
            <label htmlFor="api-key-name" className={labelClass}>Name</label>
            <input
              id="api-key-name"
              className={inputClass}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="laptop-cli"
              maxLength={128}
              required
            />
          </div>
          <div>
            <label htmlFor="api-key-role" className={labelClass}>Permissions</label>
            <select id="api-key-role" className={inputClass} value={roleId} onChange={(e) => setRoleId(e.target.value)}>
              <option value="">Same as my account</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="api-key-expiry" className={labelClass}>Expires</label>
            <select id="api-key-expiry" className={inputClass} value={expiry} onChange={(e) => setExpiry(e.target.value)}>
              {EXPIRY_CHOICES.map((c) => (
                <option key={c.label} value={c.label}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <button
          type="submit"
          disabled={creating || !name.trim()}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
        >
          {creating ? "Creating..." : "Create API Key"}
        </button>
      </form>

      {loading ? (
        <p className="text-sm text-[var(--text-muted)]">Loading…</p>
      ) : keys.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)]">No API keys yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-[var(--text-muted)] border-b border-[var(--border)]">
              <tr>
                <th className="py-2 pr-3">Name</th>
                <th className="py-2 pr-3">Prefix</th>
                <th className="py-2 pr-3">Role</th>
                <th className="py-2 pr-3">Expires</th>
                <th className="py-2 pr-3">Last used</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} className="border-b border-[var(--border)] last:border-0">
                  <td className="py-2 pr-3">{k.name}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{k.prefix}…</td>
                  <td className="py-2 pr-3">{k.role_name ?? "account"}</td>
                  <td className={`py-2 pr-3 ${k.expired ? "text-red-400" : ""}`}>
                    {k.expired ? "Expired" : fmt(k.expires_at)}
                  </td>
                  <td className="py-2 pr-3">{fmt(k.last_used_at)}</td>
                  <td className="py-2 text-right whitespace-nowrap">
                    {confirming === k.id ? (
                      <span className="space-x-2">
                        <button
                          type="button"
                          disabled={revoking === k.id}
                          onClick={() => {
                            setConfirming(null);
                            onRevoke(k);
                          }}
                          className="text-red-400 hover:text-red-300 text-xs disabled:opacity-50"
                        >
                          Confirm revoke
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirming(null)}
                          className="text-[var(--text-muted)] hover:text-white text-xs"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => setConfirming(k.id)}
                        className="text-red-400 hover:text-red-300 text-xs"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
