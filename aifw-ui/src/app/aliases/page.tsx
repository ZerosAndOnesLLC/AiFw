"use client";

import { useState, useEffect, useCallback } from "react";
import { isValidAliasName, isValidIP, isValidCIDR, isValidPortRange, isValidURL } from "@/lib/validate";

interface Alias {
  id: string;
  name: string;
  alias_type: string;
  entries: string[];
  description: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

const defaultForm = {
  name: "",
  alias_type: "host",
  entries: "",
  description: "",
  enabled: true,
};

type FormState = typeof defaultForm;

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

const TYPE_LABELS: Record<string, { label: string; hint: string; placeholder: string; color: string }> = {
  host: { label: "Hosts", hint: "One IP address per line", placeholder: "192.168.1.10\n192.168.1.20\n10.0.0.5", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
  network: { label: "Networks", hint: "One CIDR per line", placeholder: "192.168.1.0/24\n10.0.0.0/8\n172.16.0.0/12", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  port: { label: "Ports", hint: "One port or range per line", placeholder: "80\n443\n8080-8090", color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  url_table: { label: "URL Table", hint: "One URL per line (returns IP list)", placeholder: "https://example.com/blocklist.txt", color: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
};

export default function AliasesPage() {
  const [aliases, setAliases] = useState<Alias[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const fetchAliases = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch("/api/v1/aliases", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setAliases(body.data || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load aliases");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAliases(); }, [fetchAliases]);

  const resetForm = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowForm(false);
  };

  const handleEdit = (alias: Alias) => {
    setForm({
      name: alias.name,
      alias_type: alias.alias_type,
      entries: alias.entries.join("\n"),
      description: alias.description || "",
      enabled: alias.enabled,
    });
    setEditingId(alias.id);
    setShowForm(true);
  };

  const handleSubmit = async () => {
    if (!form.name.trim()) return;

    // Client-side validation
    const errors: string[] = [];
    if (!isValidAliasName(form.name)) errors.push("Name: must be alphanumeric, _, or - (max 31 chars)");
    const entries = form.entries.split("\n").map(s => s.trim()).filter(Boolean);
    for (const entry of entries) {
      if (form.alias_type === "host" && !isValidIP(entry)) { errors.push(`Entry "${entry}": not a valid IP address`); break; }
      if (form.alias_type === "network" && !isValidCIDR(entry)) { errors.push(`Entry "${entry}": not valid CIDR notation`); break; }
      if (form.alias_type === "port" && !isValidPortRange(entry)) { errors.push(`Entry "${entry}": not a valid port or range`); break; }
      if (form.alias_type === "url_table" && !isValidURL(entry)) { errors.push(`Entry "${entry}": not a valid URL`); break; }
    }
    if (errors.length > 0) { setError(errors.join(". ")); return; }

    setSubmitting(true);
    setError(null);
    try {
      const body = {
        name: form.name.trim(),
        alias_type: form.alias_type,
        entries: form.entries.split("\n").map(s => s.trim()).filter(Boolean),
        description: form.description.trim() || undefined,
        enabled: form.enabled,
      };
      const url = editingId ? `/api/v1/aliases/${editingId}` : "/api/v1/aliases";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(body) });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.message || `HTTP ${res.status}`);
      }
      await fetchAliases();
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save alias");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (alias: Alias) => {
    setError(null);
    try {
      const res = await fetch(`/api/v1/aliases/${alias.id}`, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setAliases(prev => prev.filter(a => a.id !== alias.id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete alias");
    }
  };

  const handleToggle = async (alias: Alias) => {
    try {
      const body = {
        name: alias.name,
        alias_type: alias.alias_type,
        entries: alias.entries,
        description: alias.description,
        enabled: !alias.enabled,
      };
      await fetch(`/api/v1/aliases/${alias.id}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify(body) });
      setAliases(prev => prev.map(a => a.id === alias.id ? { ...a, enabled: !a.enabled } : a));
    } catch {
      setError("Failed to toggle alias");
    }
  };

  const typeInfo = TYPE_LABELS[form.alias_type] || TYPE_LABELS.host;

  const inputCls = "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const selectCls = "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
  const labelCls = "block text-xs font-medium text-gray-400 mb-1";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Aliases</h1>
          <p className="text-sm text-gray-400">
            Named groups of hosts, networks, or ports for use in firewall rules &middot; {aliases.length} alias{aliases.length !== 1 ? "es" : ""}
          </p>
        </div>
        {!showForm && (
          <button onClick={() => { setForm(defaultForm); setEditingId(null); setShowForm(true); }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Alias
          </button>
        )}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Form */}
      {showForm && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white">
            {editingId ? "Edit Alias" : "New Alias"}
          </h3>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div>
              <label className={labelCls}>Name</label>
              <input type="text" value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. webservers" className={inputCls} />
              <p className="text-[10px] text-gray-500 mt-0.5">Alphanumeric, _, - (max 31 chars)</p>
            </div>
            <div>
              <label className={labelCls}>Type</label>
              <select value={form.alias_type} onChange={(e) => setForm(f => ({ ...f, alias_type: e.target.value }))} className={selectCls}>
                <option value="host">Hosts (IPs)</option>
                <option value="network">Networks (CIDRs)</option>
                <option value="port">Ports</option>
                <option value="url_table">URL Table</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>Description</label>
              <input type="text" value={form.description} onChange={(e) => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional" className={inputCls} />
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input type="checkbox" checked={form.enabled} onChange={(e) => setForm(f => ({ ...f, enabled: e.target.checked }))}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0" />
                <span className="text-sm text-gray-300">Enabled</span>
              </label>
            </div>
          </div>

          <div>
            <label className={labelCls}>Entries</label>
            <textarea value={form.entries} onChange={(e) => setForm(f => ({ ...f, entries: e.target.value }))}
              placeholder={typeInfo.placeholder}
              rows={5}
              className="w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white font-mono placeholder:text-gray-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors resize-y" />
            <p className="text-[10px] text-gray-500 mt-0.5">{typeInfo.hint}</p>
          </div>

          <div className="flex gap-2">
            <button onClick={handleSubmit} disabled={submitting || !form.name.trim()}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors">
              {submitting ? "Saving..." : editingId ? "Update Alias" : "Create Alias"}
            </button>
            <button onClick={resetForm}
              className="px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      )}

      {loading && <div className="text-center py-12 text-gray-500">Loading aliases...</div>}

      {/* Table */}
      {!loading && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">Name</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Type</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Entries</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">Description</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Status</th>
                  <th className="w-24"></th>
                </tr>
              </thead>
              <tbody>
                {aliases.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-12 text-gray-500">
                      No aliases configured. Use aliases to group IPs, networks, or ports for use in firewall rules.
                    </td>
                  </tr>
                ) : aliases.map((alias) => {
                  const ti = TYPE_LABELS[alias.alias_type] || TYPE_LABELS.host;
                  return (
                    <tr key={alias.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                      <td className="py-2.5 px-4">
                        <span className="font-mono text-sm text-white font-medium">&lt;{alias.name}&gt;</span>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${ti.color}`}>
                          {ti.label}
                        </span>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="text-xs text-gray-400">{alias.entries.length}</span>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="text-xs text-gray-400">{alias.description || "-"}</span>
                      </td>
                      <td className="py-2.5 px-4">
                        <button onClick={() => handleToggle(alias)}
                          className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200"
                          style={{ backgroundColor: alias.enabled ? "#22c55e" : "#4b5563" }}
                          title={alias.enabled ? "Disable" : "Enable"}>
                          <span className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow transition duration-200"
                            style={{ transform: alias.enabled ? "translateX(16px)" : "translateX(0)" }} />
                        </button>
                      </td>
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1">
                          <button onClick={() => handleEdit(alias)}
                            className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700" title="Edit">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                            </svg>
                          </button>
                          <button onClick={() => handleDelete(alias)}
                            className="p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700" title="Delete">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Usage hint */}
      {!loading && aliases.length > 0 && (
        <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-500">
          Use aliases in firewall rules by selecting &quot;Alias&quot; as the source or destination type, then choosing the alias name. In pf rules, aliases appear as <code className="text-gray-400">&lt;alias_name&gt;</code> tables.
        </div>
      )}
    </div>
  );
}
