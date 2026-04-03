"use client";

import { useState, useEffect, useCallback } from "react";

interface PluginEntry {
  name: string;
  version: string;
  description: string;
  author: string;
  state: string;
  hooks: string[];
}

interface PluginConfig {
  name: string;
  enabled: boolean;
  settings: Record<string, unknown>;
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}
function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

export default function PluginsPage() {
  const [plugins, setPlugins] = useState<PluginEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [running, setRunning] = useState(0);
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState("");
  const [selectedPlugin, setSelectedPlugin] = useState<string | null>(null);
  const [pluginConfig, setPluginConfig] = useState<PluginConfig | null>(null);
  const [configJson, setConfigJson] = useState("");
  const [savingConfig, setSavingConfig] = useState(false);

  const fetchPlugins = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/plugins", { headers: authHeadersPlain() });
      if (res.ok) {
        const data = await res.json();
        setPlugins(data.plugins || []);
        setTotal(data.total || 0);
        setRunning(data.running || 0);
      }
    } catch { /* silent */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchPlugins(); }, [fetchPlugins]);

  const togglePlugin = async (name: string, enabled: boolean) => {
    try {
      const res = await fetch("/api/v1/plugins/toggle", {
        method: "POST", headers: authHeaders(),
        body: JSON.stringify({ name, enabled }),
      });
      if (res.ok) {
        const data = await res.json();
        setActionMsg(data.message || "Done");
        fetchPlugins();
      }
    } catch { setActionMsg("Failed"); }
    setTimeout(() => setActionMsg(""), 3000);
  };

  const openConfig = async (name: string) => {
    setSelectedPlugin(name);
    try {
      const res = await fetch(`/api/v1/plugins/${name}/config`, { headers: authHeadersPlain() });
      if (res.ok) {
        const data = await res.json();
        setPluginConfig(data);
        setConfigJson(JSON.stringify(data.settings || {}, null, 2));
      }
    } catch { /* */ }
  };

  const saveConfig = async () => {
    if (!selectedPlugin) return;
    setSavingConfig(true);
    try {
      const settings = JSON.parse(configJson);
      const res = await fetch(`/api/v1/plugins/${selectedPlugin}/config`, {
        method: "PUT", headers: authHeaders(),
        body: JSON.stringify({ settings }),
      });
      if (res.ok) {
        const data = await res.json();
        setActionMsg(data.message || "Saved");
      }
    } catch (e) {
      setActionMsg("Invalid JSON or save failed");
    }
    setSavingConfig(false);
    setTimeout(() => setActionMsg(""), 3000);
  };

  const stateColor = (s: string) => {
    switch (s) {
      case "running": return "bg-green-500/20 text-green-400 border-green-500/30";
      case "stopped": return "bg-gray-500/20 text-gray-400 border-gray-500/30";
      case "error": return "bg-red-500/20 text-red-400 border-red-500/30";
      default: return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    }
  };

  const hookColor = (h: string) => {
    if (h.includes("rule")) return "text-blue-400 bg-blue-500/10 border-blue-500/20";
    if (h.includes("connection")) return "text-cyan-400 bg-cyan-500/10 border-cyan-500/20";
    if (h.includes("log")) return "text-amber-400 bg-amber-500/10 border-amber-500/20";
    if (h.includes("api")) return "text-purple-400 bg-purple-500/10 border-purple-500/20";
    return "text-gray-400 bg-gray-500/10 border-gray-500/20";
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Plugins</h1>
          <p className="text-sm text-gray-400">
            {total} plugin{total !== 1 ? "s" : ""} registered &middot; {running} running
          </p>
        </div>
      </div>

      {actionMsg && (
        <div className="bg-blue-900/30 border border-blue-700 rounded px-3 py-2 text-xs text-blue-300">{actionMsg}</div>
      )}

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading plugins...</div>
      ) : plugins.length === 0 ? (
        <div className="text-center py-12 text-gray-500">No plugins registered</div>
      ) : (
        <div className="space-y-3">
          {plugins.map(p => (
            <div key={p.name} className="bg-gray-800 border border-gray-700 rounded-lg p-4 cursor-pointer hover:border-gray-600 transition-colors"
              onClick={() => openConfig(p.name)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-2.5 h-2.5 rounded-full ${p.state === "running" ? "bg-green-500" : "bg-gray-600"}`} />
                  <div>
                    <h3 className="text-sm font-semibold text-white">{p.name}</h3>
                    <p className="text-[10px] text-gray-500">v{p.version} &middot; {p.author}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex flex-wrap gap-1">
                    {p.hooks.map(h => (
                      <span key={h} className={`text-[9px] px-1.5 py-0.5 rounded border ${hookColor(h)}`}>{h}</span>
                    ))}
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border ${stateColor(p.state)}`}>
                    {p.state}
                  </span>
                  <div onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => togglePlugin(p.name, p.state !== "running")}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${p.state === "running" ? "bg-green-500" : "bg-gray-600"}`}
                    >
                      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${p.state === "running" ? "translate-x-[18px]" : "translate-x-[3px]"}`} />
                    </button>
                  </div>
                </div>
              </div>
              <p className="text-xs text-gray-400 mt-2">{p.description}</p>
            </div>
          ))}
        </div>
      )}

      {/* Config Editor Modal */}
      {selectedPlugin && pluginConfig && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setSelectedPlugin(null)}>
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-lg w-full mx-4 space-y-4" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">{selectedPlugin} Configuration</h3>
              <button onClick={() => setSelectedPlugin(null)} className="text-gray-400 hover:text-white">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Status</label>
              <span className={`text-xs px-2 py-0.5 rounded-full border ${stateColor(plugins.find(p => p.name === selectedPlugin)?.state || "stopped")}`}>
                {plugins.find(p => p.name === selectedPlugin)?.state || "unknown"}
              </span>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Settings (JSON)</label>
              <textarea
                value={configJson}
                onChange={(e) => setConfigJson(e.target.value)}
                rows={8}
                className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500"
                placeholder="{}"
              />
            </div>

            <div className="flex gap-2 justify-end">
              <button onClick={() => setSelectedPlugin(null)}
                className="px-3 py-1.5 text-xs border border-gray-600 rounded text-gray-400 hover:text-white">
                Cancel
              </button>
              <button onClick={saveConfig} disabled={savingConfig}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50">
                {savingConfig ? "Saving..." : "Save Config"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Hook Reference */}
      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-500">
        <p className="font-medium text-gray-400 mb-2">Available Hooks</p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          <div><span className="text-blue-400">pre_rule</span> — Before rule evaluation, can block/allow</div>
          <div><span className="text-blue-400">post_rule</span> — After rule evaluation, observe result</div>
          <div><span className="text-cyan-400">connection_new</span> — New connection detected</div>
          <div><span className="text-cyan-400">connection_established</span> — Connection established</div>
          <div><span className="text-cyan-400">connection_closed</span> — Connection closed</div>
          <div><span className="text-amber-400">log_event</span> — Audit log event</div>
          <div><span className="text-purple-400">api_request</span> — API request (can block)</div>
        </div>
        <p className="mt-2 text-gray-600">Plugins return actions: Continue, Block, Allow, Log, AddToTable</p>
      </div>
    </div>
  );
}
