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
        method: "POST",
        headers: authHeaders(),
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {plugins.map(p => (
            <div key={p.name} className="bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">{p.name}</h3>
                  <p className="text-[10px] text-gray-500">v{p.version} by {p.author}</p>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${stateColor(p.state)}`}>
                  {p.state}
                </span>
              </div>

              <p className="text-xs text-gray-400">{p.description}</p>

              <div>
                <span className="text-[10px] text-gray-500 uppercase block mb-1">Hooks</span>
                <div className="flex flex-wrap gap-1">
                  {p.hooks.map(h => (
                    <span key={h} className={`text-[10px] px-1.5 py-0.5 rounded border ${hookColor(h)}`}>{h}</span>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-gray-700">
                <button
                  onClick={() => togglePlugin(p.name, p.state !== "running")}
                  className={`px-3 py-1 text-xs rounded ${
                    p.state === "running"
                      ? "bg-red-600 hover:bg-red-700 text-white"
                      : "bg-green-600 hover:bg-green-700 text-white"
                  }`}
                >
                  {p.state === "running" ? "Disable" : "Enable"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-500">
        <p className="font-medium text-gray-400 mb-1">Plugin Hooks</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <div><span className="text-blue-400">pre_rule</span> — Before rule evaluation</div>
          <div><span className="text-blue-400">post_rule</span> — After rule evaluation</div>
          <div><span className="text-cyan-400">connection_new</span> — New connection</div>
          <div><span className="text-cyan-400">connection_closed</span> — Connection closed</div>
          <div><span className="text-amber-400">log_event</span> — Audit log event</div>
          <div><span className="text-purple-400">api_request</span> — API request</div>
        </div>
      </div>
    </div>
  );
}
