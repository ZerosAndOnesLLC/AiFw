"use client";

import { useState, useEffect, useCallback } from "react";

interface TimeConfig {
  enabled: boolean;
  log_level: string;
  clock_discipline: boolean;
  clock_step_threshold_ms: number;
  clock_panic_threshold_ms: number;
  ntp_enabled: boolean;
  ntp_listen: string;
  ntp_interfaces: string[];
  ntp_rate_limit: number;
  ntp_rate_burst: number;
  nts_enabled: boolean;
  nts_ke_listen: string;
  nts_certificate: string;
  nts_private_key: string;
  ptp_enabled: boolean;
  ptp_domain: number;
  ptp_interface: string;
  ptp_transport: string;
  ptp_priority1: number;
  ptp_priority2: number;
  ptp_delay_mechanism: string;
  metrics_enabled: boolean;
  metrics_listen: string;
  management_enabled: boolean;
  management_listen: string;
}

interface NtpSource {
  id: string;
  address: string;
  nts: boolean;
  min_poll: number;
  max_poll: number;
  enabled: boolean;
}

interface TimeStatus {
  running: boolean;
  version: string;
  sources_count: number;
}

interface NetInterface { name: string; }

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}
function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

const defaultConfig: TimeConfig = {
  enabled: false, log_level: "info",
  clock_discipline: true, clock_step_threshold_ms: 128, clock_panic_threshold_ms: 1000,
  ntp_enabled: true, ntp_listen: "0.0.0.0:123", ntp_interfaces: [], ntp_rate_limit: 16, ntp_rate_burst: 32,
  nts_enabled: false, nts_ke_listen: "0.0.0.0:4460", nts_certificate: "", nts_private_key: "",
  ptp_enabled: false, ptp_domain: 0, ptp_interface: "em0", ptp_transport: "udp-ipv4", ptp_priority1: 128, ptp_priority2: 128, ptp_delay_mechanism: "e2e",
  metrics_enabled: true, metrics_listen: "127.0.0.1:9100",
  management_enabled: true, management_listen: "127.0.0.1:9200",
};

// Validation
function validateListenAddr(v: string): string | null {
  if (!/^[\d.]+:\d+$/.test(v)) return "Format: IP:port (e.g. 0.0.0.0:123)";
  const port = parseInt(v.split(":")[1]);
  if (port < 1 || port > 65535) return "Port must be 1-65535";
  return null;
}
function validatePollRange(min: number, max: number): string | null {
  if (min < 1 || min > 17) return "Min poll must be 1-17";
  if (max < 1 || max > 17) return "Max poll must be 1-17";
  if (min > max) return "Min poll must be <= max poll";
  return null;
}

export default function TimeServicePage() {
  const [status, setStatus] = useState<TimeStatus | null>(null);
  const [config, setConfig] = useState<TimeConfig>(defaultConfig);
  const [sources, setSources] = useState<NtpSource[]>([]);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);
  const [actionMsg, setActionMsg] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  // New source form
  const [newAddr, setNewAddr] = useState("");
  const [newNts, setNewNts] = useState(false);
  const [newMinPoll, setNewMinPoll] = useState(4);
  const [newMaxPoll, setNewMaxPoll] = useState(10);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/time/status", { headers: authHeadersPlain() });
      if (res.ok) setStatus(await res.json());
    } catch { /* */ }
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/time/config", { headers: authHeadersPlain() });
      if (res.ok) setConfig(await res.json());
    } catch { /* */ }
  }, []);

  const fetchSources = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/time/sources", { headers: authHeadersPlain() });
      if (res.ok) { const body = await res.json(); setSources(body.data || []); }
    } catch { /* */ }
  }, []);

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/interfaces", { headers: authHeadersPlain() });
      if (res.ok) {
        const body = await res.json();
        setInterfaces((body.data || []).map((i: NetInterface) => i.name).filter((n: string) => !n.startsWith("lo") && !n.startsWith("pflog")));
      }
    } catch { /* */ }
  }, []);

  useEffect(() => { fetchStatus(); fetchConfig(); fetchSources(); fetchInterfaces(); }, [fetchStatus, fetchConfig, fetchSources, fetchInterfaces]);
  useEffect(() => { const t = setInterval(fetchStatus, 5000); return () => clearInterval(t); }, [fetchStatus]);

  const validate = (): boolean => {
    const e: Record<string, string> = {};
    const la = validateListenAddr(config.ntp_listen);
    if (la) e.ntp_listen = la;
    if (config.nts_enabled) {
      const nla = validateListenAddr(config.nts_ke_listen);
      if (nla) e.nts_ke_listen = nla;
      if (!config.nts_certificate) e.nts_certificate = "Certificate path required when NTS enabled";
      if (!config.nts_private_key) e.nts_private_key = "Private key path required when NTS enabled";
    }
    if (config.metrics_enabled) { const ml = validateListenAddr(config.metrics_listen); if (ml) e.metrics_listen = ml; }
    if (config.management_enabled) { const ml = validateListenAddr(config.management_listen); if (ml) e.management_listen = ml; }
    if (config.clock_step_threshold_ms <= 0) e.clock_step = "Must be > 0";
    if (config.clock_panic_threshold_ms <= 0) e.clock_panic = "Must be > 0";
    if (config.ntp_rate_limit <= 0) e.ntp_rate_limit = "Must be > 0";
    if (config.ntp_rate_burst < 1) e.ntp_rate_burst = "Must be >= 1";
    if (config.ptp_domain > 127) e.ptp_domain = "Must be 0-127";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const saveConfig = async () => {
    if (!validate()) return;
    setSaving(true);
    try {
      const res = await fetch("/api/v1/time/config", { method: "PUT", headers: authHeaders(), body: JSON.stringify(config) });
      const body = await res.json();
      setActionMsg(body.message || "Saved");
    } catch (e) { setActionMsg("Save failed"); }
    setSaving(false);
    setTimeout(() => setActionMsg(""), 3000);
  };

  const applyConfig = async () => {
    if (!validate()) return;
    setApplying(true);
    try {
      // Save first, then apply
      await fetch("/api/v1/time/config", { method: "PUT", headers: authHeaders(), body: JSON.stringify(config) });
      const res = await fetch("/api/v1/time/apply", { method: "POST", headers: authHeaders() });
      const body = await res.json();
      setActionMsg(body.message || "Applied");
      fetchStatus();
    } catch (e) { setActionMsg("Apply failed"); }
    setApplying(false);
    setTimeout(() => setActionMsg(""), 5000);
  };

  const serviceAction = async (action: string) => {
    try {
      const res = await fetch(`/api/v1/time/${action}`, { method: "POST", headers: authHeaders() });
      const body = await res.json();
      setActionMsg(body.message || action);
      fetchStatus();
    } catch { setActionMsg(`${action} failed`); }
    setTimeout(() => setActionMsg(""), 3000);
  };

  const addSource = async () => {
    if (!newAddr.trim()) return;
    const pollErr = validatePollRange(newMinPoll, newMaxPoll);
    if (pollErr) { setErrors({ ...errors, newSource: pollErr }); return; }
    try {
      await fetch("/api/v1/time/sources", {
        method: "POST", headers: authHeaders(),
        body: JSON.stringify({ address: newAddr, nts: newNts, min_poll: newMinPoll, max_poll: newMaxPoll, enabled: true }),
      });
      setNewAddr(""); setNewNts(false); setNewMinPoll(4); setNewMaxPoll(10);
      setErrors({});
      fetchSources();
    } catch { /* */ }
  };

  const deleteSource = async (id: string) => {
    await fetch(`/api/v1/time/sources/${id}`, { method: "DELETE", headers: authHeaders() });
    fetchSources();
  };

  const toggleSourceEnabled = async (s: NtpSource) => {
    await fetch(`/api/v1/time/sources/${s.id}`, {
      method: "PUT", headers: authHeaders(),
      body: JSON.stringify({ address: s.address, nts: s.nts, min_poll: s.min_poll, max_poll: s.max_poll, enabled: !s.enabled }),
    });
    fetchSources();
  };

  const toggleIface = (name: string) => {
    setConfig(prev => ({
      ...prev,
      ntp_interfaces: prev.ntp_interfaces.includes(name)
        ? prev.ntp_interfaces.filter(n => n !== name)
        : [...prev.ntp_interfaces, name],
    }));
  };

  const allIfaceSelected = config.ntp_interfaces.length === 0;

  const inputCls = "bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-white w-full";
  const errCls = "text-red-400 text-[10px] mt-0.5";
  const labelCls = "text-xs text-gray-400 block mb-1";
  const sectionCls = "bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-3";
  const headCls = "text-sm font-medium text-white mb-2 flex items-center gap-2";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Time Service (NTP/PTP)</h1>
          <p className="text-sm text-gray-400">rTIME NTPv4/PTP time synchronization</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${status?.running ? "bg-green-500" : "bg-red-500"}`} />
          <span className="text-xs text-gray-400">{status?.version || "..."}</span>
        </div>
      </div>

      {/* Action bar */}
      <div className="flex items-center gap-2">
        <button onClick={() => serviceAction("start")} className="px-3 py-1.5 text-xs bg-green-600 hover:bg-green-700 text-white rounded">Start</button>
        <button onClick={() => serviceAction("stop")} className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded">Stop</button>
        <button onClick={() => serviceAction("restart")} className="px-3 py-1.5 text-xs bg-amber-600 hover:bg-amber-700 text-white rounded">Restart</button>
        <div className="flex-1" />
        <button onClick={saveConfig} disabled={saving} className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50">
          {saving ? "Saving..." : "Save Settings"}
        </button>
        <button onClick={applyConfig} disabled={applying} className="px-4 py-1.5 text-xs bg-purple-600 hover:bg-purple-700 text-white rounded disabled:opacity-50">
          {applying ? "Applying..." : "Apply & Restart"}
        </button>
      </div>
      {actionMsg && <div className="bg-blue-900/30 border border-blue-700 rounded px-3 py-2 text-xs text-blue-300">{actionMsg}</div>}

      {/* General */}
      <div className={sectionCls}>
        <div className={headCls}>General</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={config.enabled} onChange={e => setConfig({ ...config, enabled: e.target.checked })} className="accent-blue-500" />
            Enable rTIME Service
          </label>
          <div>
            <span className={labelCls}>Log Level</span>
            <select value={config.log_level} onChange={e => setConfig({ ...config, log_level: e.target.value })} className={inputCls}>
              {["trace", "debug", "info", "warn", "error"].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Clock Discipline */}
      <div className={sectionCls}>
        <div className={headCls}>Clock Discipline</div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input type="checkbox" checked={config.clock_discipline} onChange={e => setConfig({ ...config, clock_discipline: e.target.checked })} className="accent-blue-500" />
            Adjust System Clock
          </label>
          <div>
            <span className={labelCls}>Step Threshold (ms)</span>
            <input type="number" step="0.1" min="0.1" value={config.clock_step_threshold_ms}
              onChange={e => setConfig({ ...config, clock_step_threshold_ms: parseFloat(e.target.value) || 0 })} className={inputCls} />
            {errors.clock_step && <div className={errCls}>{errors.clock_step}</div>}
            <div className="text-[10px] text-gray-600 mt-0.5">Offset above this triggers immediate step instead of slew</div>
          </div>
          <div>
            <span className={labelCls}>Panic Threshold (ms)</span>
            <input type="number" step="0.1" min="0.1" value={config.clock_panic_threshold_ms}
              onChange={e => setConfig({ ...config, clock_panic_threshold_ms: parseFloat(e.target.value) || 0 })} className={inputCls} />
            {errors.clock_panic && <div className={errCls}>{errors.clock_panic}</div>}
            <div className="text-[10px] text-gray-600 mt-0.5">Refuse adjustment if offset exceeds this</div>
          </div>
        </div>
      </div>

      {/* NTP Server */}
      <div className={sectionCls}>
        <div className={headCls}>
          NTP Server
          <label className="flex items-center gap-2 text-xs text-gray-400 font-normal ml-auto">
            <input type="checkbox" checked={config.ntp_enabled} onChange={e => setConfig({ ...config, ntp_enabled: e.target.checked })} className="accent-blue-500" />
            Enabled
          </label>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <span className={labelCls}>Listen Address</span>
            <input type="text" value={config.ntp_listen} onChange={e => setConfig({ ...config, ntp_listen: e.target.value })} className={inputCls} placeholder="0.0.0.0:123" />
            {errors.ntp_listen && <div className={errCls}>{errors.ntp_listen}</div>}
          </div>
          <div>
            <span className={labelCls}>Rate Limit (req/s)</span>
            <input type="number" step="0.1" min="0.1" value={config.ntp_rate_limit}
              onChange={e => setConfig({ ...config, ntp_rate_limit: parseFloat(e.target.value) || 0 })} className={inputCls} />
            {errors.ntp_rate_limit && <div className={errCls}>{errors.ntp_rate_limit}</div>}
          </div>
          <div>
            <span className={labelCls}>Rate Burst</span>
            <input type="number" min="1" value={config.ntp_rate_burst}
              onChange={e => setConfig({ ...config, ntp_rate_burst: parseInt(e.target.value) || 1 })} className={inputCls} />
            {errors.ntp_rate_burst && <div className={errCls}>{errors.ntp_rate_burst}</div>}
          </div>
        </div>

        {/* Interface binding */}
        <div>
          <span className={labelCls}>Listen Interfaces</span>
          <div className="flex flex-wrap gap-2 mt-1">
            <button onClick={() => setConfig({ ...config, ntp_interfaces: [] })}
              className={`px-2.5 py-1 text-xs rounded border transition-colors ${allIfaceSelected ? "bg-blue-600/20 border-blue-500/40 text-blue-400" : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"}`}>
              All
            </button>
            {interfaces.map(iface => {
              const sel = config.ntp_interfaces.includes(iface);
              return (
                <button key={iface} onClick={() => toggleIface(iface)}
                  className={`px-2.5 py-1 text-xs rounded border transition-colors ${sel ? "bg-blue-600/20 border-blue-500/40 text-blue-400" : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"}`}>
                  {iface}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* NTP Sources */}
      <div className={sectionCls}>
        <div className={headCls}>Upstream NTP Sources</div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-2 text-gray-500 uppercase text-[10px]">Address</th>
                <th className="text-left py-2 px-2 text-gray-500 uppercase text-[10px]">NTS</th>
                <th className="text-left py-2 px-2 text-gray-500 uppercase text-[10px]">Min Poll</th>
                <th className="text-left py-2 px-2 text-gray-500 uppercase text-[10px]">Max Poll</th>
                <th className="text-left py-2 px-2 text-gray-500 uppercase text-[10px]">Enabled</th>
                <th className="py-2 px-2"></th>
              </tr>
            </thead>
            <tbody>
              {sources.map(s => (
                <tr key={s.id} className="border-b border-gray-700/30 hover:bg-gray-700/20">
                  <td className="py-1.5 px-2 font-mono text-white">{s.address}</td>
                  <td className="py-1.5 px-2">{s.nts ? <span className="text-green-400">Yes</span> : <span className="text-gray-500">No</span>}</td>
                  <td className="py-1.5 px-2 text-gray-300">{s.min_poll} ({Math.pow(2, s.min_poll)}s)</td>
                  <td className="py-1.5 px-2 text-gray-300">{s.max_poll} ({Math.pow(2, s.max_poll)}s)</td>
                  <td className="py-1.5 px-2">
                    <button onClick={() => toggleSourceEnabled(s)} className={`text-xs ${s.enabled ? "text-green-400" : "text-gray-500"}`}>
                      {s.enabled ? "Yes" : "No"}
                    </button>
                  </td>
                  <td className="py-1.5 px-2 text-right">
                    <button onClick={() => deleteSource(s.id)} className="text-red-400 hover:text-red-300 text-[10px]">Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* Add source form */}
        <div className="flex items-end gap-2 pt-2 border-t border-gray-700">
          <div className="flex-1">
            <span className={labelCls}>Server Address</span>
            <input type="text" value={newAddr} onChange={e => setNewAddr(e.target.value)} className={inputCls} placeholder="time.cloudflare.com" />
          </div>
          <div className="w-16">
            <span className={labelCls}>Min</span>
            <input type="number" min="1" max="17" value={newMinPoll} onChange={e => setNewMinPoll(parseInt(e.target.value) || 4)} className={inputCls} />
          </div>
          <div className="w-16">
            <span className={labelCls}>Max</span>
            <input type="number" min="1" max="17" value={newMaxPoll} onChange={e => setNewMaxPoll(parseInt(e.target.value) || 10)} className={inputCls} />
          </div>
          <label className="flex items-center gap-1 text-xs text-gray-400 pb-1">
            <input type="checkbox" checked={newNts} onChange={e => setNewNts(e.target.checked)} className="accent-blue-500" />
            NTS
          </label>
          <button onClick={addSource} className="px-3 py-1.5 text-xs bg-green-600 hover:bg-green-700 text-white rounded whitespace-nowrap">Add Source</button>
        </div>
        {errors.newSource && <div className={errCls}>{errors.newSource}</div>}
      </div>

      {/* NTS (Network Time Security) */}
      <div className={sectionCls}>
        <div className={headCls}>
          Network Time Security (NTS)
          <label className="flex items-center gap-2 text-xs text-gray-400 font-normal ml-auto">
            <input type="checkbox" checked={config.nts_enabled} onChange={e => setConfig({ ...config, nts_enabled: e.target.checked })} className="accent-blue-500" />
            Enabled
          </label>
        </div>
        {config.nts_enabled && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <span className={labelCls}>NTS-KE Listen Address</span>
              <input type="text" value={config.nts_ke_listen} onChange={e => setConfig({ ...config, nts_ke_listen: e.target.value })} className={inputCls} placeholder="0.0.0.0:4460" />
              {errors.nts_ke_listen && <div className={errCls}>{errors.nts_ke_listen}</div>}
            </div>
            <div>
              <span className={labelCls}>TLS Certificate Path</span>
              <input type="text" value={config.nts_certificate} onChange={e => setConfig({ ...config, nts_certificate: e.target.value })} className={inputCls} placeholder="/etc/rtime/cert.pem" />
              {errors.nts_certificate && <div className={errCls}>{errors.nts_certificate}</div>}
            </div>
            <div>
              <span className={labelCls}>TLS Private Key Path</span>
              <input type="text" value={config.nts_private_key} onChange={e => setConfig({ ...config, nts_private_key: e.target.value })} className={inputCls} placeholder="/etc/rtime/key.pem" />
              {errors.nts_private_key && <div className={errCls}>{errors.nts_private_key}</div>}
            </div>
          </div>
        )}
      </div>

      {/* PTP (Precision Time Protocol) */}
      <div className={sectionCls}>
        <div className={headCls}>
          Precision Time Protocol (PTP / IEEE 1588)
          <label className="flex items-center gap-2 text-xs text-gray-400 font-normal ml-auto">
            <input type="checkbox" checked={config.ptp_enabled} onChange={e => setConfig({ ...config, ptp_enabled: e.target.checked })} className="accent-blue-500" />
            Enabled
          </label>
        </div>
        {config.ptp_enabled && (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <span className={labelCls}>Domain (0-127)</span>
              <input type="number" min="0" max="127" value={config.ptp_domain}
                onChange={e => setConfig({ ...config, ptp_domain: parseInt(e.target.value) || 0 })} className={inputCls} />
              {errors.ptp_domain && <div className={errCls}>{errors.ptp_domain}</div>}
            </div>
            <div>
              <span className={labelCls}>Interface</span>
              <select value={config.ptp_interface} onChange={e => setConfig({ ...config, ptp_interface: e.target.value })} className={inputCls}>
                {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
            </div>
            <div>
              <span className={labelCls}>Transport</span>
              <select value={config.ptp_transport} onChange={e => setConfig({ ...config, ptp_transport: e.target.value })} className={inputCls}>
                <option value="udp-ipv4">UDP/IPv4</option>
              </select>
            </div>
            <div>
              <span className={labelCls}>Priority 1 (0-255)</span>
              <input type="number" min="0" max="255" value={config.ptp_priority1}
                onChange={e => setConfig({ ...config, ptp_priority1: parseInt(e.target.value) || 0 })} className={inputCls} />
            </div>
            <div>
              <span className={labelCls}>Priority 2 (0-255)</span>
              <input type="number" min="0" max="255" value={config.ptp_priority2}
                onChange={e => setConfig({ ...config, ptp_priority2: parseInt(e.target.value) || 0 })} className={inputCls} />
            </div>
            <div>
              <span className={labelCls}>Delay Mechanism</span>
              <select value={config.ptp_delay_mechanism} onChange={e => setConfig({ ...config, ptp_delay_mechanism: e.target.value })} className={inputCls}>
                <option value="e2e">End-to-End (E2E)</option>
                <option value="p2p">Peer-to-Peer (P2P)</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Metrics & Management */}
      <div className={sectionCls}>
        <div className={headCls}>Observability</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={config.metrics_enabled} onChange={e => setConfig({ ...config, metrics_enabled: e.target.checked })} className="accent-blue-500" />
              Prometheus Metrics
            </label>
            {config.metrics_enabled && (
              <div>
                <span className={labelCls}>Metrics Listen Address</span>
                <input type="text" value={config.metrics_listen} onChange={e => setConfig({ ...config, metrics_listen: e.target.value })} className={inputCls} placeholder="127.0.0.1:9100" />
                {errors.metrics_listen && <div className={errCls}>{errors.metrics_listen}</div>}
              </div>
            )}
          </div>
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={config.management_enabled} onChange={e => setConfig({ ...config, management_enabled: e.target.checked })} className="accent-blue-500" />
              Management API
            </label>
            {config.management_enabled && (
              <div>
                <span className={labelCls}>Management Listen Address</span>
                <input type="text" value={config.management_listen} onChange={e => setConfig({ ...config, management_listen: e.target.value })} className={inputCls} placeholder="127.0.0.1:9200" />
                {errors.management_listen && <div className={errCls}>{errors.management_listen}</div>}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
