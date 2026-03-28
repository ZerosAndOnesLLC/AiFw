"use client";

import { useState, useRef } from "react";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

export default function BackupPage() {
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [importData, setImportData] = useState<object | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await fetch("/api/v1/config/export", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const json = JSON.stringify(data, null, 2);

      // Download as file
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      a.href = url;
      a.download = `aifw-backup-${ts}.json`;
      a.click();
      URL.revokeObjectURL(url);

      showFeedback("success", `Configuration exported (${(json.length / 1024).toFixed(1)} KB)`);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const text = ev.target?.result as string;
        const data = JSON.parse(text);
        setImportData(data);
        setPreview(JSON.stringify(data, null, 2));
      } catch {
        showFeedback("error", "Invalid JSON file");
      }
    };
    reader.readAsText(file);
  };

  const handleImport = async () => {
    if (!importData) return;
    setImporting(true);
    try {
      const res = await fetch("/api/v1/config/import", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(importData),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result = await res.json();
      showFeedback("success", result.message || "Configuration imported");
      setImportData(null);
      setPreview(null);
      if (fileRef.current) fileRef.current.value = "";
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const configSummary = importData ? (() => {
    const d = importData as Record<string, unknown>;
    const items: string[] = [];
    if (Array.isArray(d.rules)) items.push(`${(d.rules as unknown[]).length} rules`);
    if (Array.isArray(d.nat_rules)) items.push(`${(d.nat_rules as unknown[]).length} NAT rules`);
    if (Array.isArray(d.geoip_rules)) items.push(`${(d.geoip_rules as unknown[]).length} Geo-IP rules`);
    if (Array.isArray(d.static_routes)) items.push(`${(d.static_routes as unknown[]).length} static routes`);
    if (Array.isArray(d.dns_servers)) items.push(`${(d.dns_servers as unknown[]).length} DNS servers`);
    if (d.auth_settings) items.push("auth settings");
    const vpn = d.vpn as Record<string, unknown> | undefined;
    if (vpn) {
      if (Array.isArray(vpn.wireguard_tunnels)) items.push(`${(vpn.wireguard_tunnels as unknown[]).length} WG tunnels`);
      if (Array.isArray(vpn.ipsec_sas)) items.push(`${(vpn.ipsec_sas as unknown[]).length} IPsec SAs`);
    }
    return items.join(", ") || "Empty config";
  })() : "";

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Backup & Restore</h1>
        <p className="text-sm text-[var(--text-muted)]">Export or import your firewall configuration as JSON</p>
      </div>

      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success" ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>{feedback.msg}</div>
      )}

      {/* Export */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-2">Export Configuration</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Download a complete backup of your firewall configuration including rules, NAT, routes, DNS, VPN, Geo-IP, and auth settings.
        </p>
        <button onClick={handleExport} disabled={exporting}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          {exporting ? "Exporting..." : "Export Backup"}
        </button>
      </div>

      {/* Import */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-2">Restore Configuration</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Upload a previously exported JSON backup to restore your configuration. DNS servers, auth settings, and static routes will be imported.
        </p>

        <div className="space-y-4">
          <div>
            <input ref={fileRef} type="file" accept=".json" onChange={handleFileSelect}
              className="text-sm text-[var(--text-secondary)] file:mr-3 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-gray-700 file:text-white hover:file:bg-gray-600 file:cursor-pointer" />
          </div>

          {preview && (
            <>
              <div className="bg-gray-900 border border-gray-700 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-[var(--text-muted)] uppercase font-medium">Config Summary</span>
                  <span className="text-xs text-[var(--text-secondary)]">{configSummary}</span>
                </div>
                {(() => {
                  const d = importData as Record<string, unknown>;
                  const ver = d?.version ? String(d.version) : null;
                  const exp = d?.exported_at ? new Date(String(d.exported_at)).toLocaleString() : null;
                  if (!ver) return null;
                  return <div className="text-xs text-[var(--text-muted)]">Exported from AiFw v{ver}{exp && ` on ${exp}`}</div>;
                })()}
              </div>

              <details className="text-xs">
                <summary className="text-[var(--text-muted)] cursor-pointer hover:text-[var(--text-secondary)]">
                  View raw JSON ({(preview.length / 1024).toFixed(1)} KB)
                </summary>
                <pre className="bg-gray-900 border border-gray-700 rounded-lg p-3 mt-2 overflow-x-auto max-h-64 overflow-y-auto text-[var(--text-secondary)] font-mono">
                  {preview}
                </pre>
              </details>

              <div className="flex gap-3">
                <button onClick={handleImport} disabled={importing}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                  </svg>
                  {importing ? "Importing..." : "Import & Apply"}
                </button>
                <button onClick={() => { setImportData(null); setPreview(null); if (fileRef.current) fileRef.current.value = ""; }}
                  className="px-4 py-2 text-[var(--text-muted)] hover:text-white text-sm">
                  Cancel
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
