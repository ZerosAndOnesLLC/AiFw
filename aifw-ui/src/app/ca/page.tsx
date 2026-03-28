"use client";

import { useState, useEffect, useCallback } from "react";

/* ── Types ─────────────────────────────────────────────────────── */

interface CaInfo {
  initialized: boolean;
  subject: string;
  serial: string;
  not_before: string;
  not_after: string;
  fingerprint: string;
  algorithm: string;
}

interface CertRecord {
  id: string;
  cert_type: string;
  common_name: string;
  sans: string;
  serial: string;
  not_before: string;
  not_after: string;
  status: string;
  revoked_at: string | null;
  created_at: string;
}

interface IssuedCertResponse {
  id: string;
  certificate_pem: string;
}

/* ── Helpers ───────────────────────────────────────────────────── */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function downloadBlob(body: string, filename: string, mime = "application/x-pem-file") {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function truncate(s: string, len: number): string {
  return s.length > len ? s.slice(0, len) + "..." : s;
}

/* ── Status Badge ──────────────────────────────────────────────── */

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "bg-green-500/20 text-green-400 border-green-500/30",
    revoked: "bg-red-500/20 text-red-400 border-red-500/30",
    expired: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  };
  const cls = map[status] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} capitalize`}>
      {status}
    </span>
  );
}

function TypeBadge({ type }: { type: string }) {
  const cls = type === "server"
    ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : "bg-purple-500/20 text-purple-400 border-purple-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} capitalize`}>
      {type}
    </span>
  );
}

/* ── Page ──────────────────────────────────────────────────────── */

export default function CaPage() {
  const [caInfo, setCaInfo] = useState<CaInfo | null>(null);
  const [certs, setCerts] = useState<CertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // CA generation form
  const [genCn, setGenCn] = useState("AiFw Root CA");
  const [genOrg, setGenOrg] = useState("AiFw");
  const [genDays, setGenDays] = useState(3650);
  const [generating, setGenerating] = useState(false);
  const [confirmRegen, setConfirmRegen] = useState(false);

  // Issue cert form
  const [issueOpen, setIssueOpen] = useState(false);
  const [issueType, setIssueType] = useState("server");
  const [issueCn, setIssueCn] = useState("");
  const [issueSans, setIssueSans] = useState("");
  const [issueDays, setIssueDays] = useState(365);
  const [issuing, setIssuing] = useState(false);
  const [issuedPem, setIssuedPem] = useState<string | null>(null);

  // Confirm dialogs
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* ── Fetch data ────────────────────────────────────────────── */

  const fetchCa = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/ca", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setCaInfo(await res.json());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load CA info");
    }
  }, []);

  const fetchCerts = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/ca/certs", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setCerts(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load certificates");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchCa(), fetchCerts()]);
      setLoading(false);
    })();
  }, [fetchCa, fetchCerts]);

  /* ── Actions ───────────────────────────────────────────────── */

  const generateCa = async () => {
    setGenerating(true);
    try {
      const res = await fetch("/api/v1/ca", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ common_name: genCn, organization: genOrg, validity_days: genDays }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Root CA generated successfully");
      setConfirmRegen(false);
      await fetchCa();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "CA generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const downloadCaCert = async () => {
    try {
      const res = await fetch("/api/v1/ca/cert.pem", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      downloadBlob(await res.text(), "aifw-ca.pem");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Download failed");
    }
  };

  const issueCert = async () => {
    if (!issueCn.trim()) { showFeedback("error", "Common Name is required"); return; }
    setIssuing(true);
    setIssuedPem(null);
    try {
      const body: Record<string, unknown> = {
        cert_type: issueType,
        common_name: issueCn.trim(),
        validity_days: issueDays,
      };
      if (issueSans.trim()) body.sans = issueSans.trim();
      const res = await fetch("/api/v1/ca/certs", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const result: IssuedCertResponse = await res.json();
      showFeedback("success", `Certificate issued (ID: ${result.id})`);

      // Fetch full cert details to get the PEM
      if (result.certificate_pem) {
        setIssuedPem(result.certificate_pem);
      } else {
        const detailRes = await fetch(`/api/v1/ca/certs/${result.id}`, { headers: authHeadersPlain() });
        if (detailRes.ok) {
          const detail = await detailRes.json();
          if (detail.certificate_pem) setIssuedPem(detail.certificate_pem);
        }
      }

      setIssueCn("");
      setIssueSans("");
      setIssueDays(365);
      await fetchCerts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Issue failed");
    } finally {
      setIssuing(false);
    }
  };

  const downloadCert = async (id: string, cn: string) => {
    try {
      const res = await fetch(`/api/v1/ca/certs/${id}/cert.pem`, { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      downloadBlob(await res.text(), `${cn}.cert.pem`);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Download failed");
    }
  };

  const downloadKey = async (id: string, cn: string) => {
    try {
      const res = await fetch(`/api/v1/ca/certs/${id}/key.pem`, { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      downloadBlob(await res.text(), `${cn}.key.pem`);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Download failed");
    }
  };

  const revokeCert = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/ca/certs/${id}/revoke`, {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Certificate revoked");
      setRevokeId(null);
      await fetchCerts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Revoke failed");
    }
  };

  const deleteCert = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/ca/certs/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Certificate deleted");
      setDeleteId(null);
      await fetchCerts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Delete failed");
    }
  };

  const downloadCrl = async () => {
    try {
      const res = await fetch("/api/v1/ca/crl", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      downloadBlob(await res.text(), "aifw-crl.pem");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "CRL download failed");
    }
  };

  /* ── Render ────────────────────────────────────────────────── */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading CA information...
      </div>
    );
  }

  const caInitialized = caInfo?.initialized ?? false;

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">Certificate Authority</h1>
        <p className="text-sm text-[var(--text-muted)]">Manage your internal PKI: root CA, issued certificates, and revocation</p>
      </div>

      {/* Feedback */}
      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success" ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>{feedback.msg}</div>
      )}

      {/* ── CA Status Card ────────────────────────────────────── */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Root CA Status</h2>

        {!caInitialized ? (
          <div className="space-y-4">
            <p className="text-sm text-[var(--text-secondary)]">
              No Root CA has been generated yet. Create one to start issuing certificates.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Common Name</label>
                <input type="text" value={genCn} onChange={(e) => setGenCn(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Organization</label>
                <input type="text" value={genOrg} onChange={(e) => setGenOrg(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Validity (days)</label>
                <input type="number" value={genDays} onChange={(e) => setGenDays(Number(e.target.value))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500" />
              </div>
            </div>
            <button onClick={generateCa} disabled={generating}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              {generating ? "Generating..." : "Generate Root CA"}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Subject</span>
                <span className="text-[var(--text-primary)]">{caInfo!.subject}</span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Serial</span>
                <span className="text-[var(--text-primary)] font-mono text-xs">{caInfo!.serial}</span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Algorithm</span>
                <span className="text-[var(--text-primary)]">{caInfo!.algorithm}</span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Fingerprint</span>
                <span className="text-[var(--text-primary)] font-mono text-xs" title={caInfo!.fingerprint}>
                  {truncate(caInfo!.fingerprint, 24)}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Valid From</span>
                <span className="text-[var(--text-primary)]">{fmtDate(caInfo!.not_before)}</span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Expires</span>
                <span className="text-[var(--text-primary)]">{fmtDate(caInfo!.not_after)}</span>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button onClick={downloadCaCert}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Download CA Cert
              </button>

              {!confirmRegen ? (
                <button onClick={() => setConfirmRegen(true)}
                  className="px-4 py-2 border border-red-500/40 text-red-400 hover:bg-red-500/10 text-sm rounded-md flex items-center gap-2">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Regenerate
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-red-400">This will invalidate ALL issued certificates.</span>
                  <button onClick={generateCa} disabled={generating}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs rounded-md disabled:opacity-50">
                    {generating ? "Regenerating..." : "Confirm Regenerate"}
                  </button>
                  <button onClick={() => setConfirmRegen(false)}
                    className="px-3 py-1.5 text-[var(--text-muted)] hover:text-white text-xs">
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Issue Certificate Form ────────────────────────────── */}
      {caInitialized && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          <button onClick={() => setIssueOpen(!issueOpen)}
            className="w-full flex items-center justify-between px-6 py-4 text-left">
            <h2 className="text-lg font-semibold">Issue Certificate</h2>
            <svg className={`w-5 h-5 text-[var(--text-muted)] transition-transform ${issueOpen ? "rotate-180" : ""}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {issueOpen && (
            <div className="px-6 pb-6 space-y-4 border-t border-[var(--border)] pt-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Type</label>
                  <select value={issueType} onChange={(e) => setIssueType(e.target.value)}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500">
                    <option value="server">Server</option>
                    <option value="client">Client</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Common Name</label>
                  <input type="text" value={issueCn} onChange={(e) => setIssueCn(e.target.value)}
                    placeholder="e.g. myservice.local"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Subject Alternative Names</label>
                  <input type="text" value={issueSans} onChange={(e) => setIssueSans(e.target.value)}
                    placeholder="e.g. dns:api.local, ip:10.0.0.1"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                  <p className="text-[10px] text-[var(--text-muted)] mt-1">Comma-separated DNS names and IPs</p>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Validity (days)</label>
                  <input type="number" value={issueDays} onChange={(e) => setIssueDays(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500" />
                </div>
              </div>

              <button onClick={issueCert} disabled={issuing}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                {issuing ? "Issuing..." : "Issue Certificate"}
              </button>

              {/* Issued PEM output */}
              {issuedPem && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-[var(--text-muted)] uppercase font-medium">Issued Certificate PEM</span>
                    <button onClick={() => { navigator.clipboard.writeText(issuedPem); showFeedback("success", "PEM copied to clipboard"); }}
                      className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                      </svg>
                      Copy
                    </button>
                  </div>
                  <textarea readOnly value={issuedPem} rows={8}
                    className="w-full bg-gray-900 border border-gray-700 rounded-md p-3 text-xs font-mono text-green-400 resize-y focus:outline-none" />
                  <button onClick={() => setIssuedPem(null)}
                    className="text-xs text-[var(--text-muted)] hover:text-white">
                    Dismiss
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Certificates Table ────────────────────────────────── */}
      {caInitialized && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          <div className="px-6 py-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold">Issued Certificates</h2>
          </div>

          {certs.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
              No certificates issued yet. Use the form above to create one.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                    <th className="px-6 py-3">Type</th>
                    <th className="px-6 py-3">Common Name</th>
                    <th className="px-6 py-3">SANs</th>
                    <th className="px-6 py-3">Serial</th>
                    <th className="px-6 py-3">Issued</th>
                    <th className="px-6 py-3">Expires</th>
                    <th className="px-6 py-3">Status</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {certs.map((cert) => (
                    <tr key={cert.id} className="border-b border-[var(--border)] hover:bg-white/[0.02]">
                      <td className="px-6 py-3"><TypeBadge type={cert.cert_type} /></td>
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{cert.common_name}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs font-mono">{truncate(cert.sans || "-", 30)}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">{truncate(cert.serial, 16)}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)]">{fmtDate(cert.not_before)}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)]">{fmtDate(cert.not_after)}</td>
                      <td className="px-6 py-3"><StatusBadge status={cert.status} /></td>
                      <td className="px-6 py-3">
                        <div className="flex items-center justify-end gap-1">
                          {/* Download Cert */}
                          <button onClick={() => downloadCert(cert.id, cert.common_name)}
                            title="Download Certificate"
                            className="p-1.5 text-[var(--text-muted)] hover:text-blue-400 rounded hover:bg-blue-500/10">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                          </button>
                          {/* Download Key */}
                          <button onClick={() => downloadKey(cert.id, cert.common_name)}
                            title="Download Private Key"
                            className="p-1.5 text-[var(--text-muted)] hover:text-yellow-400 rounded hover:bg-yellow-500/10">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                            </svg>
                          </button>
                          {/* Revoke */}
                          {cert.status === "active" && (
                            <button onClick={() => setRevokeId(cert.id)}
                              title="Revoke Certificate"
                              className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10">
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                              </svg>
                            </button>
                          )}
                          {/* Delete */}
                          <button onClick={() => setDeleteId(cert.id)}
                            title="Delete Certificate"
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── CRL Section ───────────────────────────────────────── */}
      {caInitialized && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">Certificate Revocation List</h2>
              <p className="text-sm text-[var(--text-secondary)] mt-1">Download the current CRL to distribute to clients and services</p>
            </div>
            <button onClick={downloadCrl}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Download CRL
            </button>
          </div>
        </div>
      )}

      {/* ── Revoke Confirm Modal ──────────────────────────────── */}
      {revokeId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Revoke Certificate</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to revoke this certificate? This action cannot be undone.
              The certificate will be added to the CRL.
            </p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setRevokeId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white">
                Cancel
              </button>
              <button onClick={() => revokeCert(revokeId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md">
                Revoke
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete Confirm Modal ──────────────────────────────── */}
      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Delete Certificate</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to permanently delete this certificate record?
              This will remove the certificate and its private key from the server.
            </p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setDeleteId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white">
                Cancel
              </button>
              <button onClick={() => deleteCert(deleteId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md">
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
