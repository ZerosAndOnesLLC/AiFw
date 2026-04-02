"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface TlsCert {
  id: string;
  name: string;
  cert_file: string;
  key_file: string;
  stores_json: string;
  created_at: string;
}

interface TlsOption {
  id: string;
  name: string;
  config_json: string;
  created_at: string;
}

interface CertResolver {
  id: string;
  name: string;
  config_json: string;
  created_at: string;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

/* -- TLS Option form types ------------------------------------------ */

interface TlsOptionForm {
  name: string;
  minVersion: string;
  maxVersion: string;
  cipherSuites: string;
  sniStrict: boolean;
  clientAuthType: string;
  clientAuthCaFiles: string;
  alpnProtocols: string;
}

const defaultTlsOptionForm: TlsOptionForm = {
  name: "",
  minVersion: "",
  maxVersion: "",
  cipherSuites: "",
  sniStrict: false,
  clientAuthType: "",
  clientAuthCaFiles: "",
  alpnProtocols: "",
};

/* -- Cert Resolver form types --------------------------------------- */

interface CertResolverForm {
  name: string;
  email: string;
  storage: string;
  caServerPreset: string;
  caServerCustom: string;
  keyType: string;
  challengeType: string;
  httpEntryPoint: string;
  dnsProvider: string;
  dnsResolvers: string;
  dnsDisablePropagationCheck: boolean;
}

const defaultCertResolverForm: CertResolverForm = {
  name: "",
  email: "",
  storage: "/usr/local/etc/trafficcop/acme.json",
  caServerPreset: "https://acme-v02.api.letsencrypt.org/directory",
  caServerCustom: "",
  keyType: "RSA4096",
  challengeType: "HTTP-01",
  httpEntryPoint: "web",
  dnsProvider: "",
  dnsResolvers: "",
  dnsDisablePropagationCheck: false,
};

/* -- TLS Cert form types -------------------------------------------- */

interface TlsCertForm {
  name: string;
  certFile: string;
  keyFile: string;
}

const defaultTlsCertForm: TlsCertForm = {
  name: "",
  certFile: "",
  keyFile: "",
};

const tlsVersions = ["", "VersionTLS10", "VersionTLS11", "VersionTLS12", "VersionTLS13"];

const clientAuthTypes = [
  "",
  "NoClientCert",
  "RequestClientCert",
  "RequireAnyClientCert",
  "VerifyClientCertIfGiven",
  "RequireAndVerifyClientCert",
];

const caServerPresets: Record<string, string> = {
  "https://acme-v02.api.letsencrypt.org/directory": "Let's Encrypt Production",
  "https://acme-staging-v02.api.letsencrypt.org/directory": "Let's Encrypt Staging",
  custom: "Custom",
};

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function buildTlsOptionJson(form: TlsOptionForm): string {
  const cfg: Record<string, unknown> = {};
  if (form.minVersion) cfg.minVersion = form.minVersion;
  if (form.maxVersion) cfg.maxVersion = form.maxVersion;
  const suites = form.cipherSuites
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (suites.length > 0) cfg.cipherSuites = suites;
  if (form.sniStrict) cfg.sniStrict = true;
  const clientAuth: Record<string, unknown> = {};
  if (form.clientAuthType) clientAuth.clientAuthType = form.clientAuthType;
  const caFiles = form.clientAuthCaFiles
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (caFiles.length > 0) clientAuth.caFiles = caFiles;
  if (Object.keys(clientAuth).length > 0) cfg.clientAuth = clientAuth;
  const alpn = form.alpnProtocols
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (alpn.length > 0) cfg.alpnProtocols = alpn;
  return JSON.stringify(cfg);
}

function parseTlsOptionJson(raw: string): Partial<TlsOptionForm> {
  try {
    const cfg = JSON.parse(raw || "{}");
    const partial: Partial<TlsOptionForm> = {};
    if (cfg.minVersion) partial.minVersion = cfg.minVersion;
    if (cfg.maxVersion) partial.maxVersion = cfg.maxVersion;
    if (Array.isArray(cfg.cipherSuites)) partial.cipherSuites = cfg.cipherSuites.join("\n");
    if (cfg.sniStrict) partial.sniStrict = true;
    if (cfg.clientAuth?.clientAuthType) partial.clientAuthType = cfg.clientAuth.clientAuthType;
    if (Array.isArray(cfg.clientAuth?.caFiles)) partial.clientAuthCaFiles = cfg.clientAuth.caFiles.join("\n");
    if (Array.isArray(cfg.alpnProtocols)) partial.alpnProtocols = cfg.alpnProtocols.join(", ");
    return partial;
  } catch {
    return {};
  }
}

function buildCertResolverJson(form: CertResolverForm): string {
  const caServer =
    form.caServerPreset === "custom" ? form.caServerCustom.trim() : form.caServerPreset;

  const acme: Record<string, unknown> = {
    email: form.email.trim(),
    storage: form.storage.trim(),
    caServer,
    keyType: form.keyType,
  };

  if (form.challengeType === "HTTP-01") {
    acme.httpChallenge = { entryPoint: form.httpEntryPoint.trim() };
  } else if (form.challengeType === "TLS-ALPN-01") {
    acme.tlsChallenge = {};
  } else if (form.challengeType === "DNS-01") {
    const dns: Record<string, unknown> = { provider: form.dnsProvider.trim() };
    const resolvers = form.dnsResolvers
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (resolvers.length > 0) dns.resolvers = resolvers;
    if (form.dnsDisablePropagationCheck) dns.disablePropagationCheck = true;
    acme.dnsChallenge = dns;
  }

  return JSON.stringify({ acme });
}

function parseCertResolverJson(raw: string): Partial<CertResolverForm> {
  try {
    const cfg = JSON.parse(raw || "{}");
    const acme = cfg.acme;
    if (!acme) return {};
    const partial: Partial<CertResolverForm> = {};
    if (acme.email) partial.email = acme.email;
    if (acme.storage) partial.storage = acme.storage;
    if (acme.keyType) partial.keyType = acme.keyType;

    // CA server preset detection
    if (acme.caServer === "https://acme-v02.api.letsencrypt.org/directory") {
      partial.caServerPreset = acme.caServer;
    } else if (acme.caServer === "https://acme-staging-v02.api.letsencrypt.org/directory") {
      partial.caServerPreset = acme.caServer;
    } else if (acme.caServer) {
      partial.caServerPreset = "custom";
      partial.caServerCustom = acme.caServer;
    }

    // Challenge type
    if (acme.httpChallenge) {
      partial.challengeType = "HTTP-01";
      if (acme.httpChallenge.entryPoint) partial.httpEntryPoint = acme.httpChallenge.entryPoint;
    } else if (acme.tlsChallenge !== undefined) {
      partial.challengeType = "TLS-ALPN-01";
    } else if (acme.dnsChallenge) {
      partial.challengeType = "DNS-01";
      if (acme.dnsChallenge.provider) partial.dnsProvider = acme.dnsChallenge.provider;
      if (Array.isArray(acme.dnsChallenge.resolvers))
        partial.dnsResolvers = acme.dnsChallenge.resolvers.join(", ");
      if (acme.dnsChallenge.disablePropagationCheck) partial.dnsDisablePropagationCheck = true;
    }

    return partial;
  } catch {
    return {};
  }
}

function parseTlsOptionDisplay(raw: string): { minVersion: string; maxVersion: string; sniStrict: boolean } {
  try {
    const cfg = JSON.parse(raw || "{}");
    return {
      minVersion: cfg.minVersion || "-",
      maxVersion: cfg.maxVersion || "-",
      sniStrict: !!cfg.sniStrict,
    };
  } catch {
    return { minVersion: "-", maxVersion: "-", sniStrict: false };
  }
}

function parseCertResolverDisplay(raw: string): { email: string; challengeType: string } {
  try {
    const cfg = JSON.parse(raw || "{}");
    const acme = cfg.acme;
    if (!acme) return { email: "-", challengeType: "-" };
    let ct = "-";
    if (acme.httpChallenge) ct = "HTTP-01";
    else if (acme.tlsChallenge !== undefined) ct = "TLS-ALPN-01";
    else if (acme.dnsChallenge) ct = "DNS-01";
    return { email: acme.email || "-", challengeType: ct };
  } catch {
    return { email: "-", challengeType: "-" };
  }
}

/* -- Page ------------------------------------------------------------ */

export default function TlsCertsPage() {
  const [certs, setCerts] = useState<TlsCert[]>([]);
  const [tlsOptions, setTlsOptions] = useState<TlsOption[]>([]);
  const [resolvers, setResolvers] = useState<CertResolver[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  // Cert modal
  const [certModalOpen, setCertModalOpen] = useState(false);
  const [editingCertId, setEditingCertId] = useState<string | null>(null);
  const [certForm, setCertForm] = useState<TlsCertForm>(defaultTlsCertForm);
  const [certSubmitting, setCertSubmitting] = useState(false);

  // TLS option modal
  const [optionModalOpen, setOptionModalOpen] = useState(false);
  const [editingOptionId, setEditingOptionId] = useState<string | null>(null);
  const [optionForm, setOptionForm] = useState<TlsOptionForm>(defaultTlsOptionForm);
  const [optionSubmitting, setOptionSubmitting] = useState(false);

  // Resolver modal
  const [resolverModalOpen, setResolverModalOpen] = useState(false);
  const [editingResolverId, setEditingResolverId] = useState<string | null>(null);
  const [resolverForm, setResolverForm] = useState<CertResolverForm>(defaultCertResolverForm);
  const [resolverSubmitting, setResolverSubmitting] = useState(false);

  // Delete confirm
  const [deleteTarget, setDeleteTarget] = useState<{ type: "cert" | "option" | "resolver"; id: string } | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchCerts = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/tls/certs", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setCerts(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load certificates");
    }
  }, []);

  const fetchOptions = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/tls/options", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setTlsOptions(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load TLS options");
    }
  }, []);

  const fetchResolvers = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/cert-resolvers", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setResolvers(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load cert resolvers");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchCerts(), fetchOptions(), fetchResolvers()]);
      setLoading(false);
    })();
  }, [fetchCerts, fetchOptions, fetchResolvers]);

  /* -- Cert Modal --------------------------------------------------- */

  const openCreateCert = () => {
    setEditingCertId(null);
    setCertForm(defaultTlsCertForm);
    setCertModalOpen(true);
  };

  const openEditCert = (cert: TlsCert) => {
    setEditingCertId(cert.id);
    setCertForm({ name: cert.name, certFile: cert.cert_file, keyFile: cert.key_file });
    setCertModalOpen(true);
  };

  const closeCertModal = () => {
    setCertModalOpen(false);
    setEditingCertId(null);
    setCertForm(defaultTlsCertForm);
  };

  const handleCertSubmit = async () => {
    if (!certForm.name.trim() || !certForm.certFile.trim() || !certForm.keyFile.trim()) {
      showFeedback("error", "Name, cert file, and key file are required");
      return;
    }
    setCertSubmitting(true);
    try {
      const payload = {
        name: certForm.name.trim(),
        cert_file: certForm.certFile.trim(),
        key_file: certForm.keyFile.trim(),
      };
      const url = editingCertId
        ? `/api/v1/reverse-proxy/tls/certs/${editingCertId}`
        : "/api/v1/reverse-proxy/tls/certs";
      const method = editingCertId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingCertId ? "Certificate updated" : "Certificate created");
      closeCertModal();
      await fetchCerts();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save certificate");
    } finally {
      setCertSubmitting(false);
    }
  };

  /* -- TLS Option Modal --------------------------------------------- */

  const openCreateOption = () => {
    setEditingOptionId(null);
    setOptionForm(defaultTlsOptionForm);
    setOptionModalOpen(true);
  };

  const openEditOption = (opt: TlsOption) => {
    const parsed = parseTlsOptionJson(opt.config_json);
    setEditingOptionId(opt.id);
    setOptionForm({ ...defaultTlsOptionForm, ...parsed, name: opt.name });
    setOptionModalOpen(true);
  };

  const closeOptionModal = () => {
    setOptionModalOpen(false);
    setEditingOptionId(null);
    setOptionForm(defaultTlsOptionForm);
  };

  const handleOptionSubmit = async () => {
    if (!optionForm.name.trim()) {
      showFeedback("error", "Name is required");
      return;
    }
    setOptionSubmitting(true);
    try {
      const payload = {
        name: optionForm.name.trim(),
        config_json: buildTlsOptionJson(optionForm),
      };
      const url = editingOptionId
        ? `/api/v1/reverse-proxy/tls/options/${editingOptionId}`
        : "/api/v1/reverse-proxy/tls/options";
      const method = editingOptionId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingOptionId ? "TLS option updated" : "TLS option created");
      closeOptionModal();
      await fetchOptions();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save TLS option");
    } finally {
      setOptionSubmitting(false);
    }
  };

  /* -- Cert Resolver Modal ------------------------------------------ */

  const openCreateResolver = () => {
    setEditingResolverId(null);
    setResolverForm(defaultCertResolverForm);
    setResolverModalOpen(true);
  };

  const openEditResolver = (r: CertResolver) => {
    const parsed = parseCertResolverJson(r.config_json);
    setEditingResolverId(r.id);
    setResolverForm({ ...defaultCertResolverForm, ...parsed, name: r.name });
    setResolverModalOpen(true);
  };

  const closeResolverModal = () => {
    setResolverModalOpen(false);
    setEditingResolverId(null);
    setResolverForm(defaultCertResolverForm);
  };

  const handleResolverSubmit = async () => {
    if (!resolverForm.name.trim() || !resolverForm.email.trim()) {
      showFeedback("error", "Name and email are required");
      return;
    }
    setResolverSubmitting(true);
    try {
      const payload = {
        name: resolverForm.name.trim(),
        config_json: buildCertResolverJson(resolverForm),
      };
      const url = editingResolverId
        ? `/api/v1/reverse-proxy/cert-resolvers/${editingResolverId}`
        : "/api/v1/reverse-proxy/cert-resolvers";
      const method = editingResolverId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingResolverId ? "Cert resolver updated" : "Cert resolver created");
      closeResolverModal();
      await fetchResolvers();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save cert resolver");
    } finally {
      setResolverSubmitting(false);
    }
  };

  /* -- Delete ------------------------------------------------------- */

  const handleDelete = async () => {
    if (!deleteTarget) return;
    const { type, id } = deleteTarget;
    let url = "";
    if (type === "cert") url = `/api/v1/reverse-proxy/tls/certs/${id}`;
    else if (type === "option") url = `/api/v1/reverse-proxy/tls/options/${id}`;
    else url = `/api/v1/reverse-proxy/cert-resolvers/${id}`;

    try {
      const res = await fetch(url, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const labels = { cert: "Certificate", option: "TLS option", resolver: "Cert resolver" };
      showFeedback("success", `${labels[type]} deleted`);
      setDeleteTarget(null);
      if (type === "cert") await fetchCerts();
      else if (type === "option") await fetchOptions();
      else await fetchResolvers();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading TLS configuration...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">TLS / Certificates</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage TLS certificates, options, and ACME certificate resolvers
        </p>
      </div>

      {/* Feedback */}
      {feedback && (
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

      {/* ============================================================= */}
      {/* Section 1: TLS Certificates                                    */}
      {/* ============================================================= */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold">TLS Certificates</h2>
          <button
            onClick={openCreateCert}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Certificate
          </button>
        </div>
        {certs.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No TLS certificates configured. Click &quot;Add Certificate&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Cert File</th>
                  <th className="px-6 py-3">Key File</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {certs.map((cert) => (
                  <tr key={cert.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => openEditCert(cert)}>
                    <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{cert.name}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">{cert.cert_file}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">{cert.key_file}</td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setDeleteTarget({ type: "cert", id: cert.id })}
                          title="Delete"
                          className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                        >
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

      {/* ============================================================= */}
      {/* Section 2: TLS Options                                         */}
      {/* ============================================================= */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold">TLS Options</h2>
          <button
            onClick={openCreateOption}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add TLS Option
          </button>
        </div>
        {tlsOptions.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No TLS options configured. Click &quot;Add TLS Option&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Min Version</th>
                  <th className="px-6 py-3">Max Version</th>
                  <th className="px-6 py-3">SNI Strict</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tlsOptions.map((opt) => {
                  const display = parseTlsOptionDisplay(opt.config_json);
                  return (
                    <tr key={opt.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => openEditOption(opt)}>
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{opt.name}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.minVersion}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.maxVersion}</td>
                      <td className="px-6 py-3">
                        {display.sniStrict ? (
                          <span className="text-xs px-2 py-0.5 rounded-full border bg-green-500/20 text-green-400 border-green-500/30">
                            Yes
                          </span>
                        ) : (
                          <span className="text-[var(--text-muted)]">-</span>
                        )}
                      </td>
                      <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => setDeleteTarget({ type: "option", id: opt.id })}
                            title="Delete"
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
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
        )}
      </div>

      {/* ============================================================= */}
      {/* Section 3: Certificate Resolvers (ACME)                        */}
      {/* ============================================================= */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold">Certificate Resolvers</h2>
          <button
            onClick={openCreateResolver}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Resolver
          </button>
        </div>
        {resolvers.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No certificate resolvers configured. Click &quot;Add Resolver&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Email</th>
                  <th className="px-6 py-3">Challenge Type</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {resolvers.map((r) => {
                  const display = parseCertResolverDisplay(r.config_json);
                  return (
                    <tr key={r.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => openEditResolver(r)}>
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{r.name}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.email}</td>
                      <td className="px-6 py-3">
                        <span className="text-xs px-2 py-0.5 rounded-full border bg-blue-500/20 text-blue-400 border-blue-500/30">
                          {display.challengeType}
                        </span>
                      </td>
                      <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => setDeleteTarget({ type: "resolver", id: r.id })}
                            title="Delete"
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
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
        )}
      </div>

      {/* ============================================================= */}
      {/* TLS Certificate Modal                                          */}
      {/* ============================================================= */}
      {certModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingCertId ? "Edit Certificate" : "Add Certificate"}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
                <input
                  type="text"
                  value={certForm.name}
                  onChange={(e) => setCertForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. my-cert"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Cert File</label>
                <input
                  type="text"
                  value={certForm.certFile}
                  onChange={(e) => setCertForm((p) => ({ ...p, certFile: e.target.value }))}
                  placeholder="/path/to/cert.pem"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Key File</label>
                <input
                  type="text"
                  value={certForm.keyFile}
                  onChange={(e) => setCertForm((p) => ({ ...p, keyFile: e.target.value }))}
                  placeholder="/path/to/key.pem"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeCertModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleCertSubmit}
                disabled={certSubmitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {certSubmitting ? "Saving..." : editingCertId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* TLS Option Modal                                               */}
      {/* ============================================================= */}
      {optionModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingOptionId ? "Edit TLS Option" : "Add TLS Option"}
            </h3>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
                <input
                  type="text"
                  value={optionForm.name}
                  onChange={(e) => setOptionForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. modern, intermediate"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* Min Version */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Min Version</label>
                <select
                  value={optionForm.minVersion}
                  onChange={(e) => setOptionForm((p) => ({ ...p, minVersion: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  {tlsVersions.map((v) => (
                    <option key={v} value={v}>
                      {v || "(none)"}
                    </option>
                  ))}
                </select>
              </div>

              {/* Max Version */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Max Version</label>
                <select
                  value={optionForm.maxVersion}
                  onChange={(e) => setOptionForm((p) => ({ ...p, maxVersion: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  {tlsVersions.map((v) => (
                    <option key={v} value={v}>
                      {v || "(none)"}
                    </option>
                  ))}
                </select>
              </div>

              {/* Cipher Suites */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Cipher Suites (one per line)</label>
                <textarea
                  value={optionForm.cipherSuites}
                  onChange={(e) => setOptionForm((p) => ({ ...p, cipherSuites: e.target.value }))}
                  rows={4}
                  placeholder={"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\nTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                />
              </div>

              {/* SNI Strict */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">SNI Strict</label>
                <button
                  type="button"
                  onClick={() => setOptionForm((p) => ({ ...p, sniStrict: !p.sniStrict }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    optionForm.sniStrict ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      optionForm.sniStrict ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {/* Client Auth Type */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Client Auth Type</label>
                <select
                  value={optionForm.clientAuthType}
                  onChange={(e) => setOptionForm((p) => ({ ...p, clientAuthType: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  {clientAuthTypes.map((v) => (
                    <option key={v} value={v}>
                      {v || "(none)"}
                    </option>
                  ))}
                </select>
              </div>

              {/* Client Auth CA Files */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Client Auth CA Files (one path per line)</label>
                <textarea
                  value={optionForm.clientAuthCaFiles}
                  onChange={(e) => setOptionForm((p) => ({ ...p, clientAuthCaFiles: e.target.value }))}
                  rows={3}
                  placeholder={"/path/to/ca1.pem\n/path/to/ca2.pem"}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                />
              </div>

              {/* ALPN Protocols */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">ALPN Protocols (comma-separated)</label>
                <input
                  type="text"
                  value={optionForm.alpnProtocols}
                  onChange={(e) => setOptionForm((p) => ({ ...p, alpnProtocols: e.target.value }))}
                  placeholder="h2, http/1.1"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeOptionModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleOptionSubmit}
                disabled={optionSubmitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {optionSubmitting ? "Saving..." : editingOptionId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* Cert Resolver Modal                                            */}
      {/* ============================================================= */}
      {resolverModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingResolverId ? "Edit Certificate Resolver" : "Add Certificate Resolver"}
            </h3>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
                <input
                  type="text"
                  value={resolverForm.name}
                  onChange={(e) => setResolverForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. letsencrypt"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* ACME Section Header */}
              <h4 className="text-sm font-medium text-[var(--text-secondary)] pt-1">ACME</h4>

              {/* Email */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Email</label>
                <input
                  type="text"
                  value={resolverForm.email}
                  onChange={(e) => setResolverForm((p) => ({ ...p, email: e.target.value }))}
                  placeholder="admin@example.com"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* Storage */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Storage Path</label>
                <input
                  type="text"
                  value={resolverForm.storage}
                  onChange={(e) => setResolverForm((p) => ({ ...p, storage: e.target.value }))}
                  placeholder="/usr/local/etc/trafficcop/acme.json"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {/* CA Server */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">CA Server</label>
                <select
                  value={resolverForm.caServerPreset}
                  onChange={(e) => setResolverForm((p) => ({ ...p, caServerPreset: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  {Object.entries(caServerPresets).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Custom CA Server URL */}
              {resolverForm.caServerPreset === "custom" && (
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Custom CA Server URL</label>
                  <input
                    type="text"
                    value={resolverForm.caServerCustom}
                    onChange={(e) => setResolverForm((p) => ({ ...p, caServerCustom: e.target.value }))}
                    placeholder="https://acme.example.com/directory"
                    className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              )}

              {/* Key Type */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Key Type</label>
                <select
                  value={resolverForm.keyType}
                  onChange={(e) => setResolverForm((p) => ({ ...p, keyType: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="RSA2048">RSA2048</option>
                  <option value="RSA4096">RSA4096</option>
                  <option value="EC256">EC256</option>
                  <option value="EC384">EC384</option>
                </select>
              </div>

              {/* Challenge Type */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Challenge Type</label>
                <select
                  value={resolverForm.challengeType}
                  onChange={(e) => setResolverForm((p) => ({ ...p, challengeType: e.target.value }))}
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="HTTP-01">HTTP-01</option>
                  <option value="TLS-ALPN-01">TLS-ALPN-01</option>
                  <option value="DNS-01">DNS-01</option>
                </select>
              </div>

              {/* HTTP-01 fields */}
              {resolverForm.challengeType === "HTTP-01" && (
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Entry Point</label>
                  <input
                    type="text"
                    value={resolverForm.httpEntryPoint}
                    onChange={(e) => setResolverForm((p) => ({ ...p, httpEntryPoint: e.target.value }))}
                    placeholder="web"
                    className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              )}

              {/* DNS-01 fields */}
              {resolverForm.challengeType === "DNS-01" && (
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs text-[var(--text-muted)] mb-1">Provider</label>
                    <input
                      type="text"
                      value={resolverForm.dnsProvider}
                      onChange={(e) => setResolverForm((p) => ({ ...p, dnsProvider: e.target.value }))}
                      placeholder="e.g. cloudflare, route53"
                      className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[var(--text-muted)] mb-1">Resolvers (comma-separated)</label>
                    <input
                      type="text"
                      value={resolverForm.dnsResolvers}
                      onChange={(e) => setResolverForm((p) => ({ ...p, dnsResolvers: e.target.value }))}
                      placeholder="1.1.1.1:53, 8.8.8.8:53"
                      className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm text-[var(--text-secondary)]">Disable Propagation Check</label>
                    <button
                      type="button"
                      onClick={() =>
                        setResolverForm((p) => ({
                          ...p,
                          dnsDisablePropagationCheck: !p.dnsDisablePropagationCheck,
                        }))
                      }
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        resolverForm.dnsDisablePropagationCheck ? "bg-blue-600" : "bg-gray-600"
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          resolverForm.dnsDisablePropagationCheck ? "translate-x-6" : "translate-x-1"
                        }`}
                      />
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeResolverModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleResolverSubmit}
                disabled={resolverSubmitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {resolverSubmitting ? "Saving..." : editingResolverId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* Delete Confirm Modal                                           */}
      {/* ============================================================= */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              Delete {deleteTarget.type === "cert" ? "Certificate" : deleteTarget.type === "option" ? "TLS Option" : "Certificate Resolver"}
            </h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this {deleteTarget.type === "cert" ? "certificate" : deleteTarget.type === "option" ? "TLS option" : "certificate resolver"}? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
