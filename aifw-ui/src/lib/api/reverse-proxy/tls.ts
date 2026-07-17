import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface TlsCert {
  id: string;
  name: string;
  cert_file: string;
  key_file: string;
  stores_json: string;
  created_at: string;
}

export interface TlsOption {
  id: string;
  name: string;
  config_json: string;
  created_at: string;
}

export interface CertResolver {
  id: string;
  name: string;
  config_json: string;
  created_at: string;
}

/* -- TLS Option form types ------------------------------------------ */

export interface TlsOptionForm {
  name: string;
  minVersion: string;
  maxVersion: string;
  cipherSuites: string;
  sniStrict: boolean;
  clientAuthType: string;
  clientAuthCaFiles: string;
  alpnProtocols: string;
}

export const defaultTlsOptionForm: TlsOptionForm = {
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

export interface CertResolverForm {
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

export const defaultCertResolverForm: CertResolverForm = {
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

export interface TlsCertForm {
  name: string;
  certFile: string;
  keyFile: string;
}

export const defaultTlsCertForm: TlsCertForm = {
  name: "",
  certFile: "",
  keyFile: "",
};

export const tlsVersions = ["", "VersionTLS10", "VersionTLS11", "VersionTLS12", "VersionTLS13"];

export const clientAuthTypes = [
  "",
  "NoClientCert",
  "RequestClientCert",
  "RequireAnyClientCert",
  "VerifyClientCertIfGiven",
  "RequireAndVerifyClientCert",
];

export const caServerPresets: Record<string, string> = {
  "https://acme-v02.api.letsencrypt.org/directory": "Let's Encrypt Production",
  "https://acme-staging-v02.api.letsencrypt.org/directory": "Let's Encrypt Staging",
  custom: "Custom",
};

/* -- Helpers --------------------------------------------------------- */

export function buildTlsOptionJson(form: TlsOptionForm): string {
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

export function parseTlsOptionJson(raw: string): Partial<TlsOptionForm> {
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

export function buildCertResolverJson(form: CertResolverForm): string {
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

export function parseCertResolverJson(raw: string): Partial<CertResolverForm> {
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

export function parseTlsOptionDisplay(raw: string): { minVersion: string; maxVersion: string; sniStrict: boolean } {
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

export function parseCertResolverDisplay(raw: string): { email: string; challengeType: string } {
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

/* -- Request payloads ------------------------------------------------ */

export interface TlsCertPayload {
  name: string;
  cert_file: string;
  key_file: string;
}

export interface TlsOptionPayload {
  name: string;
  config_json: string;
}

export interface CertResolverPayload {
  name: string;
  config_json: string;
}

/* -- HTTP calls ------------------------------------------------------ */

export async function listTlsCerts(): Promise<TlsCert[]> {
  const body = await api.get<TlsCert[] | { data?: TlsCert[] }>("/api/v1/reverse-proxy/tls/certs");
  return Array.isArray(body) ? body : body.data || [];
}

export async function createTlsCert(payload: TlsCertPayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/tls/certs", payload);
}

export async function updateTlsCert(id: string, payload: TlsCertPayload): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/tls/certs/${id}`, payload);
}

export async function deleteTlsCert(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/tls/certs/${id}`);
}

export async function listTlsOptions(): Promise<TlsOption[]> {
  const body = await api.get<TlsOption[] | { data?: TlsOption[] }>("/api/v1/reverse-proxy/tls/options");
  return Array.isArray(body) ? body : body.data || [];
}

export async function createTlsOption(payload: TlsOptionPayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/tls/options", payload);
}

export async function updateTlsOption(id: string, payload: TlsOptionPayload): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/tls/options/${id}`, payload);
}

export async function deleteTlsOption(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/tls/options/${id}`);
}

export async function listCertResolvers(): Promise<CertResolver[]> {
  const body = await api.get<CertResolver[] | { data?: CertResolver[] }>("/api/v1/reverse-proxy/cert-resolvers");
  return Array.isArray(body) ? body : body.data || [];
}

export async function createCertResolver(payload: CertResolverPayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/cert-resolvers", payload);
}

export async function updateCertResolver(id: string, payload: CertResolverPayload): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/cert-resolvers/${id}`, payload);
}

export async function deleteCertResolver(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/cert-resolvers/${id}`);
}
