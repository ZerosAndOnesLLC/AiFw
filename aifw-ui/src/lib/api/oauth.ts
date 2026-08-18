import { api } from "@/lib/api";

/// OAuth / SSO (#170) — types + typed API calls. Provider management is
/// admin-only; login options / authorize are public.

export type OAuthProviderType = "google" | "github" | "oidc";

export interface OAuthLoginOption {
  name: string;
  provider_type: OAuthProviderType;
}

export interface OAuthProvider {
  id: string;
  name: string;
  provider_type: OAuthProviderType;
  client_id: string;
  auth_url: string;
  token_url: string;
  userinfo_url: string;
  scopes: string;
  enabled: boolean;
  created_at: string;
}

export interface CreateOAuthProviderRequest {
  name: string;
  provider_type: OAuthProviderType;
  client_id: string;
  client_secret: string;
  auth_url?: string;
  token_url?: string;
  userinfo_url?: string;
  scopes?: string;
}

export interface OAuthSettings {
  public_url: string;
}

export async function fetchOAuthLoginOptions(): Promise<OAuthLoginOption[]> {
  const body = await api.get<{ data: OAuthLoginOption[] }>("/api/v1/auth/oauth/login-options");
  return body.data ?? [];
}

/// Ask the API for the provider's authorization URL and send the browser there.
export async function startOAuthLogin(name: string): Promise<void> {
  const body = await api.get<{ authorize_url: string }>(
    `/api/v1/auth/oauth/${encodeURIComponent(name)}/authorize`,
  );
  window.location.assign(body.authorize_url);
}

/// Human text for the `?oauth_error=` codes the callback redirects with.
export function oauthErrorMessage(code: string): string {
  switch (code) {
    case "denied": return "Sign-in was cancelled at the identity provider.";
    case "state": return "The sign-in request expired or was already used. Please try again.";
    case "exchange": return "The identity provider rejected the sign-in (token exchange failed). Check the client ID / secret and redirect URI.";
    case "userinfo": return "Could not read your profile from the identity provider.";
    case "no_account": return "No AiFw account is linked to that identity, and automatic account creation is off. Ask an administrator.";
    case "disabled": return "This account is disabled.";
    case "provider": return "That sign-in provider is not available.";
    default: return "Single sign-on failed. Please try again.";
  }
}

export async function listOAuthProviders(): Promise<OAuthProvider[]> {
  const body = await api.get<{ data: OAuthProvider[] }>("/api/v1/auth/oauth/providers");
  return body.data ?? [];
}

export function createOAuthProvider(req: CreateOAuthProviderRequest): Promise<{ data: OAuthProvider }> {
  return api.post<{ data: OAuthProvider }>("/api/v1/auth/oauth/providers", req);
}

export function deleteOAuthProvider(id: string): Promise<unknown> {
  return api.delete<unknown>(`/api/v1/auth/oauth/providers/${id}`);
}

export function getOAuthSettings(): Promise<OAuthSettings> {
  return api.get<OAuthSettings>("/api/v1/auth/oauth/settings");
}

export function saveOAuthSettings(s: OAuthSettings): Promise<OAuthSettings> {
  return api.put<OAuthSettings>("/api/v1/auth/oauth/settings", s);
}
