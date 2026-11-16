import { api } from "@/lib/api";

/* ------------------------------- Types ---------------------------------- */

/** An API key as listed — the secret is never returned after creation. */
export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  user_id: string;
  username: string;
  role_id: string | null;
  role_name: string | null;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  expired: boolean;
}

export interface CreateApiKeyRequest {
  name: string;
  /** Narrow the key to this role (must not exceed your own permissions). */
  role_id?: string;
  /** Lifetime in days (1–3650); omit for a key that never expires. */
  expires_in_days?: number;
}

/** Returned once on creation; `key` is the only time the secret is shown. */
export interface CreatedApiKey {
  id: string;
  name: string;
  key: string;
  prefix: string;
  user_id: string;
  role_id: string | null;
  expires_at: string | null;
}

export interface RoleOption {
  id: string;
  name: string;
}

/* ------------------------------ API calls ------------------------------- */

export async function listApiKeys(): Promise<ApiKeyInfo[]> {
  const res = await api.get<{ data: ApiKeyInfo[] }>("/api/v1/auth/api-keys");
  return res.data ?? [];
}

export function createApiKey(req: CreateApiKeyRequest): Promise<CreatedApiKey> {
  return api.post<CreatedApiKey>("/api/v1/auth/api-keys", req);
}

export function revokeApiKey(id: string): Promise<{ message: string }> {
  return api.delete<{ message: string }>(`/api/v1/auth/api-keys/${encodeURIComponent(id)}`);
}

/** Roles a key may be narrowed to. Needs users:read; callers fall back to []. */
export async function listRoleOptions(): Promise<RoleOption[]> {
  const res = await api.get<{ roles?: RoleOption[] }>("/api/v1/auth/roles");
  return (res.roles ?? []).filter((r) => r.name !== "system");
}
