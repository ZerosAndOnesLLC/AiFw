"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  ApiKeyInfo,
  CreateApiKeyRequest,
  CreatedApiKey,
  RoleOption,
  createApiKey,
  listApiKeys,
  listRoleOptions,
  revokeApiKey,
} from "@/lib/api/apiKeys";

/** State + actions for Profile → API Keys (self-service keys for the CLI/scripts). */
export function useApiKeys() {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [roles, setRoles] = useState<RoleOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  /** Secret of the key just created — shown once, then cleared. */
  const [created, setCreated] = useState<CreatedApiKey | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback(5000);

  const refresh = useCallback(async () => {
    try {
      setKeys(await listApiKeys());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Failed to load API keys: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, [showFeedback]);

  useEffect(() => {
    (async () => {
      await refresh();
      try {
        setRoles(await listRoleOptions());
      } catch {
        // Without users:read the role picker just offers "same as my account".
        setRoles([]);
      }
    })();
  }, [refresh]);

  const create = async (req: CreateApiKeyRequest): Promise<boolean> => {
    setCreating(true);
    clearFeedback();
    try {
      const key = await createApiKey(req);
      setCreated(key);
      await refresh();
      showFeedback("success", `API key "${key.name}" created. Copy it now — it won't be shown again.`);
      return true;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Create failed: ${msg}`);
      return false;
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (key: ApiKeyInfo) => {
    setRevoking(key.id);
    clearFeedback();
    try {
      await revokeApiKey(key.id);
      setKeys((ks) => ks.filter((k) => k.id !== key.id));
      if (created?.id === key.id) setCreated(null);
      showFeedback("success", `API key "${key.name}" revoked.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Revoke failed: ${msg}`);
    } finally {
      setRevoking(null);
    }
  };

  return {
    keys,
    roles,
    loading,
    creating,
    revoking,
    created,
    dismissCreated: () => setCreated(null),
    feedback,
    create,
    revoke,
  };
}
