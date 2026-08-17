"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import { api } from "@/lib/api";
import {
  CreateOAuthProviderRequest,
  OAuthProvider,
  OAuthProviderType,
  createOAuthProvider,
  deleteOAuthProvider,
  getOAuthSettings,
  listOAuthProviders,
  saveOAuthSettings,
} from "@/lib/api/oauth";

export interface ProviderForm {
  name: string;
  provider_type: OAuthProviderType;
  client_id: string;
  client_secret: string;
  auth_url: string;
  token_url: string;
  userinfo_url: string;
  scopes: string;
}

export const emptyProviderForm: ProviderForm = {
  name: "",
  provider_type: "google",
  client_id: "",
  client_secret: "",
  auth_url: "",
  token_url: "",
  userinfo_url: "",
  scopes: "",
};

/** State + actions for Settings → API & Auth → Single Sign-On (#170). */
export function useSsoSettings() {
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [publicUrl, setPublicUrl] = useState("");
  const [requireTotpForOauth, setRequireTotpForOauth] = useState(false);
  const [autoCreateUsers, setAutoCreateUsers] = useState(true);
  const [form, setForm] = useState<ProviderForm>(emptyProviderForm);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback(6000);

  const refresh = useCallback(async () => {
    try {
      const [list, settings, auth] = await Promise.all([
        listOAuthProviders(),
        getOAuthSettings(),
        api.get<{ require_totp_for_oauth?: boolean; auto_create_oauth_users?: boolean }>("/api/v1/auth/settings"),
      ]);
      setProviders(list);
      setPublicUrl(settings.public_url || "");
      setRequireTotpForOauth(!!auth.require_totp_for_oauth);
      setAutoCreateUsers(auth.auto_create_oauth_users !== false);
    } catch {
      /* older API or not admin — section stays empty */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { queueMicrotask(refresh); }, [refresh]);

  const savePolicy = async () => {
    setSaving(true);
    clearFeedback();
    try {
      await saveOAuthSettings({ public_url: publicUrl.trim() });
      await api.put("/api/v1/auth/settings", {
        require_totp_for_oauth: requireTotpForOauth,
        auto_create_oauth_users: autoCreateUsers,
      });
      showFeedback("success", "Single sign-on settings saved.");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const addProvider = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const req: CreateOAuthProviderRequest = {
        name: form.name.trim(),
        provider_type: form.provider_type,
        client_id: form.client_id.trim(),
        client_secret: form.client_secret,
      };
      if (form.provider_type === "oidc") {
        req.auth_url = form.auth_url.trim();
        req.token_url = form.token_url.trim();
        req.userinfo_url = form.userinfo_url.trim();
      }
      if (form.scopes.trim()) req.scopes = form.scopes.trim();
      await createOAuthProvider(req);
      setForm(emptyProviderForm);
      setShowForm(false);
      showFeedback("success", `Provider "${req.name}" added.`);
      await refresh();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Could not add provider");
    } finally {
      setSaving(false);
    }
  };

  const removeProvider = async (p: OAuthProvider) => {
    if (!window.confirm(`Remove sign-in provider "${p.name}"? Users linked to it can no longer sign in with it.`)) return;
    setDeleting(p.id);
    try {
      await deleteOAuthProvider(p.id);
      showFeedback("success", `Provider "${p.name}" removed.`);
      await refresh();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Delete failed");
    } finally {
      setDeleting(null);
    }
  };

  /// Redirect URI the operator must register at the provider.
  const redirectUriFor = (name: string): string => {
    const base = publicUrl.trim().replace(/\/+$/, "") || (typeof window !== "undefined" ? window.location.origin : "");
    return `${base}/api/v1/auth/oauth/${encodeURIComponent(name)}/callback`;
  };

  return {
    providers,
    publicUrl,
    setPublicUrl,
    requireTotpForOauth,
    setRequireTotpForOauth,
    autoCreateUsers,
    setAutoCreateUsers,
    form,
    setForm,
    showForm,
    setShowForm,
    loading,
    saving,
    deleting,
    feedback,
    savePolicy,
    addProvider,
    removeProvider,
    redirectUriFor,
  };
}
