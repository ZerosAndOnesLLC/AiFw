"use client";

import { Feedback } from "@/hooks/useFeedback";
import type { OAuthProvider } from "@/lib/api/oauth";
import type { ProviderForm } from "@/hooks/useSsoSettings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

export interface SsoSectionProps {
  visible: boolean;
  providers: OAuthProvider[];
  publicUrl: string;
  setPublicUrl: (v: string) => void;
  requireTotpForOauth: boolean;
  setRequireTotpForOauth: (v: boolean) => void;
  autoCreateUsers: boolean;
  setAutoCreateUsers: (v: boolean) => void;
  form: ProviderForm;
  setForm: (f: ProviderForm) => void;
  showForm: boolean;
  setShowForm: (v: boolean) => void;
  loading: boolean;
  saving: boolean;
  deleting: string | null;
  feedback: Feedback | null;
  savePolicy: () => void;
  addProvider: () => void;
  removeProvider: (p: OAuthProvider) => void;
  redirectUriFor: (name: string) => string;
}

const TYPE_LABEL: Record<string, string> = { google: "Google", github: "GitHub", oidc: "Generic OIDC" };

export function SsoSection({
  visible, providers, publicUrl, setPublicUrl, requireTotpForOauth, setRequireTotpForOauth,
  autoCreateUsers, setAutoCreateUsers, form, setForm, showForm, setShowForm, loading, saving,
  deleting, feedback, savePolicy, addProvider, removeProvider, redirectUriFor,
}: SsoSectionProps) {
  const set = <K extends keyof ProviderForm>(k: K, v: ProviderForm[K]) => setForm({ ...form, [k]: v });
  const formValid =
    form.name.trim() && form.client_id.trim() && form.client_secret &&
    (form.provider_type !== "oidc" || (form.auth_url.trim() && form.token_url.trim() && form.userinfo_url.trim()));

  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-1">
        <h2 className="font-medium">Single Sign-On (OAuth / OIDC)</h2>
      </div>
      <p className="text-xs text-[var(--text-muted)] mb-4">
        Let users sign in with Google, GitHub or any OpenID Connect provider (Okta, Auth0, Keycloak, Entra ID…).
        The first sign-in links the provider identity to a local account: a <em>verified</em> email that matches an
        existing username links that account; otherwise, if enabled below, a new <strong>viewer</strong> account is
        created — promote it under Users. Register the redirect URI shown for each provider at the identity provider.
      </p>
      <FeedbackBanner feedback={feedback} />
      {loading ? (
        <p className="text-sm text-[var(--text-muted)]">Loading…</p>
      ) : (
        <div className="space-y-5">
          {/* Providers */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-medium">Providers</h3>
              <button type="button" onClick={() => setShowForm(!showForm)}
                className="px-3 py-1.5 text-xs rounded border border-[var(--border)] hover:border-[var(--accent)]">
                {showForm ? "Cancel" : "Add provider"}
              </button>
            </div>
            {providers.length === 0 && !showForm && (
              <p className="text-sm text-[var(--text-muted)]">No providers configured — the sign-in page shows only the password form.</p>
            )}
            {providers.length > 0 && (
              <div className="overflow-x-auto rounded-md border border-[var(--border)]">
                <table className="w-full text-sm">
                  <thead className="bg-[var(--bg-primary)] text-xs uppercase tracking-wider text-[var(--text-muted)]">
                    <tr>
                      <th className="text-left px-3 py-2">Name</th>
                      <th className="text-left px-3 py-2">Type</th>
                      <th className="text-left px-3 py-2">Client ID</th>
                      <th className="text-left px-3 py-2">Redirect URI (register at provider)</th>
                      <th className="px-3 py-2" />
                    </tr>
                  </thead>
                  <tbody>
                    {providers.map((p) => (
                      <tr key={p.id} className="border-t border-[var(--border)]">
                        <td className="px-3 py-2 font-medium">{p.name}</td>
                        <td className="px-3 py-2 text-[var(--text-secondary)]">{TYPE_LABEL[p.provider_type] ?? p.provider_type}</td>
                        <td className="px-3 py-2 font-mono text-xs truncate max-w-[14rem]" title={p.client_id}>{p.client_id}</td>
                        <td className="px-3 py-2 font-mono text-[11px] break-all">{redirectUriFor(p.name)}</td>
                        <td className="px-3 py-2 text-right">
                          <button type="button" onClick={() => removeProvider(p)} disabled={deleting === p.id}
                            className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50">
                            {deleting === p.id ? "Removing…" : "Remove"}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {showForm && (
              <div className="mt-3 rounded-md border border-[var(--border)] bg-[var(--bg-primary)] p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Display name</label>
                  <input type="text" value={form.name} onChange={(e) => set("name", e.target.value)} className={inputCls} placeholder="e.g. Google Workspace" />
                  <p className="mt-1 text-[11px] text-[var(--text-muted)]">Shown on the sign-in button and used in the redirect URI.</p>
                </div>
                <div>
                  <label className={labelCls}>Type</label>
                  <select value={form.provider_type} onChange={(e) => set("provider_type", e.target.value as ProviderForm["provider_type"])} className={inputCls}>
                    <option value="google">Google</option>
                    <option value="github">GitHub</option>
                    <option value="oidc">Generic OIDC</option>
                  </select>
                </div>
                <div>
                  <label className={labelCls}>Client ID</label>
                  <input type="text" value={form.client_id} onChange={(e) => set("client_id", e.target.value)} className={inputCls} />
                </div>
                <div>
                  <label className={labelCls}>Client secret</label>
                  <input type="password" autoComplete="new-password" value={form.client_secret} onChange={(e) => set("client_secret", e.target.value)} className={inputCls} />
                </div>
                {form.provider_type === "oidc" && (
                  <>
                    <div className="md:col-span-2">
                      <label className={labelCls}>Authorization endpoint</label>
                      <input type="url" value={form.auth_url} onChange={(e) => set("auth_url", e.target.value)} className={inputCls} placeholder="https://idp.example.com/oauth2/v1/authorize" />
                    </div>
                    <div>
                      <label className={labelCls}>Token endpoint</label>
                      <input type="url" value={form.token_url} onChange={(e) => set("token_url", e.target.value)} className={inputCls} placeholder="https://idp.example.com/oauth2/v1/token" />
                    </div>
                    <div>
                      <label className={labelCls}>Userinfo endpoint</label>
                      <input type="url" value={form.userinfo_url} onChange={(e) => set("userinfo_url", e.target.value)} className={inputCls} placeholder="https://idp.example.com/oauth2/v1/userinfo" />
                    </div>
                  </>
                )}
                <div className="md:col-span-2">
                  <label className={labelCls}>Scopes <span className="normal-case">(optional)</span></label>
                  <input type="text" value={form.scopes} onChange={(e) => set("scopes", e.target.value)} className={inputCls}
                    placeholder={form.provider_type === "github" ? "read:user user:email" : "openid email profile"} />
                </div>
                <div className="md:col-span-2 flex items-center gap-3">
                  <button type="button" onClick={addProvider} disabled={saving || !formValid} className={saveBtnCls}>
                    {saving ? "Adding…" : "Add provider"}
                  </button>
                  {form.name.trim() && (
                    <span className="text-[11px] text-[var(--text-muted)] font-mono break-all">Redirect URI: {redirectUriFor(form.name.trim())}</span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Policy */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-[var(--border)]">
            <div className="md:col-span-2">
              <label className={labelCls}>Public URL (for the redirect URI)</label>
              <input type="url" value={publicUrl} onChange={(e) => setPublicUrl(e.target.value)} className={inputCls}
                placeholder="https://firewall.example.com:8080 — leave empty to use the address in the browser" />
              <p className="mt-1 text-[11px] text-[var(--text-muted)]">
                Set this when the appliance sits behind a reverse proxy or is reached under a name different from the request Host.
              </p>
            </div>
            <label className="flex items-start gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={autoCreateUsers} onChange={(e) => setAutoCreateUsers(e.target.checked)} className="mt-0.5" />
              <span>
                Auto-create accounts on first sign-in
                <span className="block text-[11px] text-[var(--text-muted)]">New identities become <strong>viewer</strong> accounts. Off ⇒ only pre-linked accounts (or a verified email matching an existing username) can sign in.</span>
              </span>
            </label>
            <label className="flex items-start gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={requireTotpForOauth} onChange={(e) => setRequireTotpForOauth(e.target.checked)} className="mt-0.5" />
              <span>
                Require TOTP after single sign-on
                <span className="block text-[11px] text-[var(--text-muted)]">Accounts with TOTP enrolled must also enter their code. Off ⇒ the identity provider is trusted for MFA.</span>
              </span>
            </label>
            <div className="md:col-span-2">
              <button type="button" onClick={savePolicy} disabled={saving} className={saveBtnCls}>
                {saving ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
