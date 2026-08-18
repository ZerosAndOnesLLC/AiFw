"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { api, setAuthed } from "@/lib/api";
import { hardNavigate } from "@/lib/navigation";
import { fetchOAuthLoginOptions, startOAuthLogin, oauthErrorMessage, type OAuthLoginOption } from "@/lib/api/oauth";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [totpRequired, setTotpRequired] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  // OAuth / SSO (#170)
  const [oauthOptions, setOauthOptions] = useState<OAuthLoginOption[]>([]);
  const [oauthTicket, setOauthTicket] = useState<string | null>(null);
  const [oauthUser, setOauthUser] = useState("");

  useEffect(() => {
    // The provider callback bounces the browser back here with the outcome
    // in the query string (static UI, no server-side rendering). State
    // updates run from an async continuation so the effect body itself
    // stays side-effect free for the linter.
    const params = new URLSearchParams(window.location.search);
    (async () => {
      if (params.get("oauth") === "ok") {
        setAuthed(true);
        hardNavigate("/");
        return;
      }
      const oauthError = params.get("oauth_error");
      if (oauthError) setError(oauthErrorMessage(oauthError));
      const ticket = params.get("oauth_totp");
      if (ticket) {
        setOauthTicket(ticket);
        setOauthUser(params.get("user") || "");
        setTotpRequired(true);
        window.history.replaceState(null, "", window.location.pathname);
      }
      try {
        setOauthOptions(await fetchOAuthLoginOptions());
      } catch {
        /* no SSO configured or API unreachable — password form still works */
      }
    })();
  }, []);

  const handleOAuthStart = async (name: string) => {
    setError("");
    setLoading(true);
    try {
      await startOAuthLogin(name);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start single sign-on");
      setLoading(false);
    }
  };

  const inputClass = "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]";

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      // noAuthRedirect: a 401 here means bad credentials, not an expired
      // session — redirecting to /login would just loop.
      // On success the server installs the session as HttpOnly cookies
      // (SEC-M7 #304); the page only records the logged-in marker.
      const data = await api.post<{ tokens?: { access_token?: string }; totp_required?: boolean }>(
        "/api/v1/auth/login",
        { username, password },
        { noAuthRedirect: true },
      );
      if (data.tokens?.access_token) {
        setAuthed(true);
        hardNavigate("/");
      } else if (data.totp_required) {
        setTotpRequired(true);
      }
    } catch {
      setError("Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  const handleTotpLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      // Two TOTP entry points: after a password login (username+password
      // re-sent) or after an OAuth callback (single-use ticket, #170).
      const data = oauthTicket
        ? await api.post<{ access_token?: string }>(
            "/api/v1/auth/oauth/totp",
            { ticket: oauthTicket, totp_code: totpCode },
            { noAuthRedirect: true },
          )
        : await api.post<{ access_token?: string }>(
            "/api/v1/auth/totp/login",
            { username, password, totp_code: totpCode },
            { noAuthRedirect: true },
          );
      if (data.access_token) {
        setAuthed(true);
        hardNavigate("/");
      }
    } catch {
      setError(oauthTicket
        ? "Invalid code — or the sign-in ticket expired. Start single sign-on again."
        : "Invalid TOTP code or recovery code");
      if (oauthTicket) { setOauthTicket(null); setTotpRequired(false); }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <Image src="/AiFw-1.png" alt="AiFw" width={384} height={192} className="h-48 w-auto mx-auto mb-2" priority unoptimized />
        </div>

        {!totpRequired ? (
          <form onSubmit={handleLogin} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
            {error && (
              <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md">
                {error}
              </div>
            )}

            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
                className={inputClass} required autoFocus />
            </div>

            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                className={inputClass} required />
            </div>

            <button type="submit" disabled={loading}
              className="w-full py-2.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50">
              {loading ? "Signing in..." : "Sign In"}
            </button>

            {oauthOptions.length > 0 && (
              <div className="pt-2 space-y-2">
                <div className="flex items-center gap-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  <span className="flex-1 border-t border-[var(--border)]" />
                  or continue with
                  <span className="flex-1 border-t border-[var(--border)]" />
                </div>
                {oauthOptions.map((o) => (
                  <button key={o.name} type="button" disabled={loading} onClick={() => handleOAuthStart(o.name)}
                    className="w-full py-2 border border-[var(--border)] hover:border-[var(--accent)] rounded-md text-sm text-[var(--text-primary)] transition-colors disabled:opacity-50">
                    {o.name}
                  </button>
                ))}
              </div>
            )}
          </form>
        ) : (
          <form onSubmit={handleTotpLogin} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
            {error && (
              <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md">
                {error}
              </div>
            )}

            <div className="text-center text-sm text-[var(--text-secondary)] mb-2">
              {oauthTicket && oauthUser ? <span className="block text-xs text-[var(--text-muted)] mb-1">Signed in as {oauthUser} — second factor required.</span> : null}
              Enter the 6-digit code from your authenticator app, or a recovery code.
            </div>

            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">TOTP Code</label>
              <input type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass} required autoFocus autoComplete="one-time-code"
                placeholder="000000" maxLength={24} />
            </div>

            <button type="submit" disabled={loading}
              className="w-full py-2.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50">
              {loading ? "Verifying..." : "Verify"}
            </button>

            <button type="button" onClick={() => { setTotpRequired(false); setTotpCode(""); setError(""); setOauthTicket(null); }}
              className="w-full py-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] text-sm transition-colors">
              Back to login
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
