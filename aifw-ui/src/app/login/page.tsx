"use client";

import { useState } from "react";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [totpRequired, setTotpRequired] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const inputClass = "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]";

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) throw new Error("Invalid credentials");
      const data = await res.json();
      const token = data.tokens?.access_token;
      if (token) {
        localStorage.setItem("aifw_token", token);
        window.location.href = "/";
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
      const res = await fetch("/api/v1/auth/totp/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, totp_code: totpCode }),
      });
      if (!res.ok) throw new Error("Invalid code");
      const data = await res.json();
      const token = data.access_token;
      if (token) {
        localStorage.setItem("aifw_token", token);
        window.location.href = "/";
      }
    } catch {
      setError("Invalid TOTP code or recovery code");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-[var(--accent)] flex items-center justify-center font-bold text-white text-2xl mx-auto mb-4">
            AI
          </div>
          <h1 className="text-2xl font-bold">AiFw</h1>
          <p className="text-sm text-[var(--text-muted)]">AI-Powered Firewall for FreeBSD</p>
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
          </form>
        ) : (
          <form onSubmit={handleTotpLogin} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-4">
            {error && (
              <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md">
                {error}
              </div>
            )}

            <div className="text-center text-sm text-[var(--text-secondary)] mb-2">
              Enter the 6-digit code from your authenticator app, or a recovery code.
            </div>

            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">TOTP Code</label>
              <input type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)}
                className={inputClass} required autoFocus autoComplete="one-time-code"
                placeholder="000000" maxLength={20} />
            </div>

            <button type="submit" disabled={loading}
              className="w-full py-2.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50">
              {loading ? "Verifying..." : "Verify"}
            </button>

            <button type="button" onClick={() => { setTotpRequired(false); setTotpCode(""); setError(""); }}
              className="w-full py-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] text-sm transition-colors">
              Back to login
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
