"use client";

import { useEffect, useState } from "react";

interface UserProfile {
  id: string;
  username: string;
  totp_enabled: boolean;
  auth_provider: string;
  role: string;
  created_at: string;
}

interface TotpSetup {
  secret: string;
  provisioning_uri: string;
  recovery_codes: string[];
}

function authHeaders(): HeadersInit {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

export default function ProfilePage() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Password change
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);

  // TOTP setup
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [settingUpTotp, setSettingUpTotp] = useState(false);
  const [disablingTotp, setDisablingTotp] = useState(false);
  const [disableCode, setDisableCode] = useState("");
  const [showDisable, setShowDisable] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 5000);
  };

  // Get current user ID from JWT
  const getUserId = (): string | null => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return null;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      return payload.sub;
    } catch { return null; }
  };

  useEffect(() => {
    const userId = getUserId();
    if (!userId) return;
    fetch(`/api/v1/auth/users/${userId}`, { headers: authHeaders() })
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((d) => setUser(d.data))
      .catch(() => showFeedback("error", "Failed to load profile"))
      .finally(() => setLoading(false));
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      showFeedback("error", "Passwords do not match");
      return;
    }
    if (newPassword.length < 8) {
      showFeedback("error", "Password must be at least 8 characters");
      return;
    }
    setChangingPassword(true);
    try {
      // Verify current password by attempting login
      const loginRes = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user?.username, password: currentPassword }),
      });
      if (!loginRes.ok) {
        showFeedback("error", "Current password is incorrect");
        return;
      }

      const userId = getUserId();
      const res = await fetch(`/api/v1/auth/users/${userId}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ password: newPassword }),
      });
      if (!res.ok) throw new Error();
      showFeedback("success", "Password changed successfully");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch {
      showFeedback("error", "Failed to change password");
    } finally {
      setChangingPassword(false);
    }
  };

  const handleSetupTotp = async () => {
    setSettingUpTotp(true);
    try {
      const res = await fetch("/api/v1/auth/totp/setup", {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      setTotpSetup(data);
      setRecoveryCodes(data.recovery_codes);
    } catch {
      showFeedback("error", "Failed to start TOTP setup");
    } finally {
      setSettingUpTotp(false);
    }
  };

  const handleVerifyTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/v1/auth/totp/verify", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ code: totpCode }),
      });
      if (!res.ok) throw new Error();
      showFeedback("success", "MFA enabled successfully");
      setTotpSetup(null);
      setTotpCode("");
      if (user) setUser({ ...user, totp_enabled: true });
    } catch {
      showFeedback("error", "Invalid TOTP code. Check your authenticator app.");
    }
  };

  const handleDisableTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    setDisablingTotp(true);
    try {
      const res = await fetch("/api/v1/auth/totp/disable", {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ code: disableCode }),
      });
      if (!res.ok) throw new Error();
      showFeedback("success", "MFA disabled");
      setShowDisable(false);
      setDisableCode("");
      setRecoveryCodes(null);
      if (user) setUser({ ...user, totp_enabled: false });
    } catch {
      showFeedback("error", "Invalid code");
    } finally {
      setDisablingTotp(false);
    }
  };

  const inputClass = "w-full px-3 py-2 text-sm bg-gray-900 border border-gray-700 rounded-md text-white focus:outline-none focus:border-blue-500";

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold">My Profile</h1>
        <p className="text-sm text-[var(--text-muted)]">Manage your account, password, and multi-factor authentication</p>
      </div>

      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success" ? "bg-green-500/10 border-green-500/30 text-green-400" : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>
          {feedback.msg}
        </div>
      )}

      {/* Account Info */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Account</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-[var(--text-muted)] text-xs uppercase tracking-wider">Username</span>
            <p className="font-mono mt-1">{user?.username}</p>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs uppercase tracking-wider">Role</span>
            <p className="mt-1">
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                user?.role === "admin" ? "bg-red-500/20 text-red-400" :
                user?.role === "operator" ? "bg-blue-500/20 text-blue-400" :
                "bg-gray-500/20 text-gray-400"
              }`}>{user?.role}</span>
            </p>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs uppercase tracking-wider">Auth Provider</span>
            <p className="mt-1">{user?.auth_provider}</p>
          </div>
          <div>
            <span className="text-[var(--text-muted)] text-xs uppercase tracking-wider">Created</span>
            <p className="mt-1">{user?.created_at ? new Date(user.created_at).toLocaleDateString() : "-"}</p>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Change Password</h2>
        <form onSubmit={handleChangePassword} className="space-y-3 max-w-sm">
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Current Password</label>
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
              className={inputClass} required />
          </div>
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">New Password</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
              className={inputClass} required minLength={8} />
          </div>
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Confirm New Password</label>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
              className={inputClass} required />
          </div>
          <button type="submit" disabled={changingPassword}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50">
            {changingPassword ? "Changing..." : "Change Password"}
          </button>
        </form>
      </div>

      {/* Multi-Factor Authentication */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Multi-Factor Authentication</h2>
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            user?.totp_enabled ? "bg-green-500/20 text-green-400" : "bg-yellow-500/20 text-yellow-400"
          }`}>
            {user?.totp_enabled ? "Enabled" : "Disabled"}
          </span>
        </div>

        {!user?.totp_enabled && !totpSetup && (
          <div>
            <p className="text-sm text-[var(--text-secondary)] mb-3">
              Add an extra layer of security with a TOTP authenticator app (Google Authenticator, Authy, 1Password, etc.)
            </p>
            <button onClick={handleSetupTotp} disabled={settingUpTotp}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50">
              {settingUpTotp ? "Setting up..." : "Enable MFA"}
            </button>
          </div>
        )}

        {totpSetup && !user?.totp_enabled && (
          <div className="space-y-4">
            <p className="text-sm text-[var(--text-secondary)]">
              Scan this QR code with your authenticator app, or enter the secret key manually:
            </p>

            <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 space-y-3">
              <div>
                <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">Secret Key</span>
                <p className="font-mono text-sm mt-1 select-all text-cyan-400">{totpSetup.secret}</p>
              </div>
              <div>
                <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">Provisioning URI</span>
                <p className="font-mono text-xs mt-1 break-all text-[var(--text-secondary)]">{totpSetup.provisioning_uri}</p>
              </div>
            </div>

            {recoveryCodes && (
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <p className="text-sm font-semibold text-yellow-400 mb-2">Save your recovery codes</p>
                <p className="text-xs text-[var(--text-secondary)] mb-3">These are shown only once. Store them somewhere safe.</p>
                <div className="grid grid-cols-2 gap-1">
                  {recoveryCodes.map((code, i) => (
                    <code key={i} className="text-xs font-mono text-yellow-300 bg-gray-900 px-2 py-1 rounded">{code}</code>
                  ))}
                </div>
              </div>
            )}

            <form onSubmit={handleVerifyTotp} className="flex gap-2 items-end">
              <div className="flex-1">
                <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Enter code from app to verify</label>
                <input type="text" value={totpCode} onChange={(e) => setTotpCode(e.target.value)}
                  className={inputClass} placeholder="000000" maxLength={6} required autoFocus />
              </div>
              <button type="submit" className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md">
                Verify & Enable
              </button>
              <button type="button" onClick={() => { setTotpSetup(null); setTotpCode(""); }}
                className="px-4 py-2 text-[var(--text-muted)] hover:text-white text-sm">
                Cancel
              </button>
            </form>
          </div>
        )}

        {user?.totp_enabled && !showDisable && (
          <div>
            <p className="text-sm text-[var(--text-secondary)] mb-3">
              MFA is active. You&apos;ll need your authenticator app code to sign in.
            </p>
            <button onClick={() => setShowDisable(true)}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md">
              Disable MFA
            </button>
          </div>
        )}

        {user?.totp_enabled && showDisable && (
          <form onSubmit={handleDisableTotp} className="space-y-3 max-w-sm">
            <p className="text-sm text-[var(--text-secondary)]">
              Enter your current TOTP code to disable MFA:
            </p>
            <input type="text" value={disableCode} onChange={(e) => setDisableCode(e.target.value)}
              className={inputClass} placeholder="000000" maxLength={6} required autoFocus />
            <div className="flex gap-2">
              <button type="submit" disabled={disablingTotp}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50">
                {disablingTotp ? "Disabling..." : "Confirm Disable"}
              </button>
              <button type="button" onClick={() => { setShowDisable(false); setDisableCode(""); }}
                className="px-4 py-2 text-[var(--text-muted)] hover:text-white text-sm">
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
