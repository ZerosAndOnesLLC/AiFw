"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/context/AuthContext";
import { PERMISSION_CATEGORIES } from "@/lib/permissions";

const API = "";

interface User {
  id: string;
  username: string;
  totp_enabled: boolean;
  auth_provider: string;
  role: string;
  enabled: boolean;
  created_at: string;
}

interface AuditEntry {
  id: string;
  user_id: string | null;
  actor_id: string;
  action: string;
  details: string | null;
  ip_addr: string | null;
  created_at: string;
}

interface Feedback {
  type: "success" | "error";
  message: string;
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

function getCurrentUserId(): string | null {
  const token = localStorage.getItem("aifw_token");
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.sub || payload.user_id || null;
  } catch {
    return null;
  }
}

function roleBadge(role: string) {
  const colors: Record<string, string> = {
    admin: "bg-red-500/20 text-red-400 border-red-500/30",
    operator: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    viewer: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  const cls = colors[role] || colors.viewer;
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${cls}`}>
      {role}
    </span>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  // Add user form
  const [showAddForm, setShowAddForm] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const [adding, setAdding] = useState(false);

  // Edit user
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editRole, setEditRole] = useState("");
  const [editEnabled, setEditEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  // Delete confirmation
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Audit log
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditOpen, setAuditOpen] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);

  // Tabs
  const [activeTab, setActiveTab] = useState<"users" | "roles">("users");

  // Roles
  const [roles, setRoles] = useState<{ id: string; name: string; permissions: string[]; builtin: boolean; description: string | null }[]>([]);
  const [showRoleForm, setShowRoleForm] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDesc, setNewRoleDesc] = useState("");
  const [newRolePerms, setNewRolePerms] = useState<Set<string>>(new Set());
  const [roleSaving, setRoleSaving] = useState(false);
  const [deletingRoleId, setDeletingRoleId] = useState<string | null>(null);

  const { permissions: myPerms } = useAuth();
  const canWriteUsers = myPerms.has("users:write");

  const currentUserId = getCurrentUserId();

  const setFeedbackWithTimeout = useCallback((fb: Feedback) => {
    setFeedback(fb);
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/auth/users`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setUsers(data.data || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to load users: ${msg}` });
    } finally {
      setLoading(false);
    }
  }, [setFeedbackWithTimeout]);

  const fetchAudit = useCallback(async () => {
    setAuditLoading(true);
    try {
      const res = await fetch(`${API}/api/v1/auth/audit`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAuditEntries(data.data || []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to load audit log: ${msg}` });
    } finally {
      setAuditLoading(false);
    }
  }, [setFeedbackWithTimeout]);

  const fetchRoles = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/auth/roles`, { headers: authHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      setRoles(data.roles || []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchUsers();
    fetchRoles();
  }, [fetchUsers, fetchRoles]);

  // Add user
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    setAdding(true);
    try {
      const res = await fetch(`${API}/api/v1/auth/users`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ username: newUsername.trim(), password: newPassword, role: newRole }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      setFeedbackWithTimeout({ type: "success", message: `User "${newUsername.trim()}" created.` });
      setNewUsername("");
      setNewPassword("");
      setNewRole("viewer");
      setShowAddForm(false);
      await fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to create user: ${msg}` });
    } finally {
      setAdding(false);
    }
  };

  // Start editing
  const startEdit = (user: User) => {
    setEditingId(user.id);
    setEditUsername(user.username);
    setEditPassword("");
    setEditRole(user.role);
    setEditEnabled(user.enabled);
  };

  const cancelEdit = () => {
    setEditingId(null);
  };

  // Save edit
  const handleSaveEdit = async () => {
    if (!editingId || !editUsername.trim()) return;
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        username: editUsername.trim(),
        role: editRole,
        enabled: editEnabled,
      };
      if (editPassword.trim()) {
        body.password = editPassword;
      }
      const res = await fetch(`${API}/api/v1/auth/users/${editingId}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || data.message || `HTTP ${res.status}`);
      }
      setFeedbackWithTimeout({ type: "success", message: "User updated." });
      setEditingId(null);
      await fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to update user: ${msg}` });
    } finally {
      setSaving(false);
    }
  };

  // Toggle enabled
  const handleToggleEnabled = async (user: User) => {
    try {
      const res = await fetch(`${API}/api/v1/auth/users/${user.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ enabled: !user.enabled }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout({
        type: "success",
        message: `User "${user.username}" ${!user.enabled ? "enabled" : "disabled"}.`,
      });
      await fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to toggle user: ${msg}` });
    }
  };

  // Delete user
  const handleDelete = async (user: User) => {
    try {
      const res = await fetch(`${API}/api/v1/auth/users/${user.id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout({ type: "success", message: `User "${user.username}" deleted.` });
      setDeletingId(null);
      await fetchUsers();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout({ type: "error", message: `Failed to delete user: ${msg}` });
    }
  };

  // Toggle audit panel
  const toggleAudit = () => {
    const next = !auditOpen;
    setAuditOpen(next);
    if (next && auditEntries.length === 0) {
      fetchAudit();
    }
  };

  const inputCls =
    "w-full px-3 py-2 text-sm bg-gray-900 border border-gray-700 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-blue-500";
  const labelCls = "text-xs text-gray-400 uppercase tracking-wider block mb-1";
  const sectionCls = "bg-gray-800 border border-gray-700 rounded-lg p-5";
  const btnPrimary =
    "px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const btnDanger =
    "px-3 py-1.5 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 rounded-md text-sm transition-colors";
  const btnSecondary =
    "px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-md text-sm transition-colors";

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-sm text-gray-400">Manage users, roles, and permissions</p>
        </div>
        {activeTab === "users" && canWriteUsers && (
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className={btnPrimary}
          >
            {showAddForm ? "Cancel" : "+ Add User"}
          </button>
        )}
        {activeTab === "roles" && canWriteUsers && (
          <button
            onClick={() => { setShowRoleForm(!showRoleForm); setNewRoleName(""); setNewRoleDesc(""); setNewRolePerms(new Set()); }}
            className={btnPrimary}
          >
            {showRoleForm ? "Cancel" : "+ Create Role"}
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[var(--bg-primary)] rounded-lg p-1 border border-[var(--border)] w-fit">
        {(["users", "roles"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all capitalize ${
              activeTab === tab
                ? "bg-[var(--accent)] text-white"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Feedback banner (shared) */}
      {feedback && (
        <div
          className={`p-3 text-sm rounded-md border ${
            feedback.type === "error"
              ? "text-red-400 bg-red-500/10 border-red-500/20"
              : "text-green-400 bg-green-500/10 border-green-500/20"
          }`}
        >
          {feedback.message}
        </div>
      )}

      {activeTab === "users" && (<>
      {/* Add user form */}
      {showAddForm && (
        <section className={sectionCls}>
          <h2 className="font-medium text-white mb-4">New User</h2>
          <form onSubmit={handleAddUser} className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className={labelCls}>Username</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="Username"
                  className={inputCls}
                  required
                  autoFocus
                />
              </div>
              <div>
                <label className={labelCls}>Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Password"
                  className={inputCls}
                  required
                />
              </div>
              <div>
                <label className={labelCls}>Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className={inputCls}
                >
                  {roles.map((r) => (
                    <option key={r.id} value={r.name}>{r.name}{r.builtin ? "" : " (custom)"}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex justify-end">
              <button type="submit" disabled={adding} className={btnPrimary}>
                {adding ? "Creating..." : "Create User"}
              </button>
            </div>
          </form>
        </section>
      )}

      {/* Users table */}
      <section className={sectionCls + " p-0 overflow-hidden"}>
        {loading ? (
          <div className="p-8 text-center text-gray-400">Loading users...</div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center text-gray-400">No users found.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-left text-xs text-gray-400 uppercase tracking-wider">
                <th className="px-5 py-3">Username</th>
                <th className="px-5 py-3">Role</th>
                <th className="px-5 py-3">MFA</th>
                <th className="px-5 py-3">Provider</th>
                <th className="px-5 py-3">Enabled</th>
                <th className="px-5 py-3">Created</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                  {editingId === user.id ? (
                    /* Inline edit row */
                    <>
                      <td className="px-5 py-3">
                        <input
                          type="text"
                          value={editUsername}
                          onChange={(e) => setEditUsername(e.target.value)}
                          className="w-full px-2 py-1 text-sm bg-gray-900 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                        />
                      </td>
                      <td className="px-5 py-3">
                        <select
                          value={editRole}
                          onChange={(e) => setEditRole(e.target.value)}
                          className="px-2 py-1 text-sm bg-gray-900 border border-gray-600 rounded text-white focus:outline-none focus:border-blue-500"
                        >
                          {roles.map((r) => (
                            <option key={r.id} value={r.name}>{r.name}{r.builtin ? "" : " (custom)"}</option>
                          ))}
                        </select>
                      </td>
                      <td className="px-5 py-3 text-gray-400">
                        {user.totp_enabled ? "On" : "Off"}
                      </td>
                      <td className="px-5 py-3">
                        <input
                          type="password"
                          value={editPassword}
                          onChange={(e) => setEditPassword(e.target.value)}
                          placeholder="(unchanged)"
                          className="w-full px-2 py-1 text-sm bg-gray-900 border border-gray-600 rounded text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                        />
                      </td>
                      <td className="px-5 py-3">
                        <button
                          onClick={() => setEditEnabled(!editEnabled)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                            editEnabled ? "bg-green-600" : "bg-gray-600"
                          }`}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              editEnabled ? "translate-x-4" : "translate-x-0.5"
                            }`}
                          />
                        </button>
                      </td>
                      <td className="px-5 py-3 text-gray-400 text-xs">
                        {formatDate(user.created_at)}
                      </td>
                      <td className="px-5 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={handleSaveEdit}
                            disabled={saving}
                            className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/40 text-green-400 border border-green-500/30 rounded-md text-sm transition-colors disabled:opacity-50"
                          >
                            {saving ? "Saving..." : "Save"}
                          </button>
                          <button onClick={cancelEdit} className={btnSecondary}>
                            Cancel
                          </button>
                        </div>
                      </td>
                    </>
                  ) : (
                    /* Display row */
                    <>
                      <td className="px-5 py-3 font-medium text-white">{user.username}</td>
                      <td className="px-5 py-3">{roleBadge(user.role)}</td>
                      <td className="px-5 py-3">
                        {user.totp_enabled ? (
                          <span className="text-green-400 text-xs font-medium">Enabled</span>
                        ) : (
                          <span className="text-gray-500 text-xs">Disabled</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-gray-400">{user.auth_provider}</td>
                      <td className="px-5 py-3">
                        <button
                          onClick={() => handleToggleEnabled(user)}
                          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                            user.enabled ? "bg-green-600" : "bg-gray-600"
                          }`}
                          title={user.enabled ? "Disable user" : "Enable user"}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                              user.enabled ? "translate-x-4" : "translate-x-0.5"
                            }`}
                          />
                        </button>
                      </td>
                      <td className="px-5 py-3 text-gray-400 text-xs">{formatDate(user.created_at)}</td>
                      <td className="px-5 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button onClick={() => startEdit(user)} className={btnSecondary}>
                            Edit
                          </button>
                          {currentUserId === user.id ? (
                            <span className="px-3 py-1.5 text-gray-600 text-sm cursor-not-allowed" title="Cannot delete yourself">
                              Delete
                            </span>
                          ) : deletingId === user.id ? (
                            <div className="flex items-center gap-1">
                              <button onClick={() => handleDelete(user)} className={btnDanger}>
                                Confirm
                              </button>
                              <button onClick={() => setDeletingId(null)} className={btnSecondary}>
                                No
                              </button>
                            </div>
                          ) : (
                            <button onClick={() => setDeletingId(user.id)} className={btnDanger}>
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Audit Log */}
      <section className={sectionCls}>
        <button
          onClick={toggleAudit}
          className="w-full flex items-center justify-between text-left"
        >
          <h2 className="font-medium text-white">Audit Log</h2>
          <svg
            className={`w-5 h-5 text-gray-400 transition-transform ${auditOpen ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {auditOpen && (
          <div className="mt-4">
            {auditLoading ? (
              <p className="text-sm text-gray-400">Loading audit log...</p>
            ) : auditEntries.length === 0 ? (
              <p className="text-sm text-gray-400">No audit entries found.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700 text-left text-xs text-gray-400 uppercase tracking-wider">
                      <th className="px-4 py-2">Time</th>
                      <th className="px-4 py-2">Action</th>
                      <th className="px-4 py-2">Actor</th>
                      <th className="px-4 py-2">Target User</th>
                      <th className="px-4 py-2">IP Address</th>
                      <th className="px-4 py-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.map((entry) => {
                      const actionColors: Record<string, string> = {
                        login_success: "text-green-400",
                        login_failed: "text-red-400",
                        user_created: "text-blue-400",
                        user_updated: "text-yellow-400",
                        user_deleted: "text-red-400",
                      };
                      const color = actionColors[entry.action] || "text-gray-400";
                      return (
                        <tr key={entry.id} className="border-b border-gray-700/50">
                          <td className="px-4 py-2 text-gray-400 text-xs whitespace-nowrap">
                            {formatDate(entry.created_at)}
                          </td>
                          <td className={`px-4 py-2 font-mono text-xs ${color}`}>
                            {entry.action}
                          </td>
                          <td className="px-4 py-2 text-gray-300 text-xs font-mono">
                            {entry.actor_id}
                          </td>
                          <td className="px-4 py-2 text-gray-400 text-xs font-mono">
                            {entry.user_id || "-"}
                          </td>
                          <td className="px-4 py-2 text-gray-400 text-xs font-mono">
                            {entry.ip_addr || "-"}
                          </td>
                          <td className="px-4 py-2 text-gray-500 text-xs max-w-xs truncate">
                            {entry.details || "-"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>
      </>)}

      {/* Roles Tab */}
      {activeTab === "roles" && (<>
        {/* Create Role Form */}
        {showRoleForm && canWriteUsers && (
          <section className={sectionCls}>
            <h2 className="font-medium text-white mb-4">Create Custom Role</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Role Name</label>
                  <input
                    type="text"
                    value={newRoleName}
                    onChange={(e) => setNewRoleName(e.target.value)}
                    placeholder="e.g. network-engineer"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Description</label>
                  <input
                    type="text"
                    value={newRoleDesc}
                    onChange={(e) => setNewRoleDesc(e.target.value)}
                    placeholder="Optional description"
                    className={inputCls}
                  />
                </div>
              </div>

              <div>
                <label className={labelCls}>Permissions</label>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mt-2">
                  {PERMISSION_CATEGORIES.map((cat) => (
                    <div key={cat.label} className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md p-3">
                      <p className="text-xs font-medium text-[var(--text-primary)] mb-2">{cat.label}</p>
                      <div className="space-y-1">
                        {cat.perms.map((perm) => (
                          <label key={perm} className="flex items-center gap-2 text-xs cursor-pointer">
                            <input
                              type="checkbox"
                              checked={newRolePerms.has(perm)}
                              onChange={(e) => {
                                const next = new Set(newRolePerms);
                                e.target.checked ? next.add(perm) : next.delete(perm);
                                setNewRolePerms(next);
                              }}
                              className="rounded border-[var(--border)]"
                            />
                            <span className="text-[var(--text-secondary)] font-mono">{perm}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={async () => {
                    if (!newRoleName.trim()) return;
                    setRoleSaving(true);
                    try {
                      const res = await fetch(`${API}/api/v1/auth/roles`, {
                        method: "POST",
                        headers: authHeaders(),
                        body: JSON.stringify({
                          name: newRoleName.trim(),
                          permissions: Array.from(newRolePerms),
                          description: newRoleDesc.trim() || null,
                        }),
                      });
                      if (!res.ok) throw new Error(`HTTP ${res.status}`);
                      setFeedbackWithTimeout({ type: "success", message: `Role "${newRoleName.trim()}" created` });
                      setShowRoleForm(false);
                      setNewRoleName("");
                      setNewRoleDesc("");
                      setNewRolePerms(new Set());
                      await fetchRoles();
                    } catch (err: unknown) {
                      const msg = err instanceof Error ? err.message : "Unknown error";
                      setFeedbackWithTimeout({ type: "error", message: `Failed to create role: ${msg}` });
                    } finally {
                      setRoleSaving(false);
                    }
                  }}
                  disabled={roleSaving || !newRoleName.trim()}
                  className={btnPrimary}
                >
                  {roleSaving ? "Creating..." : "Create Role"}
                </button>
              </div>
            </div>
          </section>
        )}

        {/* Roles List */}
        <div className="space-y-4">
          {roles.map((role) => (
            <section key={role.id} className={sectionCls}>
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-medium text-white">{role.name}</h3>
                    {role.builtin && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-500/20 text-gray-400 border border-gray-500/30">built-in</span>
                    )}
                    {roleBadge(role.name)}
                  </div>
                  {role.description && (
                    <p className="text-xs text-gray-400 mt-0.5">{role.description}</p>
                  )}
                </div>
                {!role.builtin && canWriteUsers && (
                  <button
                    onClick={async () => {
                      if (!confirm(`Delete role "${role.name}"?`)) return;
                      setDeletingRoleId(role.id);
                      try {
                        const res = await fetch(`${API}/api/v1/auth/roles/${role.id}`, {
                          method: "DELETE",
                          headers: authHeaders(),
                        });
                        if (!res.ok) {
                          const body = await res.json().catch(() => ({}));
                          throw new Error(body.message || `HTTP ${res.status}`);
                        }
                        setFeedbackWithTimeout({ type: "success", message: `Role "${role.name}" deleted` });
                        await fetchRoles();
                      } catch (err: unknown) {
                        const msg = err instanceof Error ? err.message : "Unknown error";
                        setFeedbackWithTimeout({ type: "error", message: `Delete failed: ${msg}` });
                      } finally {
                        setDeletingRoleId(null);
                      }
                    }}
                    disabled={deletingRoleId === role.id}
                    className="text-xs text-gray-400 hover:text-red-400 transition-colors"
                  >
                    {deletingRoleId === role.id ? "Deleting..." : "Delete"}
                  </button>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {role.permissions.map((perm) => (
                  <span
                    key={perm}
                    className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-secondary)] font-mono"
                  >
                    {perm}
                  </span>
                ))}
                {role.permissions.length === 0 && (
                  <span className="text-xs text-gray-500">No permissions</span>
                )}
              </div>
            </section>
          ))}
        </div>
      </>)}
    </div>
  );
}
