"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useAuth } from "@/context/AuthContext";
import { PERMISSION_CATEGORIES } from "@/lib/permissions";

const API = "";

interface User {
  id: string;
  username: string;
  totp_enabled: boolean;
  auth_provider: string;
  role: string;
  role_id?: string;
  enabled: boolean;
  created_at: string;
}

interface Role {
  id: string;
  name: string;
  permissions: string[];
  builtin: boolean;
  description: string | null;
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
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function getCurrentUserId(): string | null {
  const token = localStorage.getItem("aifw_token");
  if (!token) return null;
  try {
    let b64 = token.split(".")[1];
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const payload = JSON.parse(atob(b64));
    return payload.sub || null;
  } catch { return null; }
}

const roleColors: Record<string, { badge: string; accent: string }> = {
  admin: { badge: "bg-red-500/20 text-red-400 border-red-500/30", accent: "border-red-500/40" },
  operator: { badge: "bg-blue-500/20 text-blue-400 border-blue-500/30", accent: "border-blue-500/40" },
  viewer: { badge: "bg-gray-500/20 text-gray-400 border-gray-500/30", accent: "border-gray-500/40" },
};
const customRoleStyle = { badge: "bg-purple-500/20 text-purple-400 border-purple-500/30", accent: "border-purple-500/40" };

function getRoleStyle(name: string, builtin: boolean) {
  if (builtin) return roleColors[name] || customRoleStyle;
  return customRoleStyle;
}

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

// ── Permission matrix grid ──────────────────────────────────────────
function PermissionGrid({ permissions, onChange, readonly }: {
  permissions: Set<string>;
  onChange?: (perms: Set<string>) => void;
  readonly?: boolean;
}) {
  const togglePerm = (perm: string) => {
    if (readonly || !onChange) return;
    const next = new Set(permissions);
    next.has(perm) ? next.delete(perm) : next.add(perm);
    onChange(next);
  };

  const toggleCategory = (cat: typeof PERMISSION_CATEGORIES[number]) => {
    if (readonly || !onChange) return;
    const allOn = cat.perms.every(p => permissions.has(p));
    const next = new Set(permissions);
    cat.perms.forEach(p => allOn ? next.delete(p) : next.add(p));
    onChange(next);
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[var(--border)]">
            <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase tracking-wider text-[10px] w-40">Category</th>
            <th className="text-center py-2 px-2 text-[var(--text-muted)] uppercase tracking-wider text-[10px]">Read / View</th>
            <th className="text-center py-2 px-2 text-[var(--text-muted)] uppercase tracking-wider text-[10px]">Write / Manage</th>
          </tr>
        </thead>
        <tbody>
          {PERMISSION_CATEGORIES.map(cat => {
            const readPerm = cat.perms.find(p => p.endsWith(":read") || p.endsWith(":view"));
            const writePerm = cat.perms.find(p => p.endsWith(":write") || p.endsWith(":install") || p.endsWith(":reboot"));
            const allOn = cat.perms.every(p => permissions.has(p));
            const someOn = cat.perms.some(p => permissions.has(p));

            return (
              <tr key={cat.label} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                <td className="py-2 px-3">
                  <button
                    onClick={() => toggleCategory(cat)}
                    disabled={readonly}
                    className={`flex items-center gap-2 ${readonly ? "cursor-default" : "cursor-pointer"}`}
                  >
                    <div className={`w-2 h-2 rounded-sm flex-shrink-0 ${
                      allOn ? "bg-green-500" : someOn ? "bg-yellow-500" : "bg-gray-600"
                    }`} />
                    <span className="font-medium text-[var(--text-primary)]">{cat.label}</span>
                  </button>
                </td>
                {readPerm ? (
                  <td className="text-center py-2 px-2">
                    <button
                      onClick={() => togglePerm(readPerm)}
                      disabled={readonly}
                      className={`inline-flex items-center justify-center w-7 h-7 rounded-md transition-all ${
                        permissions.has(readPerm)
                          ? "bg-green-500/20 text-green-400 border border-green-500/30"
                          : "bg-[var(--bg-primary)] text-gray-600 border border-[var(--border)]"
                      } ${readonly ? "cursor-default" : "cursor-pointer hover:border-[var(--accent)]"}`}
                      title={readPerm}
                    >
                      {permissions.has(readPerm) ? (
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                      ) : (
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                      )}
                    </button>
                  </td>
                ) : <td />}
                {writePerm ? (
                  <td className="text-center py-2 px-2">
                    <button
                      onClick={() => togglePerm(writePerm)}
                      disabled={readonly}
                      className={`inline-flex items-center justify-center w-7 h-7 rounded-md transition-all ${
                        permissions.has(writePerm)
                          ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                          : "bg-[var(--bg-primary)] text-gray-600 border border-[var(--border)]"
                      } ${readonly ? "cursor-default" : "cursor-pointer hover:border-[var(--accent)]"}`}
                      title={writePerm}
                    >
                      {permissions.has(writePerm) ? (
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                      ) : (
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                      )}
                    </button>
                  </td>
                ) : <td />}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────
export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  // Add user
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

  // Delete
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Audit
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditOpen, setAuditOpen] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);

  // Tabs
  const [activeTab, setActiveTab] = useState<"users" | "roles">("users");

  // Roles
  const [roles, setRoles] = useState<Role[]>([]);
  const [showRoleForm, setShowRoleForm] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDesc, setNewRoleDesc] = useState("");
  const [newRolePerms, setNewRolePerms] = useState<Set<string>>(new Set());
  const [roleSaving, setRoleSaving] = useState(false);
  const [editingRoleId, setEditingRoleId] = useState<string | null>(null);
  const [editRolePerms, setEditRolePerms] = useState<Set<string>>(new Set());
  const [editRoleName, setEditRoleName] = useState("");
  const [editRoleDesc, setEditRoleDesc] = useState("");
  const [deletingRoleId, setDeletingRoleId] = useState<string | null>(null);

  const { permissions: myPerms } = useAuth();
  const canWriteUsers = myPerms.has("users:write");
  const currentUserId = getCurrentUserId();

  // User count per role
  const userCountByRole = useMemo(() => {
    const counts: Record<string, number> = {};
    users.forEach(u => { counts[u.role] = (counts[u.role] || 0) + 1; });
    return counts;
  }, [users]);

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

  // ── User handlers ──
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    setAdding(true);
    try {
      const res = await fetch(`${API}/api/v1/auth/users`, {
        method: "POST", headers: authHeaders(),
        body: JSON.stringify({ username: newUsername.trim(), password: newPassword, role: newRole }),
      });
      if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.error || b.message || `HTTP ${res.status}`); }
      setFeedbackWithTimeout({ type: "success", message: `User "${newUsername.trim()}" created.` });
      setNewUsername(""); setNewPassword(""); setNewRole("viewer"); setShowAddForm(false);
      await fetchUsers();
    } catch (err: unknown) {
      setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` });
    } finally { setAdding(false); }
  };

  const startEdit = (u: User) => { setEditingId(u.id); setEditUsername(u.username); setEditPassword(""); setEditRole(u.role); setEditEnabled(u.enabled); };
  const cancelEdit = () => setEditingId(null);

  const handleSaveEdit = async () => {
    if (!editingId || !editUsername.trim()) return;
    setSaving(true);
    try {
      const body: Record<string, unknown> = { username: editUsername.trim(), role: editRole, enabled: editEnabled };
      if (editPassword.trim()) body.password = editPassword;
      const res = await fetch(`${API}/api/v1/auth/users/${editingId}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify(body) });
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || d.message || `HTTP ${res.status}`); }
      setFeedbackWithTimeout({ type: "success", message: "User updated." }); setEditingId(null); await fetchUsers();
    } catch (err: unknown) {
      setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` });
    } finally { setSaving(false); }
  };

  const handleToggleEnabled = async (u: User) => {
    try {
      const res = await fetch(`${API}/api/v1/auth/users/${u.id}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify({ enabled: !u.enabled }) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout({ type: "success", message: `${u.username} ${!u.enabled ? "enabled" : "disabled"}.` }); await fetchUsers();
    } catch (err: unknown) { setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` }); }
  };

  const handleDelete = async (u: User) => {
    try {
      const res = await fetch(`${API}/api/v1/auth/users/${u.id}`, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout({ type: "success", message: `User "${u.username}" deleted.` }); setDeletingId(null); await fetchUsers();
    } catch (err: unknown) { setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` }); }
  };

  // ── Role handlers ──
  const handleCreateRole = async () => {
    if (!newRoleName.trim()) return;
    setRoleSaving(true);
    try {
      const res = await fetch(`${API}/api/v1/auth/roles`, {
        method: "POST", headers: authHeaders(),
        body: JSON.stringify({ name: newRoleName.trim(), permissions: Array.from(newRolePerms), description: newRoleDesc.trim() || null }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout({ type: "success", message: `Role "${newRoleName.trim()}" created` });
      setShowRoleForm(false); setNewRoleName(""); setNewRoleDesc(""); setNewRolePerms(new Set()); await fetchRoles();
    } catch (err: unknown) { setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` }); }
    finally { setRoleSaving(false); }
  };

  const startEditRole = (r: Role) => {
    setEditingRoleId(r.id); setEditRoleName(r.name); setEditRoleDesc(r.description || ""); setEditRolePerms(new Set(r.permissions));
  };

  const handleSaveRole = async () => {
    if (!editingRoleId) return;
    setRoleSaving(true);
    try {
      const res = await fetch(`${API}/api/v1/auth/roles/${editingRoleId}`, {
        method: "PUT", headers: authHeaders(),
        body: JSON.stringify({ name: editRoleName.trim() || undefined, permissions: Array.from(editRolePerms), description: editRoleDesc.trim() || null }),
      });
      if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.message || `HTTP ${res.status}`); }
      setFeedbackWithTimeout({ type: "success", message: "Role updated" }); setEditingRoleId(null); await fetchRoles();
    } catch (err: unknown) { setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` }); }
    finally { setRoleSaving(false); }
  };

  const handleDeleteRole = async (r: Role) => {
    if (!confirm(`Delete role "${r.name}"? Users assigned to this role will need to be reassigned.`)) return;
    setDeletingRoleId(r.id);
    try {
      const res = await fetch(`${API}/api/v1/auth/roles/${r.id}`, { method: "DELETE", headers: authHeaders() });
      if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.message || `HTTP ${res.status}`); }
      setFeedbackWithTimeout({ type: "success", message: `Role "${r.name}" deleted` }); await fetchRoles();
    } catch (err: unknown) { setFeedbackWithTimeout({ type: "error", message: `Failed: ${err instanceof Error ? err.message : "Unknown"}` }); }
    finally { setDeletingRoleId(null); }
  };

  const toggleAudit = () => {
    const next = !auditOpen;
    setAuditOpen(next);
    if (next && auditEntries.length === 0) fetchAudit();
  };

  const inputCls = "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]";
  const labelCls = "text-[10px] text-[var(--text-muted)] uppercase tracking-wider block mb-1";
  const sectionCls = "bg-[var(--bg-card)] border border-[var(--border)] rounded-lg";
  const btnPrimary = "px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const btnDanger = "px-3 py-1.5 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 rounded-md text-xs transition-colors";
  const btnSecondary = "px-3 py-1.5 bg-[var(--bg-primary)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)] border border-[var(--border)] rounded-md text-xs transition-colors";

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Users & Roles</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {users.length} user{users.length !== 1 ? "s" : ""} across {roles.length} role{roles.length !== 1 ? "s" : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {activeTab === "users" && canWriteUsers && (
            <button onClick={() => setShowAddForm(!showAddForm)} className={btnPrimary}>
              {showAddForm ? "Cancel" : "+ Add User"}
            </button>
          )}
          {activeTab === "roles" && canWriteUsers && (
            <button onClick={() => { setShowRoleForm(!showRoleForm); setNewRoleName(""); setNewRoleDesc(""); setNewRolePerms(new Set()); }} className={btnPrimary}>
              {showRoleForm ? "Cancel" : "+ Create Role"}
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[var(--bg-card)] rounded-lg p-1 border border-[var(--border)] w-fit">
        {(["users", "roles"] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-5 py-2 text-sm font-medium rounded-md transition-all ${
              activeTab === tab ? "bg-[var(--accent)] text-white shadow-sm" : "text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)]"
            }`}
          >
            {tab === "users" ? `Users (${users.length})` : `Roles (${roles.length})`}
          </button>
        ))}
      </div>

      {/* Feedback */}
      {feedback && (
        <div className={`p-3 text-sm rounded-md border ${feedback.type === "error" ? "text-red-400 bg-red-500/10 border-red-500/20" : "text-green-400 bg-green-500/10 border-green-500/20"}`}>
          {feedback.message}
        </div>
      )}

      {/* ═══════════════ USERS TAB ═══════════════ */}
      {activeTab === "users" && (<>
        {showAddForm && (
          <div className={`${sectionCls} p-5`}>
            <h2 className="text-sm font-medium mb-4">New User</h2>
            <form onSubmit={handleAddUser} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div><label className={labelCls}>Username</label><input type="text" value={newUsername} onChange={e => setNewUsername(e.target.value)} placeholder="Username" className={inputCls} required autoFocus /></div>
                <div><label className={labelCls}>Password</label><input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="Password" className={inputCls} required /></div>
                <div><label className={labelCls}>Role</label>
                  <select value={newRole} onChange={e => setNewRole(e.target.value)} className={inputCls}>
                    {roles.map(r => <option key={r.id} value={r.name}>{r.name}{!r.builtin ? " (custom)" : ""}</option>)}
                  </select>
                </div>
              </div>
              <div className="flex justify-end"><button type="submit" disabled={adding} className={btnPrimary}>{adding ? "Creating..." : "Create User"}</button></div>
            </form>
          </div>
        )}

        {/* Users table */}
        <div className={`${sectionCls} overflow-hidden`}>
          {loading ? <div className="p-8 text-center text-[var(--text-muted)]">Loading...</div>
          : users.length === 0 ? <div className="p-8 text-center text-[var(--text-muted)]">No users.</div>
          : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-[10px] text-[var(--text-muted)] uppercase tracking-wider">
                  <th className="px-4 py-3">User</th><th className="px-4 py-3">Role</th><th className="px-4 py-3">MFA</th>
                  <th className="px-4 py-3">Provider</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => {
                  const style = getRoleStyle(user.role, roles.find(r => r.name === user.role)?.builtin ?? true);
                  const isEditing = editingId === user.id;
                  return (
                    <tr key={user.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                      {isEditing ? (<>
                        <td className="px-4 py-3"><input type="text" value={editUsername} onChange={e => setEditUsername(e.target.value)} className="w-full px-2 py-1 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" /></td>
                        <td className="px-4 py-3">
                          <select value={editRole} onChange={e => setEditRole(e.target.value)} className="px-2 py-1 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
                            {roles.map(r => <option key={r.id} value={r.name}>{r.name}</option>)}
                          </select>
                        </td>
                        <td className="px-4 py-3 text-[var(--text-muted)] text-xs">{user.totp_enabled ? "On" : "Off"}</td>
                        <td className="px-4 py-3"><input type="password" value={editPassword} onChange={e => setEditPassword(e.target.value)} placeholder="(unchanged)" className="w-full px-2 py-1 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]" /></td>
                        <td className="px-4 py-3">
                          <button onClick={() => setEditEnabled(!editEnabled)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${editEnabled ? "bg-green-600" : "bg-gray-600"}`}>
                            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${editEnabled ? "translate-x-4" : "translate-x-0.5"}`} />
                          </button>
                        </td>
                        <td className="px-4 py-3 text-[var(--text-muted)] text-xs">{formatDate(user.created_at)}</td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button onClick={handleSaveEdit} disabled={saving} className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/40 text-green-400 border border-green-500/30 rounded-md text-xs transition-colors disabled:opacity-50">{saving ? "..." : "Save"}</button>
                            <button onClick={cancelEdit} className={btnSecondary}>Cancel</button>
                          </div>
                        </td>
                      </>) : (<>
                        <td className="px-4 py-3 font-medium">{user.username}{user.id === currentUserId && <span className="ml-1.5 text-[10px] text-[var(--accent)]">(you)</span>}</td>
                        <td className="px-4 py-3"><span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${style.badge}`}>{user.role}</span></td>
                        <td className="px-4 py-3">{user.totp_enabled ? <span className="text-green-400 text-xs">Enabled</span> : <span className="text-[var(--text-muted)] text-xs">Off</span>}</td>
                        <td className="px-4 py-3 text-[var(--text-muted)] text-xs">{user.auth_provider}</td>
                        <td className="px-4 py-3">
                          <button onClick={() => handleToggleEnabled(user)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${user.enabled ? "bg-green-600" : "bg-gray-600"}`} title={user.enabled ? "Disable" : "Enable"}>
                            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${user.enabled ? "translate-x-4" : "translate-x-0.5"}`} />
                          </button>
                        </td>
                        <td className="px-4 py-3 text-[var(--text-muted)] text-xs">{formatDate(user.created_at)}</td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {canWriteUsers && <button onClick={() => startEdit(user)} className={btnSecondary}>Edit</button>}
                            {canWriteUsers && (currentUserId === user.id
                              ? <span className="px-3 py-1.5 text-[var(--text-muted)] text-xs cursor-not-allowed">Delete</span>
                              : deletingId === user.id
                                ? <><button onClick={() => handleDelete(user)} className={btnDanger}>Confirm</button><button onClick={() => setDeletingId(null)} className={btnSecondary}>No</button></>
                                : <button onClick={() => setDeletingId(user.id)} className={btnDanger}>Delete</button>
                            )}
                          </div>
                        </td>
                      </>)}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Audit Log */}
        <div className={sectionCls}>
          <button onClick={toggleAudit} className="w-full flex items-center justify-between px-5 py-4">
            <h2 className="text-sm font-medium">Audit Log</h2>
            <svg className={`w-4 h-4 text-[var(--text-muted)] transition-transform ${auditOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
          </button>
          {auditOpen && (
            <div className="border-t border-[var(--border)]">
              {auditLoading ? <p className="px-5 py-4 text-sm text-[var(--text-muted)]">Loading...</p>
              : auditEntries.length === 0 ? <p className="px-5 py-4 text-sm text-[var(--text-muted)]">No entries.</p>
              : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="border-b border-[var(--border)] text-left text-[10px] text-[var(--text-muted)] uppercase tracking-wider">
                      <th className="px-4 py-2">Time</th><th className="px-4 py-2">Action</th><th className="px-4 py-2">Actor</th><th className="px-4 py-2">Target</th><th className="px-4 py-2">IP</th><th className="px-4 py-2">Details</th>
                    </tr></thead>
                    <tbody>{auditEntries.map(e => {
                      const c: Record<string, string> = { login_success: "text-green-400", login_failed: "text-red-400", user_created: "text-blue-400", user_updated: "text-yellow-400", user_deleted: "text-red-400" };
                      return (<tr key={e.id} className="border-b border-[var(--border)]">
                        <td className="px-4 py-2 text-[var(--text-muted)] whitespace-nowrap">{formatDate(e.created_at)}</td>
                        <td className={`px-4 py-2 font-mono ${c[e.action] || "text-[var(--text-muted)]"}`}>{e.action}</td>
                        <td className="px-4 py-2 font-mono text-[var(--text-secondary)]">{e.actor_id?.slice(0, 8)}...</td>
                        <td className="px-4 py-2 font-mono text-[var(--text-muted)]">{e.user_id?.slice(0, 8) || "-"}</td>
                        <td className="px-4 py-2 font-mono text-[var(--text-muted)]">{e.ip_addr || "-"}</td>
                        <td className="px-4 py-2 text-[var(--text-muted)] max-w-xs truncate">{e.details || "-"}</td>
                      </tr>);
                    })}</tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </>)}

      {/* ═══════════════ ROLES TAB ═══════════════ */}
      {activeTab === "roles" && (<>
        {/* Create Role Form */}
        {showRoleForm && canWriteUsers && (
          <div className={`${sectionCls} p-5`}>
            <h2 className="text-sm font-medium mb-4">Create Custom Role</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div><label className={labelCls}>Name</label><input type="text" value={newRoleName} onChange={e => setNewRoleName(e.target.value)} placeholder="e.g. network-engineer" className={inputCls} autoFocus /></div>
                <div><label className={labelCls}>Description</label><input type="text" value={newRoleDesc} onChange={e => setNewRoleDesc(e.target.value)} placeholder="What can this role do?" className={inputCls} /></div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className={labelCls}>Permissions</label>
                  <div className="flex gap-2">
                    <button onClick={() => { const all = new Set<string>(); PERMISSION_CATEGORIES.forEach(c => c.perms.forEach(p => all.add(p))); setNewRolePerms(all); }} className="text-[10px] text-[var(--accent)] hover:underline">Select All</button>
                    <button onClick={() => setNewRolePerms(new Set())} className="text-[10px] text-[var(--text-muted)] hover:underline">Clear All</button>
                  </div>
                </div>
                <PermissionGrid permissions={newRolePerms} onChange={setNewRolePerms} />
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-[var(--border)]">
                <span className="text-xs text-[var(--text-muted)]">{newRolePerms.size} permission{newRolePerms.size !== 1 ? "s" : ""} selected</span>
                <button onClick={handleCreateRole} disabled={roleSaving || !newRoleName.trim()} className={btnPrimary}>{roleSaving ? "Creating..." : "Create Role"}</button>
              </div>
            </div>
          </div>
        )}

        {/* Roles Grid */}
        <div className="space-y-4">
          {roles.map(role => {
            const style = getRoleStyle(role.name, role.builtin);
            const userCount = userCountByRole[role.name] || 0;
            const isEditing = editingRoleId === role.id;
            const permSet = isEditing ? editRolePerms : new Set(role.permissions);

            return (
              <div key={role.id} className={`${sectionCls} overflow-hidden border-l-2 ${style.accent}`}>
                {/* Role header */}
                <div className="px-5 py-4 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        {isEditing && !role.builtin ? (
                          <input type="text" value={editRoleName} onChange={e => setEditRoleName(e.target.value)} className="px-2 py-0.5 text-sm font-semibold bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] w-40" />
                        ) : (
                          <h3 className="text-sm font-semibold">{role.name}</h3>
                        )}
                        <span className={`px-2 py-0.5 text-[10px] font-medium rounded-full border ${style.badge}`}>
                          {role.builtin ? "built-in" : "custom"}
                        </span>
                        <span className="text-[10px] text-[var(--text-muted)]">
                          {userCount} user{userCount !== 1 ? "s" : ""}
                        </span>
                      </div>
                      {isEditing && !role.builtin ? (
                        <input type="text" value={editRoleDesc} onChange={e => setEditRoleDesc(e.target.value)} placeholder="Description" className="mt-1 px-2 py-0.5 text-xs bg-[var(--bg-primary)] border border-[var(--border)] rounded text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] w-64" />
                      ) : role.description ? (
                        <p className="text-xs text-[var(--text-muted)] mt-0.5">{role.description}</p>
                      ) : null}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {isEditing ? (<>
                      <button onClick={handleSaveRole} disabled={roleSaving} className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/40 text-green-400 border border-green-500/30 rounded-md text-xs transition-colors disabled:opacity-50">{roleSaving ? "..." : "Save"}</button>
                      <button onClick={() => setEditingRoleId(null)} className={btnSecondary}>Cancel</button>
                    </>) : canWriteUsers && !role.builtin ? (<>
                      <button onClick={() => startEditRole(role)} className={btnSecondary}>Edit</button>
                      <button onClick={() => handleDeleteRole(role)} disabled={deletingRoleId === role.id} className={btnDanger}>{deletingRoleId === role.id ? "..." : "Delete"}</button>
                    </>) : null}
                    <div className="text-xs font-mono text-[var(--text-muted)] ml-2">{role.permissions.length} perms</div>
                  </div>
                </div>

                {/* Permission matrix */}
                <div className="border-t border-[var(--border)]">
                  <PermissionGrid
                    permissions={permSet}
                    onChange={isEditing ? setEditRolePerms : undefined}
                    readonly={!isEditing}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </>)}
    </div>
  );
}
