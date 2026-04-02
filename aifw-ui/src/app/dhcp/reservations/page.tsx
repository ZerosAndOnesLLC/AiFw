"use client";

import { useState, useEffect, useCallback } from "react";
import { isValidMAC, validateIP } from "@/lib/validate";

/* -- Types ---------------------------------------------------------- */

interface DhcpReservation {
  id: string;
  subnet_id?: string;
  mac_address: string;
  ip_address: string;
  hostname?: string;
  client_id?: string;
  description?: string;
  created_at: string;
}

interface DhcpSubnet {
  id: string;
  network: string;
}

interface ReservationForm {
  mac_address: string;
  ip_address: string;
  hostname: string;
  client_id: string;
  subnet_id: string;
  description: string;
}

const defaultForm: ReservationForm = {
  mac_address: "",
  ip_address: "",
  hostname: "",
  client_id: "",
  subnet_id: "",
  description: "",
};

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/* -- Page ------------------------------------------------------------ */

export default function DhcpReservationsPage() {
  const [reservations, setReservations] = useState<DhcpReservation[]>([]);
  const [subnets, setSubnets] = useState<DhcpSubnet[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ReservationForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchReservations = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/v4/reservations", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setReservations(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load reservations");
    }
  }, []);

  const fetchSubnets = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/v4/subnets", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setSubnets(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load subnets");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchReservations(), fetchSubnets()]);
      setLoading(false);
    })();
  }, [fetchReservations, fetchSubnets]);

  /* -- Helpers ------------------------------------------------------ */

  const subnetLabel = (id?: string) => {
    if (!id) return "-";
    const s = subnets.find((sub) => sub.id === id);
    return s ? s.network : id;
  };

  /* -- Modal -------------------------------------------------------- */

  const openCreate = () => {
    setEditingId(null);
    setForm(defaultForm);
    setModalOpen(true);
  };

  const openEdit = (r: DhcpReservation) => {
    setEditingId(r.id);
    setForm({
      mac_address: r.mac_address,
      ip_address: r.ip_address,
      hostname: r.hostname || "",
      client_id: r.client_id || "",
      subnet_id: r.subnet_id || "",
      description: r.description || "",
    });
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setForm(defaultForm);
  };

  const handleSubmit = async () => {
    if (!form.mac_address.trim() || !form.ip_address.trim()) {
      showFeedback("error", "MAC address and IP address are required");
      return;
    }

    // Client-side validation
    const errors: string[] = [];
    if (!isValidMAC(form.mac_address)) errors.push("MAC address: invalid format (expected AA:BB:CC:DD:EE:FF)");
    { const e = validateIP(form.ip_address, "IP address"); if (e) errors.push(e); }
    if (errors.length > 0) { showFeedback("error", errors.join(". ")); return; }

    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        mac_address: form.mac_address.trim(),
        ip_address: form.ip_address.trim(),
      };
      if (form.hostname.trim()) payload.hostname = form.hostname.trim();
      if (form.client_id.trim()) payload.client_id = form.client_id.trim();
      if (form.subnet_id) payload.subnet_id = form.subnet_id;
      if (form.description.trim()) payload.description = form.description.trim();

      const url = editingId
        ? `/api/v1/dhcp/v4/reservations/${editingId}`
        : "/api/v1/dhcp/v4/reservations";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      showFeedback("success", editingId ? "Reservation updated" : "Reservation created");
      closeModal();
      await fetchReservations();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save reservation");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/dhcp/v4/reservations/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Reservation deleted");
      setDeleteId(null);
      await fetchReservations();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete reservation");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading reservations...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">DHCP Reservations</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Manage static IP-to-MAC address reservations
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Reservation
        </button>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* -- Table --------------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {reservations.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No reservations configured. Click &quot;Add Reservation&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">MAC Address</th>
                  <th className="px-6 py-3">IP Address</th>
                  <th className="px-6 py-3">Hostname</th>
                  <th className="px-6 py-3">Subnet</th>
                  <th className="px-6 py-3">Description</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reservations.map((r) => (
                  <tr
                    key={r.id}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                    onClick={() => openEdit(r)}
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {r.mac_address}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {r.ip_address}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {r.hostname || "-"}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {subnetLabel(r.subnet_id)}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {r.description || "-"}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {fmtDate(r.created_at)}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEdit(r)}
                          title="Edit Reservation"
                          className="p-1.5 text-[var(--text-muted)] hover:text-blue-400 rounded hover:bg-blue-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => setDeleteId(r.id)}
                          title="Delete Reservation"
                          className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* -- Create/Edit Modal --------------------------------------- */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-lg w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">
              {editingId ? "Edit Reservation" : "Add Reservation"}
            </h3>

            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">MAC Address</label>
                <input
                  type="text"
                  value={form.mac_address}
                  onChange={(e) => setForm((p) => ({ ...p, mac_address: e.target.value }))}
                  placeholder="e.g. AA:BB:CC:DD:EE:FF"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">IP Address</label>
                <input
                  type="text"
                  value={form.ip_address}
                  onChange={(e) => setForm((p) => ({ ...p, ip_address: e.target.value }))}
                  placeholder="e.g. 192.168.1.50"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Hostname</label>
                <input
                  type="text"
                  value={form.hostname}
                  onChange={(e) => setForm((p) => ({ ...p, hostname: e.target.value }))}
                  placeholder="Optional hostname"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Client ID (DHCP Option 61)</label>
                <input
                  type="text"
                  value={form.client_id}
                  onChange={(e) => setForm((p) => ({ ...p, client_id: e.target.value }))}
                  placeholder="Optional — alternative to MAC for identification"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Subnet</label>
                <select
                  value={form.subnet_id}
                  onChange={(e) => setForm((p) => ({ ...p, subnet_id: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">-- No subnet --</option>
                  {subnets.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.network}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
                  placeholder="Optional description"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {submitting
                  ? "Saving..."
                  : editingId
                    ? "Update Reservation"
                    : "Create Reservation"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -- Delete Confirm Modal ------------------------------------ */}
      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Delete Reservation</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this reservation? The associated client will receive a
              dynamic IP on its next renewal.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
