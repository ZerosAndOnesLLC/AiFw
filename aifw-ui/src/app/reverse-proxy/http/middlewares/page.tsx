"use client";

import { useState } from "react";
import { HttpMiddleware } from "@/lib/api/reverse-proxy/middlewares";
import { useHttpMiddlewares } from "@/hooks/useHttpMiddlewares";
import { MiddlewaresTable } from "./components/MiddlewaresTable";
import { MiddlewareFormModal } from "./components/MiddlewareFormModal";

/* ── Page ─────────────────────────────────────────────────────── */

export default function HttpMiddlewaresPage() {
  const {
    middlewares,
    loading,
    submitting,
    deletingId,
    feedback,
    saveMiddleware,
    deleteMiddleware,
    toggleEnabled,
  } = useHttpMiddlewares();

  // Modal state (the modal itself owns the form fields)
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<HttpMiddleware | null>(null);

  /* ── Modal helpers ──────────────────────────────────────────── */

  function openCreate() {
    setEditing(null);
    setModalOpen(true);
  }

  function openEdit(mw: HttpMiddleware) {
    setEditing(mw);
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditing(null);
  }

  /* ── Render ─────────────────────────────────────────────────── */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading HTTP middlewares...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">HTTP Middlewares</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {middlewares.length} middleware{middlewares.length !== 1 ? "s" : ""} configured
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Middleware
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

      {/* Table */}
      <MiddlewaresTable
        middlewares={middlewares}
        deletingId={deletingId}
        onEdit={openEdit}
        onDelete={deleteMiddleware}
        onToggleEnabled={toggleEnabled}
      />

      {/* Create / Edit Modal */}
      {modalOpen && (
        <MiddlewareFormModal
          editing={editing}
          submitting={submitting}
          onClose={closeModal}
          onSubmit={(body) => saveMiddleware(editing?.id ?? null, body, closeModal)}
        />
      )}
    </div>
  );
}
