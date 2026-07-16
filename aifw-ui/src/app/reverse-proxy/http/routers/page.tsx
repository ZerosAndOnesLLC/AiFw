"use client";

import { useState } from "react";
import type { HttpRouter, HttpRouterPayload } from "@/lib/api/reverse-proxy/routers";
import { useHttpRouters } from "@/hooks/useHttpRouters";
import { RoutersTable } from "./components/RoutersTable";
import { RouterFormModal } from "./components/RouterFormModal";

export default function HttpRoutersPage() {
  const {
    routers,
    entrypoints,
    services,
    middlewares,
    loading,
    submitting,
    deletingId,
    feedback,
    showFeedback,
    saveRouter,
    deleteRouter,
    toggleEnabled,
  } = useHttpRouters();

  // Modal state: the form itself lives inside RouterFormModal, which is
  // mounted fresh on every open (seeded from `editing`, null for create).
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<HttpRouter | null>(null);

  const openCreate = () => {
    setEditing(null);
    setShowModal(true);
  };

  const openEdit = (router: HttpRouter) => {
    setEditing(router);
    setShowModal(true);
  };

  const closeModal = () => {
    setEditing(null);
    setShowModal(false);
  };

  const handleSubmit = (body: HttpRouterPayload) => {
    saveRouter(editing?.id ?? null, body, closeModal);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading HTTP routers...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">HTTP Routers</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Route incoming HTTP requests to backend services based on rules
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Router
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
      <RoutersTable
        routers={routers}
        deletingId={deletingId}
        onEdit={openEdit}
        onDelete={deleteRouter}
        onToggleEnabled={toggleEnabled}
      />

      {/* Modal */}
      {showModal && (
        <RouterFormModal
          editing={editing}
          entrypoints={entrypoints}
          services={services}
          middlewares={middlewares}
          submitting={submitting}
          onSubmit={handleSubmit}
          onClose={closeModal}
          showError={(msg) => showFeedback("error", msg)}
        />
      )}
    </div>
  );
}
