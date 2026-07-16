"use client";

import { useState } from "react";
import { useDhcpSubnets } from "@/hooks/useDhcpSubnets";
import type { DhcpSubnet, SubnetForm } from "@/lib/api/dhcp-subnets";
import { SubnetTable } from "./components/SubnetTable";
import { SubnetFormModal } from "./components/SubnetFormModal";
import { DeleteSubnetModal } from "./components/DeleteSubnetModal";

export default function DhcpSubnetsPage() {
  const {
    subnets,
    globalDefaults,
    loading,
    submitting,
    feedback,
    showFeedback,
    saveSubnet,
    deleteSubnet,
  } = useDhcpSubnets();

  // Modal state: null = closed, { editing: null } = create, { editing: subnet } = edit
  const [modal, setModal] = useState<{ editing: DhcpSubnet | null } | null>(null);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const handleSubmit = async (form: SubnetForm) => {
    await saveSubnet(modal?.editing?.id ?? null, form, () => setModal(null));
  };

  const handleDelete = async (id: string) => {
    await deleteSubnet(id, () => setDeleteId(null));
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading subnets...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">DHCP Subnets</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Manage DHCPv4/v6 subnets and address pools
          </p>
        </div>
        <button
          onClick={() => setModal({ editing: null })}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Subnet
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
      <SubnetTable
        subnets={subnets}
        onEdit={(subnet) => setModal({ editing: subnet })}
        onDelete={setDeleteId}
      />

      {/* -- Create/Edit Modal --------------------------------------- */}
      {modal && (
        <SubnetFormModal
          editing={modal.editing}
          globalDefaults={globalDefaults}
          submitting={submitting}
          showFeedback={showFeedback}
          onSubmit={handleSubmit}
          onClose={() => setModal(null)}
        />
      )}

      {/* -- Delete Confirm Modal ------------------------------------ */}
      {deleteId && (
        <DeleteSubnetModal
          onCancel={() => setDeleteId(null)}
          onConfirm={() => handleDelete(deleteId)}
        />
      )}
    </div>
  );
}
