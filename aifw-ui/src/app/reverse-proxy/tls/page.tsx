"use client";

import { useState } from "react";
import {
  TlsCert,
  TlsOption,
  CertResolver,
  TlsCertForm,
  TlsOptionForm,
  CertResolverForm,
  defaultTlsCertForm,
  defaultTlsOptionForm,
  defaultCertResolverForm,
  parseTlsOptionJson,
  parseCertResolverJson,
} from "@/lib/api/reverse-proxy/tls";
import { useTlsCerts } from "@/hooks/useTlsCerts";
import { TlsCertsSection } from "./components/TlsCertsSection";
import { TlsOptionsSection } from "./components/TlsOptionsSection";
import { CertResolversSection } from "./components/CertResolversSection";
import { TlsCertModal } from "./components/TlsCertModal";
import { TlsOptionModal } from "./components/TlsOptionModal";
import { CertResolverModal } from "./components/CertResolverModal";
import { DeleteConfirmModal } from "./components/DeleteConfirmModal";

/* -- Page ------------------------------------------------------------ */

export default function TlsCertsPage() {
  const {
    certs,
    tlsOptions,
    resolvers,
    loading,
    feedback,
    certSubmitting,
    optionSubmitting,
    resolverSubmitting,
    saveCert,
    saveOption,
    saveResolver,
    deleteTarget,
    setDeleteTarget,
    confirmDelete,
  } = useTlsCerts();

  // Cert modal
  const [certModalOpen, setCertModalOpen] = useState(false);
  const [editingCertId, setEditingCertId] = useState<string | null>(null);
  const [certForm, setCertForm] = useState<TlsCertForm>(defaultTlsCertForm);

  // TLS option modal
  const [optionModalOpen, setOptionModalOpen] = useState(false);
  const [editingOptionId, setEditingOptionId] = useState<string | null>(null);
  const [optionForm, setOptionForm] = useState<TlsOptionForm>(defaultTlsOptionForm);

  // Resolver modal
  const [resolverModalOpen, setResolverModalOpen] = useState(false);
  const [editingResolverId, setEditingResolverId] = useState<string | null>(null);
  const [resolverForm, setResolverForm] = useState<CertResolverForm>(defaultCertResolverForm);

  /* -- Cert Modal --------------------------------------------------- */

  const openCreateCert = () => {
    setEditingCertId(null);
    setCertForm(defaultTlsCertForm);
    setCertModalOpen(true);
  };

  const openEditCert = (cert: TlsCert) => {
    setEditingCertId(cert.id);
    setCertForm({ name: cert.name, certFile: cert.cert_file, keyFile: cert.key_file });
    setCertModalOpen(true);
  };

  const closeCertModal = () => {
    setCertModalOpen(false);
    setEditingCertId(null);
    setCertForm(defaultTlsCertForm);
  };

  /* -- TLS Option Modal --------------------------------------------- */

  const openCreateOption = () => {
    setEditingOptionId(null);
    setOptionForm(defaultTlsOptionForm);
    setOptionModalOpen(true);
  };

  const openEditOption = (opt: TlsOption) => {
    const parsed = parseTlsOptionJson(opt.config_json);
    setEditingOptionId(opt.id);
    setOptionForm({ ...defaultTlsOptionForm, ...parsed, name: opt.name });
    setOptionModalOpen(true);
  };

  const closeOptionModal = () => {
    setOptionModalOpen(false);
    setEditingOptionId(null);
    setOptionForm(defaultTlsOptionForm);
  };

  /* -- Cert Resolver Modal ------------------------------------------ */

  const openCreateResolver = () => {
    setEditingResolverId(null);
    setResolverForm(defaultCertResolverForm);
    setResolverModalOpen(true);
  };

  const openEditResolver = (r: CertResolver) => {
    const parsed = parseCertResolverJson(r.config_json);
    setEditingResolverId(r.id);
    setResolverForm({ ...defaultCertResolverForm, ...parsed, name: r.name });
    setResolverModalOpen(true);
  };

  const closeResolverModal = () => {
    setResolverModalOpen(false);
    setEditingResolverId(null);
    setResolverForm(defaultCertResolverForm);
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading TLS configuration...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">TLS / Certificates</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage TLS certificates, options, and ACME certificate resolvers
        </p>
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

      {/* Section 1: TLS Certificates */}
      <TlsCertsSection
        certs={certs}
        onAdd={openCreateCert}
        onEdit={openEditCert}
        onDelete={(id) => setDeleteTarget({ type: "cert", id })}
      />

      {/* Section 2: TLS Options */}
      <TlsOptionsSection
        tlsOptions={tlsOptions}
        onAdd={openCreateOption}
        onEdit={openEditOption}
        onDelete={(id) => setDeleteTarget({ type: "option", id })}
      />

      {/* Section 3: Certificate Resolvers (ACME) */}
      <CertResolversSection
        resolvers={resolvers}
        onAdd={openCreateResolver}
        onEdit={openEditResolver}
        onDelete={(id) => setDeleteTarget({ type: "resolver", id })}
      />

      {/* TLS Certificate Modal */}
      {certModalOpen && (
        <TlsCertModal
          editingId={editingCertId}
          form={certForm}
          setForm={setCertForm}
          submitting={certSubmitting}
          onCancel={closeCertModal}
          onSubmit={() => saveCert(certForm, editingCertId, closeCertModal)}
        />
      )}

      {/* TLS Option Modal */}
      {optionModalOpen && (
        <TlsOptionModal
          editingId={editingOptionId}
          form={optionForm}
          setForm={setOptionForm}
          submitting={optionSubmitting}
          onCancel={closeOptionModal}
          onSubmit={() => saveOption(optionForm, editingOptionId, closeOptionModal)}
        />
      )}

      {/* Cert Resolver Modal */}
      {resolverModalOpen && (
        <CertResolverModal
          editingId={editingResolverId}
          form={resolverForm}
          setForm={setResolverForm}
          submitting={resolverSubmitting}
          onCancel={closeResolverModal}
          onSubmit={() => saveResolver(resolverForm, editingResolverId, closeResolverModal)}
        />
      )}

      {/* Delete Confirm Modal */}
      {deleteTarget && (
        <DeleteConfirmModal
          targetType={deleteTarget.type}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={confirmDelete}
        />
      )}
    </div>
  );
}
