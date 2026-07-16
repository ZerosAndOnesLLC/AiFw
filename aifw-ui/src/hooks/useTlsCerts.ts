"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  TlsCert,
  TlsOption,
  CertResolver,
  TlsCertForm,
  TlsOptionForm,
  CertResolverForm,
  buildTlsOptionJson,
  buildCertResolverJson,
  listTlsCerts,
  createTlsCert,
  updateTlsCert,
  deleteTlsCert,
  listTlsOptions,
  createTlsOption,
  updateTlsOption,
  deleteTlsOption,
  listCertResolvers,
  createCertResolver,
  updateCertResolver,
  deleteCertResolver,
} from "@/lib/api/reverse-proxy/tls";

export type DeleteTargetType = "cert" | "option" | "resolver";

export interface DeleteTarget {
  type: DeleteTargetType;
  id: string;
}

/// Owns all TLS page data (certs, options, resolvers), the shared loading
/// flag, feedback banner state, and the create/update/delete actions (#428).
export function useTlsCerts() {
  const [certs, setCerts] = useState<TlsCert[]>([]);
  const [tlsOptions, setTlsOptions] = useState<TlsOption[]>([]);
  const [resolvers, setResolvers] = useState<CertResolver[]>([]);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback } = useFeedback();

  const [certSubmitting, setCertSubmitting] = useState(false);
  const [optionSubmitting, setOptionSubmitting] = useState(false);
  const [resolverSubmitting, setResolverSubmitting] = useState(false);

  // Delete confirm
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget | null>(null);

  /* -- Fetch -------------------------------------------------------- */

  const fetchCerts = useCallback(async () => {
    try {
      setCerts(await listTlsCerts());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load certificates");
    }
  }, [showFeedback]);

  const fetchOptions = useCallback(async () => {
    try {
      setTlsOptions(await listTlsOptions());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load TLS options");
    }
  }, [showFeedback]);

  const fetchResolvers = useCallback(async () => {
    try {
      setResolvers(await listCertResolvers());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load cert resolvers");
    }
  }, [showFeedback]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchCerts(), fetchOptions(), fetchResolvers()]);
      setLoading(false);
    })();
  }, [fetchCerts, fetchOptions, fetchResolvers]);

  /* -- Save actions -------------------------------------------------- */

  // `onSaved` runs after the success feedback and before the refetch, so
  // callers can close their modal at the same point the page always did.

  const saveCert = useCallback(
    async (form: TlsCertForm, editingId: string | null, onSaved: () => void) => {
      if (!form.name.trim() || !form.certFile.trim() || !form.keyFile.trim()) {
        showFeedback("error", "Name, cert file, and key file are required");
        return;
      }
      setCertSubmitting(true);
      try {
        const payload = {
          name: form.name.trim(),
          cert_file: form.certFile.trim(),
          key_file: form.keyFile.trim(),
        };
        if (editingId) {
          await updateTlsCert(editingId, payload);
        } else {
          await createTlsCert(payload);
        }
        showFeedback("success", editingId ? "Certificate updated" : "Certificate created");
        onSaved();
        await fetchCerts();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save certificate");
      } finally {
        setCertSubmitting(false);
      }
    },
    [fetchCerts, showFeedback],
  );

  const saveOption = useCallback(
    async (form: TlsOptionForm, editingId: string | null, onSaved: () => void) => {
      if (!form.name.trim()) {
        showFeedback("error", "Name is required");
        return;
      }
      setOptionSubmitting(true);
      try {
        const payload = {
          name: form.name.trim(),
          config_json: buildTlsOptionJson(form),
        };
        if (editingId) {
          await updateTlsOption(editingId, payload);
        } else {
          await createTlsOption(payload);
        }
        showFeedback("success", editingId ? "TLS option updated" : "TLS option created");
        onSaved();
        await fetchOptions();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save TLS option");
      } finally {
        setOptionSubmitting(false);
      }
    },
    [fetchOptions, showFeedback],
  );

  const saveResolver = useCallback(
    async (form: CertResolverForm, editingId: string | null, onSaved: () => void) => {
      if (!form.name.trim() || !form.email.trim()) {
        showFeedback("error", "Name and email are required");
        return;
      }
      setResolverSubmitting(true);
      try {
        const payload = {
          name: form.name.trim(),
          config_json: buildCertResolverJson(form),
        };
        if (editingId) {
          await updateCertResolver(editingId, payload);
        } else {
          await createCertResolver(payload);
        }
        showFeedback("success", editingId ? "Cert resolver updated" : "Cert resolver created");
        onSaved();
        await fetchResolvers();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save cert resolver");
      } finally {
        setResolverSubmitting(false);
      }
    },
    [fetchResolvers, showFeedback],
  );

  /* -- Delete ------------------------------------------------------- */

  const confirmDelete = useCallback(async () => {
    if (!deleteTarget) return;
    const { type, id } = deleteTarget;
    try {
      if (type === "cert") await deleteTlsCert(id);
      else if (type === "option") await deleteTlsOption(id);
      else await deleteCertResolver(id);
      const labels = { cert: "Certificate", option: "TLS option", resolver: "Cert resolver" };
      showFeedback("success", `${labels[type]} deleted`);
      setDeleteTarget(null);
      if (type === "cert") await fetchCerts();
      else if (type === "option") await fetchOptions();
      else await fetchResolvers();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete");
    }
  }, [deleteTarget, fetchCerts, fetchOptions, fetchResolvers, showFeedback]);

  return {
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
  };
}
