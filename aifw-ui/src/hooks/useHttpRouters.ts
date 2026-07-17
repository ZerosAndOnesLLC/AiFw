"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  type HttpRouter,
  type Entrypoint,
  type HttpService,
  type HttpMiddleware,
  type HttpRouterPayload,
  listHttpRouters,
  listEntrypoints,
  listHttpServices,
  listHttpMiddlewares,
  createHttpRouter,
  updateHttpRouter,
  deleteHttpRouter,
} from "@/lib/api/reverse-proxy/routers";

/// Data + CRUD state for the HTTP routers page (#428). Owns the router
/// list, the lookup lists the form needs (entrypoints/services/middlewares),
/// loading/submitting flags, and success/error feedback.
export function useHttpRouters() {
  const [routers, setRouters] = useState<HttpRouter[]>([]);
  const [entrypoints, setEntrypoints] = useState<Entrypoint[]>([]);
  const [services, setServices] = useState<HttpService[]>([]);
  const [middlewares, setMiddlewares] = useState<HttpMiddleware[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const { feedback, showFeedback } = useFeedback();

  /* -- Fetch -------------------------------------------------------- */

  const fetchRouters = useCallback(async () => {
    try {
      setRouters(await listHttpRouters());
    } catch {
      showFeedback("error", "Failed to load HTTP routers");
    } finally {
      setLoading(false);
    }
  }, [showFeedback]);

  const fetchEntrypoints = useCallback(async () => {
    try {
      setEntrypoints(await listEntrypoints());
    } catch { /* silent */ }
  }, []);

  const fetchServices = useCallback(async () => {
    try {
      setServices(await listHttpServices());
    } catch { /* silent */ }
  }, []);

  const fetchMiddlewares = useCallback(async () => {
    try {
      setMiddlewares(await listHttpMiddlewares());
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      Promise.all([fetchRouters(), fetchEntrypoints(), fetchServices(), fetchMiddlewares()]);
    });
  }, [fetchRouters, fetchEntrypoints, fetchServices, fetchMiddlewares]);

  /* -- CRUD --------------------------------------------------------- */

  /// Create (editingId null) or update a router. `onSuccess` runs after the
  /// success banner is shown and before the list refetch (the page uses it
  /// to close the modal, mirroring the original resetForm ordering).
  const saveRouter = useCallback(
    async (editingId: string | null, body: HttpRouterPayload, onSuccess?: () => void) => {
      setSubmitting(true);
      try {
        if (editingId) {
          await updateHttpRouter(editingId, body);
        } else {
          await createHttpRouter(body);
        }

        showFeedback("success", editingId ? "Router updated" : "Router created");
        onSuccess?.();
        await fetchRouters();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save router");
      } finally {
        setSubmitting(false);
      }
    },
    [showFeedback, fetchRouters],
  );

  const deleteRouter = useCallback(
    async (id: string) => {
      setDeletingId(id);
      try {
        await deleteHttpRouter(id);
        showFeedback("success", "Router deleted");
        setRouters((prev) => prev.filter((r) => r.id !== id));
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to delete router");
      } finally {
        setDeletingId(null);
      }
    },
    [showFeedback],
  );

  const toggleEnabled = useCallback(
    async (router: HttpRouter) => {
      try {
        await updateHttpRouter(router.id, { ...router, enabled: !router.enabled });
        setRouters((prev) =>
          prev.map((r) => (r.id === router.id ? { ...r, enabled: !r.enabled } : r))
        );
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to toggle router");
      }
    },
    [showFeedback],
  );

  return {
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
  };
}
