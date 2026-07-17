"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  HttpMiddleware,
  HttpMiddlewareBody,
  listHttpMiddlewares,
  createHttpMiddleware,
  updateHttpMiddleware,
  deleteHttpMiddleware,
} from "@/lib/api/reverse-proxy/middlewares";

/// Data hook for the HTTP middlewares page (#428): owns the middleware
/// list, loading/submitting/deleting flags, and all CRUD actions with
/// their success/error feedback.
export function useHttpMiddlewares() {
  const [middlewares, setMiddlewares] = useState<HttpMiddleware[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const { feedback, showFeedback } = useFeedback(5000);

  /* ── Fetch ─────────────────────────────────────────────────── */

  const fetchMiddlewares = useCallback(async () => {
    try {
      setMiddlewares(await listHttpMiddlewares());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load middlewares");
    } finally {
      setLoading(false);
    }
  }, [showFeedback]);

  useEffect(() => {
    queueMicrotask(fetchMiddlewares);
  }, [fetchMiddlewares]);

  /* ── CRUD ───────────────────────────────────────────────────── */

  /// Create (editingId == null) or update a middleware. `onSuccess` runs
  /// after the save succeeds and before the list refetch (the page uses
  /// it to close the modal, matching the original ordering).
  const saveMiddleware = useCallback(
    async (editingId: string | null, body: HttpMiddlewareBody, onSuccess?: () => void) => {
      setSubmitting(true);
      try {
        if (editingId) {
          await updateHttpMiddleware(editingId, body);
        } else {
          await createHttpMiddleware(body);
        }
        showFeedback("success", editingId ? "Middleware updated" : "Middleware created");
        onSuccess?.();
        await fetchMiddlewares();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save middleware");
      } finally {
        setSubmitting(false);
      }
    },
    [fetchMiddlewares, showFeedback]
  );

  const deleteMiddleware = useCallback(
    async (mw: HttpMiddleware) => {
      if (!confirm(`Delete middleware "${mw.name}"?`)) return;
      setDeletingId(mw.id);
      try {
        await deleteHttpMiddleware(mw.id);
        showFeedback("success", `Middleware "${mw.name}" deleted`);
        await fetchMiddlewares();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to delete middleware");
      } finally {
        setDeletingId(null);
      }
    },
    [fetchMiddlewares, showFeedback]
  );

  const toggleEnabled = useCallback(
    async (mw: HttpMiddleware) => {
      try {
        const body: HttpMiddlewareBody = {
          name: mw.name,
          middleware_type: mw.middleware_type,
          config_json: mw.config_json,
          enabled: !mw.enabled,
        };
        await updateHttpMiddleware(mw.id, body);
        setMiddlewares((prev) =>
          prev.map((m) => (m.id === mw.id ? { ...m, enabled: !mw.enabled } : m))
        );
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to toggle middleware");
      }
    },
    [showFeedback]
  );

  return {
    middlewares,
    loading,
    submitting,
    deletingId,
    feedback,
    saveMiddleware,
    deleteMiddleware,
    toggleEnabled,
  };
}
