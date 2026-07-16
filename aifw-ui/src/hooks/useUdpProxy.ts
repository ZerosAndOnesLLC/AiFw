"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  type UdpRouter,
  type UdpService,
  type EntryPoint,
  type RouterForm,
  type ServiceForm,
  buildServiceConfigJson,
  listUdpRouters,
  createUdpRouter,
  updateUdpRouter,
  deleteUdpRouter,
  listUdpServices,
  createUdpService,
  updateUdpService,
  deleteUdpService,
  listEntryPoints,
} from "@/lib/api/reverse-proxy/udp";

/// Data/state hook for the UDP reverse-proxy page (#428): owns the router,
/// service and entrypoint lists, the shared loading flag, submit flags, and
/// all create/update/delete actions with their success/error feedback.
/// Routers and services share one feedback banner, so this is a single
/// combined hook rather than one per resource.
export function useUdpProxy() {
  /* -- Data state ---------------------------------------------------- */
  const [routers, setRouters] = useState<UdpRouter[]>([]);
  const [services, setServices] = useState<UdpService[]>([]);
  const [entrypoints, setEntrypoints] = useState<EntryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [routerSubmitting, setRouterSubmitting] = useState(false);
  const [serviceSubmitting, setServiceSubmitting] = useState(false);
  const { feedback, showFeedback } = useFeedback();

  /* -- Fetch -------------------------------------------------------- */

  const fetchRouters = useCallback(async () => {
    try {
      setRouters(await listUdpRouters());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load UDP routers");
    }
  }, [showFeedback]);

  const fetchServices = useCallback(async () => {
    try {
      setServices(await listUdpServices());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load UDP services");
    }
  }, [showFeedback]);

  const fetchEntrypoints = useCallback(async () => {
    try {
      setEntrypoints(await listEntryPoints());
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchRouters(), fetchServices(), fetchEntrypoints()]);
      setLoading(false);
    })();
  }, [fetchRouters, fetchServices, fetchEntrypoints]);

  /* -- Router actions ------------------------------------------------ */

  /// Create (editingId null) or update a router. `onSaved` runs right after
  /// the success feedback, before the list refetch — the page uses it to
  /// close the modal, matching the original ordering.
  const saveRouter = useCallback(
    async (form: RouterForm, editingId: string | null, onSaved?: () => void) => {
      if (!form.name.trim()) {
        showFeedback("error", "Name is required");
        return;
      }
      setRouterSubmitting(true);
      try {
        const payload = {
          name: form.name.trim(),
          rule: form.rule.trim(),
          service: form.service.trim(),
          entry_points: form.entry_points.trim(),
          priority: parseInt(form.priority, 10) || 0,
          enabled: form.enabled,
        };
        if (editingId) {
          await updateUdpRouter(editingId, payload);
        } else {
          await createUdpRouter(payload);
        }
        showFeedback("success", editingId ? "UDP router updated" : "UDP router created");
        onSaved?.();
        await fetchRouters();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save UDP router");
      } finally {
        setRouterSubmitting(false);
      }
    },
    [showFeedback, fetchRouters],
  );

  const deleteRouter = useCallback(
    async (id: string, onDeleted?: () => void) => {
      try {
        await deleteUdpRouter(id);
        showFeedback("success", "UDP router deleted");
        onDeleted?.();
        await fetchRouters();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to delete UDP router");
      }
    },
    [showFeedback, fetchRouters],
  );

  /* -- Service actions ----------------------------------------------- */

  const saveService = useCallback(
    async (form: ServiceForm, editingId: string | null, onSaved?: () => void) => {
      if (!form.name.trim()) {
        showFeedback("error", "Service name is required");
        return;
      }
      setServiceSubmitting(true);
      try {
        const payload = {
          name: form.name.trim(),
          service_type: form.service_type,
          config_json: buildServiceConfigJson(form),
          enabled: form.enabled,
        };
        if (editingId) {
          await updateUdpService(editingId, payload);
        } else {
          await createUdpService(payload);
        }
        showFeedback("success", editingId ? "UDP service updated" : "UDP service created");
        onSaved?.();
        await fetchServices();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save UDP service");
      } finally {
        setServiceSubmitting(false);
      }
    },
    [showFeedback, fetchServices],
  );

  const deleteService = useCallback(
    async (id: string, onDeleted?: () => void) => {
      try {
        await deleteUdpService(id);
        showFeedback("success", "UDP service deleted");
        onDeleted?.();
        await fetchServices();
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to delete UDP service");
      }
    },
    [showFeedback, fetchServices],
  );

  return {
    routers,
    services,
    entrypoints,
    loading,
    feedback,
    routerSubmitting,
    serviceSubmitting,
    saveRouter,
    deleteRouter,
    saveService,
    deleteService,
  };
}
