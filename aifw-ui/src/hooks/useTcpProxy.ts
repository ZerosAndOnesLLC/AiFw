"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  TcpRouter,
  TcpService,
  EntryPoint,
  RouterForm,
  defaultRouterForm,
  ServiceForm,
  ServerEntry,
  defaultServiceForm,
  buildTlsJson,
  parseTlsJson,
  buildServiceConfigJson,
  parseServiceConfigJson,
  listTcpRouters,
  createTcpRouter,
  updateTcpRouter,
  deleteTcpRouter,
  listTcpServices,
  createTcpService,
  updateTcpService,
  deleteTcpService,
  listEntryPoints,
} from "@/lib/api/reverse-proxy/tcp";

/// Data + CRUD state for the TCP routing page (#428): TCP routers,
/// TCP services, and the shared entrypoint list, with modal/form state
/// and success/error feedback.
export function useTcpProxy() {
  /* -- Router state ------------------------------------------------- */
  const [routers, setRouters] = useState<TcpRouter[]>([]);
  const [routerModalOpen, setRouterModalOpen] = useState(false);
  const [editingRouterId, setEditingRouterId] = useState<string | null>(null);
  const [routerForm, setRouterForm] = useState<RouterForm>(defaultRouterForm);
  const [routerSubmitting, setRouterSubmitting] = useState(false);
  const [deleteRouterId, setDeleteRouterId] = useState<string | null>(null);

  /* -- Service state ------------------------------------------------ */
  const [services, setServices] = useState<TcpService[]>([]);
  const [serviceModalOpen, setServiceModalOpen] = useState(false);
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [serviceForm, setServiceForm] = useState<ServiceForm>(defaultServiceForm);
  const [serviceSubmitting, setServiceSubmitting] = useState(false);
  const [deleteServiceId, setDeleteServiceId] = useState<string | null>(null);

  /* -- Shared state ------------------------------------------------- */
  const [entrypoints, setEntrypoints] = useState<EntryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback } = useFeedback();

  /* -- Fetch -------------------------------------------------------- */

  const fetchRouters = useCallback(async () => {
    try {
      setRouters(await listTcpRouters());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load TCP routers");
    }
  }, [showFeedback]);

  const fetchServices = useCallback(async () => {
    try {
      setServices(await listTcpServices());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load TCP services");
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

  /* -- Router CRUD -------------------------------------------------- */

  const openCreateRouter = () => {
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
    setRouterModalOpen(true);
  };

  const openEditRouter = (r: TcpRouter) => {
    const tls = parseTlsJson(r.tls_json);
    setEditingRouterId(r.id);
    setRouterForm({
      name: r.name,
      rule: r.rule,
      service: r.service,
      entry_points: r.entry_points,
      priority: String(r.priority),
      tlsPassthrough: tls.passthrough,
      tlsCertResolver: tls.certResolver,
      enabled: r.enabled,
    });
    setRouterModalOpen(true);
  };

  const closeRouterModal = () => {
    setRouterModalOpen(false);
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
  };

  const handleRouterSubmit = async () => {
    if (!routerForm.name.trim() || !routerForm.rule.trim()) {
      showFeedback("error", "Name and rule are required");
      return;
    }
    setRouterSubmitting(true);
    try {
      const payload = {
        name: routerForm.name.trim(),
        rule: routerForm.rule.trim(),
        service: routerForm.service.trim(),
        entry_points: routerForm.entry_points.trim(),
        priority: parseInt(routerForm.priority, 10) || 0,
        tls_json: buildTlsJson(routerForm),
        enabled: routerForm.enabled,
      };
      if (editingRouterId) {
        await updateTcpRouter(editingRouterId, payload);
      } else {
        await createTcpRouter(payload);
      }
      showFeedback("success", editingRouterId ? "TCP router updated" : "TCP router created");
      closeRouterModal();
      await fetchRouters();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save TCP router");
    } finally {
      setRouterSubmitting(false);
    }
  };

  const handleDeleteRouter = async (id: string) => {
    try {
      await deleteTcpRouter(id);
      showFeedback("success", "TCP router deleted");
      setDeleteRouterId(null);
      await fetchRouters();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete TCP router");
    }
  };

  /* -- Service CRUD ------------------------------------------------- */

  const openCreateService = () => {
    setEditingServiceId(null);
    setServiceForm({ ...defaultServiceForm, servers: [{ address: "", weight: "1", tls: false }], weightedRefs: [{ name: "", weight: "1" }] });
    setServiceModalOpen(true);
  };

  const openEditService = (s: TcpService) => {
    const parsed = parseServiceConfigJson(s.config_json, s.service_type);
    setEditingServiceId(s.id);
    setServiceForm({
      ...defaultServiceForm,
      name: s.name,
      service_type: s.service_type,
      enabled: s.enabled,
      servers: parsed.servers || [{ address: "", weight: "1", tls: false }],
      healthCheckInterval: parsed.healthCheckInterval || "",
      healthCheckTimeout: parsed.healthCheckTimeout || "",
      proxyProtocol: parsed.proxyProtocol || "none",
      weightedRefs: parsed.weightedRefs || [{ name: "", weight: "1" }],
    });
    setServiceModalOpen(true);
  };

  const closeServiceModal = () => {
    setServiceModalOpen(false);
    setEditingServiceId(null);
    setServiceForm(defaultServiceForm);
  };

  const handleServiceSubmit = async () => {
    if (!serviceForm.name.trim()) {
      showFeedback("error", "Service name is required");
      return;
    }
    setServiceSubmitting(true);
    try {
      const payload = {
        name: serviceForm.name.trim(),
        service_type: serviceForm.service_type,
        config_json: buildServiceConfigJson(serviceForm),
        enabled: serviceForm.enabled,
      };
      if (editingServiceId) {
        await updateTcpService(editingServiceId, payload);
      } else {
        await createTcpService(payload);
      }
      showFeedback("success", editingServiceId ? "TCP service updated" : "TCP service created");
      closeServiceModal();
      await fetchServices();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save TCP service");
    } finally {
      setServiceSubmitting(false);
    }
  };

  const handleDeleteService = async (id: string) => {
    try {
      await deleteTcpService(id);
      showFeedback("success", "TCP service deleted");
      setDeleteServiceId(null);
      await fetchServices();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete TCP service");
    }
  };

  /* -- Server list helpers ------------------------------------------ */

  const addServer = () => {
    setServiceForm((f) => ({ ...f, servers: [...f.servers, { address: "", weight: "1", tls: false }] }));
  };

  const removeServer = (idx: number) => {
    setServiceForm((f) => ({ ...f, servers: f.servers.filter((_, i) => i !== idx) }));
  };

  const updateServer = (idx: number, field: keyof ServerEntry, value: string | boolean) => {
    setServiceForm((f) => ({
      ...f,
      servers: f.servers.map((s, i) => (i === idx ? { ...s, [field]: value } : s)),
    }));
  };

  /* -- Weighted refs helpers ---------------------------------------- */

  const addWeightedRef = () => {
    setServiceForm((f) => ({ ...f, weightedRefs: [...f.weightedRefs, { name: "", weight: "1" }] }));
  };

  const removeWeightedRef = (idx: number) => {
    setServiceForm((f) => ({ ...f, weightedRefs: f.weightedRefs.filter((_, i) => i !== idx) }));
  };

  const updateWeightedRef = (idx: number, field: "name" | "weight", value: string) => {
    setServiceForm((f) => ({
      ...f,
      weightedRefs: f.weightedRefs.map((r, i) => (i === idx ? { ...r, [field]: value } : r)),
    }));
  };

  return {
    /* shared */
    loading,
    feedback,
    entrypoints,
    /* routers */
    routers,
    routerModalOpen,
    editingRouterId,
    routerForm,
    setRouterForm,
    routerSubmitting,
    deleteRouterId,
    setDeleteRouterId,
    openCreateRouter,
    openEditRouter,
    closeRouterModal,
    handleRouterSubmit,
    handleDeleteRouter,
    /* services */
    services,
    serviceModalOpen,
    editingServiceId,
    serviceForm,
    setServiceForm,
    serviceSubmitting,
    deleteServiceId,
    setDeleteServiceId,
    openCreateService,
    openEditService,
    closeServiceModal,
    handleServiceSubmit,
    handleDeleteService,
    addServer,
    removeServer,
    updateServer,
    addWeightedRef,
    removeWeightedRef,
    updateWeightedRef,
  };
}
