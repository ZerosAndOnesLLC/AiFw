"use client";

import { useState } from "react";
import {
  type RouterForm,
  type ServiceForm,
  type UdpRouter,
  type UdpService,
  defaultRouterForm,
  defaultServiceForm,
  parseServiceConfigJson,
} from "@/lib/api/reverse-proxy/udp";
import { useUdpProxy } from "@/hooks/useUdpProxy";
import { RoutersSection } from "./components/RoutersSection";
import { ServicesSection } from "./components/ServicesSection";
import { RouterModal } from "./components/RouterModal";
import { ServiceModal } from "./components/ServiceModal";
import { ConfirmDeleteModal } from "./components/ConfirmDeleteModal";

/* -- Page ------------------------------------------------------------ */

export default function UdpPage() {
  const {
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
  } = useUdpProxy();

  /* -- Router modal state -------------------------------------------- */
  const [routerModalOpen, setRouterModalOpen] = useState(false);
  const [editingRouterId, setEditingRouterId] = useState<string | null>(null);
  const [routerForm, setRouterForm] = useState<RouterForm>(defaultRouterForm);
  const [deleteRouterId, setDeleteRouterId] = useState<string | null>(null);

  /* -- Service modal state -------------------------------------------- */
  const [serviceModalOpen, setServiceModalOpen] = useState(false);
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [serviceForm, setServiceForm] = useState<ServiceForm>(defaultServiceForm);
  const [deleteServiceId, setDeleteServiceId] = useState<string | null>(null);

  /* -- Router modal handlers ------------------------------------------ */

  const openCreateRouter = () => {
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
    setRouterModalOpen(true);
  };

  const openEditRouter = (r: UdpRouter) => {
    setEditingRouterId(r.id);
    setRouterForm({
      name: r.name,
      rule: r.rule,
      service: r.service,
      entry_points: r.entry_points,
      priority: String(r.priority),
      enabled: r.enabled,
    });
    setRouterModalOpen(true);
  };

  const closeRouterModal = () => {
    setRouterModalOpen(false);
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
  };

  /* -- Service modal handlers ----------------------------------------- */

  const openCreateService = () => {
    setEditingServiceId(null);
    setServiceForm({ ...defaultServiceForm, servers: [{ address: "", weight: "1" }], weightedRefs: [{ name: "", weight: "1" }] });
    setServiceModalOpen(true);
  };

  const openEditService = (s: UdpService) => {
    const parsed = parseServiceConfigJson(s.config_json, s.service_type);
    setEditingServiceId(s.id);
    setServiceForm({
      ...defaultServiceForm,
      name: s.name,
      service_type: s.service_type,
      enabled: s.enabled,
      servers: parsed.servers || [{ address: "", weight: "1" }],
      healthCheckInterval: parsed.healthCheckInterval || "",
      healthCheckTimeout: parsed.healthCheckTimeout || "",
      healthCheckPayload: parsed.healthCheckPayload || "",
      healthCheckExpectedResponse: parsed.healthCheckExpectedResponse || "",
      weightedRefs: parsed.weightedRefs || [{ name: "", weight: "1" }],
    });
    setServiceModalOpen(true);
  };

  const closeServiceModal = () => {
    setServiceModalOpen(false);
    setEditingServiceId(null);
    setServiceForm(defaultServiceForm);
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading UDP routers &amp; services...
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">UDP Routing</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage UDP routers and services for the reverse proxy
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

      <RoutersSection
        routers={routers}
        onAdd={openCreateRouter}
        onEdit={openEditRouter}
        onDelete={setDeleteRouterId}
      />

      <ServicesSection
        services={services}
        onAdd={openCreateService}
        onEdit={openEditService}
        onDelete={setDeleteServiceId}
      />

      {routerModalOpen && (
        <RouterModal
          form={routerForm}
          setForm={setRouterForm}
          services={services}
          entrypoints={entrypoints}
          editing={!!editingRouterId}
          submitting={routerSubmitting}
          onCancel={closeRouterModal}
          onSubmit={() => saveRouter(routerForm, editingRouterId, closeRouterModal)}
        />
      )}

      {serviceModalOpen && (
        <ServiceModal
          form={serviceForm}
          setForm={setServiceForm}
          editing={!!editingServiceId}
          submitting={serviceSubmitting}
          onCancel={closeServiceModal}
          onSubmit={() => saveService(serviceForm, editingServiceId, closeServiceModal)}
        />
      )}

      {deleteRouterId && (
        <ConfirmDeleteModal
          title="Delete UDP Router"
          message="Are you sure you want to delete this UDP router? This action cannot be undone."
          onCancel={() => setDeleteRouterId(null)}
          onConfirm={() => deleteRouter(deleteRouterId, () => setDeleteRouterId(null))}
        />
      )}

      {deleteServiceId && (
        <ConfirmDeleteModal
          title="Delete UDP Service"
          message="Are you sure you want to delete this UDP service? Any routers referencing it will stop working."
          onCancel={() => setDeleteServiceId(null)}
          onConfirm={() => deleteService(deleteServiceId, () => setDeleteServiceId(null))}
        />
      )}
    </div>
  );
}
