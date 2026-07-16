"use client";

import { useTcpProxy } from "@/hooks/useTcpProxy";
import { RouterTable } from "./components/RouterTable";
import { ServiceTable } from "./components/ServiceTable";
import { RouterModal } from "./components/RouterModal";
import { ServiceModal } from "./components/ServiceModal";
import { DeleteConfirmModal } from "./components/DeleteConfirmModal";

export default function TcpPage() {
  const {
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
  } = useTcpProxy();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading TCP routers &amp; services...
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">TCP Routing</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage TCP routers and services for the reverse proxy
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

      {/* TCP Routers section */}
      <RouterTable
        routers={routers}
        onAdd={openCreateRouter}
        onEdit={openEditRouter}
        onDelete={setDeleteRouterId}
      />

      {/* TCP Services section */}
      <ServiceTable
        services={services}
        onAdd={openCreateService}
        onEdit={openEditService}
        onDelete={setDeleteServiceId}
      />

      {/* Router modal */}
      {routerModalOpen && (
        <RouterModal
          editingRouterId={editingRouterId}
          form={routerForm}
          setForm={setRouterForm}
          services={services}
          entrypoints={entrypoints}
          submitting={routerSubmitting}
          onClose={closeRouterModal}
          onSubmit={handleRouterSubmit}
        />
      )}

      {/* Service modal */}
      {serviceModalOpen && (
        <ServiceModal
          editingServiceId={editingServiceId}
          form={serviceForm}
          setForm={setServiceForm}
          submitting={serviceSubmitting}
          onClose={closeServiceModal}
          onSubmit={handleServiceSubmit}
          addServer={addServer}
          removeServer={removeServer}
          updateServer={updateServer}
          addWeightedRef={addWeightedRef}
          removeWeightedRef={removeWeightedRef}
          updateWeightedRef={updateWeightedRef}
        />
      )}

      {/* Delete router confirm modal */}
      {deleteRouterId && (
        <DeleteConfirmModal
          title="Delete TCP Router"
          message="Are you sure you want to delete this TCP router? This action cannot be undone."
          onCancel={() => setDeleteRouterId(null)}
          onConfirm={() => handleDeleteRouter(deleteRouterId)}
        />
      )}

      {/* Delete service confirm modal */}
      {deleteServiceId && (
        <DeleteConfirmModal
          title="Delete TCP Service"
          message="Are you sure you want to delete this TCP service? Any routers referencing it will stop working."
          onCancel={() => setDeleteServiceId(null)}
          onConfirm={() => handleDeleteService(deleteServiceId)}
        />
      )}
    </div>
  );
}
