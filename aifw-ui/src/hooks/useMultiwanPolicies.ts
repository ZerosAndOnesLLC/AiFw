"use client";

// Data + CRUD hook for the Multi-WAN policy-routing page (#428 / QUAL-H8).
//
// Note: this page historically shows a persistent error banner that the
// user dismisses manually (no success feedback, no auto-dismiss), so it
// keeps its own `error` state instead of the auto-dismissing `useFeedback`
// hook — swapping would change behavior.

import { useCallback, useState } from "react";
import { usePolling } from "@/lib/usePolling";
import {
  BlastRadius,
  FormState,
  Gateway,
  GatewayGroup,
  PolicyRule,
  RoutingInstance,
  applyPolicies,
  createPolicy,
  deletePolicy,
  duplicatePolicy,
  listGateways,
  listGroups,
  listInstances,
  listPolicies,
  policyBodyFromForm,
  previewBlastRadius,
  reorderPolicies,
  togglePolicy,
  updatePolicy,
} from "@/lib/api/multiwan-policies";

export function useMultiwanPolicies() {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [groups, setGroups] = useState<GatewayGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [p, i, g, grp] = await Promise.all([
        listPolicies(),
        listInstances(),
        listGateways(),
        listGroups(),
      ]);
      setPolicies(p);
      setInstances(i);
      setGateways(g);
      setGroups(grp);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  usePolling(refresh, 15_000);

  const clearError = useCallback(() => setError(null), []);

  /* ────────── CRUD ────────── */

  /// Create (editingId null) or update a policy from the form. `onSuccess`
  /// runs after the save but before the refresh, mirroring the original
  /// close-panel-then-refresh ordering; `submitting` stays true throughout.
  async function savePolicy(
    editingId: string | null,
    form: FormState,
    onSuccess: () => void,
  ) {
    setSubmitting(true);
    setError(null);
    try {
      const body = policyBodyFromForm(form);
      if (editingId) {
        await updatePolicy(editingId, body);
      } else {
        await createPolicy(body);
      }
      onSuccess();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "save failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function toggle(p: PolicyRule) {
    try {
      await togglePolicy(p.id, p.status !== "active");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "toggle failed");
    }
  }

  async function duplicate(id: string) {
    try {
      await duplicatePolicy(id);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "duplicate failed");
    }
  }

  async function removePolicy(id: string) {
    if (!confirm("Delete policy?")) return;
    try {
      await deletePolicy(id);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
    }
  }

  async function applyNow() {
    if (!confirm("Reload pf with current policies?")) return;
    try {
      await applyPolicies();
    } catch (e) {
      setError(e instanceof Error ? e.message : "apply failed");
    }
  }

  async function previewBlast() {
    setBlastLoading(true);
    setBlast(null);
    try {
      setBlast(await previewBlastRadius(policies));
    } catch (e) {
      setError(e instanceof Error ? e.message : "preview failed");
    } finally {
      setBlastLoading(false);
    }
  }

  const dismissBlast = useCallback(() => setBlast(null), []);

  /* ────────── drag-to-reorder ────────── */

  async function persistOrder(newOrder: PolicyRule[]) {
    setPolicies(newOrder);
    try {
      await reorderPolicies(newOrder.map((p) => p.id));
    } catch (e) {
      setError(e instanceof Error ? e.message : "reorder failed");
      refresh();
    }
  }

  return {
    policies,
    instances,
    gateways,
    groups,
    loading,
    error,
    clearError,
    refresh,
    submitting,
    savePolicy,
    toggle,
    duplicate,
    removePolicy,
    applyNow,
    blast,
    blastLoading,
    previewBlast,
    dismissBlast,
    persistOrder,
  };
}
