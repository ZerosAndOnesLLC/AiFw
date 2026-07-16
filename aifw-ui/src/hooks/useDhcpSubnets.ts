"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  type DhcpSubnet,
  type GlobalDefaults,
  type SubnetForm,
  buildSubnetPayload,
  createDhcpSubnet,
  deleteDhcpSubnet,
  fetchDhcpGlobalDefaults,
  listDhcpSubnets,
  updateDhcpSubnet,
  validateSubnetForm,
} from "@/lib/api/dhcp-subnets";

/// State + actions for the DHCP subnets page (#428). Owns the subnet
/// list, the global defaults used by the modal's Auto-fill, the loading
/// flag, and the create/update/delete actions with their success/error
/// feedback banners.
export function useDhcpSubnets() {
  const [subnets, setSubnets] = useState<DhcpSubnet[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [globalDefaults, setGlobalDefaults] = useState<GlobalDefaults>({
    dns_servers: [],
    ntp_servers: [],
    domain_name: "",
    default_lease_time: 86400,
  });
  const { feedback, showFeedback } = useFeedback();

  /* -- Fetch -------------------------------------------------------- */

  const fetchSubnets = useCallback(async () => {
    try {
      setSubnets(await listDhcpSubnets());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load subnets");
    }
  }, [showFeedback]);

  const fetchGlobalDefaults = useCallback(async () => {
    try {
      setGlobalDefaults(await fetchDhcpGlobalDefaults());
    } catch {
      /* silent — Auto will fall back to safe defaults */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchSubnets(), fetchGlobalDefaults()]);
      setLoading(false);
    })();
  }, [fetchSubnets, fetchGlobalDefaults]);

  /* -- Actions ------------------------------------------------------ */

  /** Create (`editingId` = null) or update a subnet. Validates first and
   *  surfaces errors via the feedback banner. `onSuccess` fires after the
   *  success banner and before the list refresh (the page uses it to
   *  close the modal). Returns true on success. */
  const saveSubnet = useCallback(
    async (editingId: string | null, form: SubnetForm, onSuccess?: () => void): Promise<boolean> => {
      const errors = validateSubnetForm(form);
      if (errors.length > 0) { showFeedback("error", errors.join(". ")); return false; }

      setSubmitting(true);
      try {
        const payload = buildSubnetPayload(form);
        if (editingId) {
          await updateDhcpSubnet(editingId, payload);
        } else {
          await createDhcpSubnet(payload);
        }

        showFeedback("success", editingId ? "Subnet updated" : "Subnet created");
        onSuccess?.();
        await fetchSubnets();
        return true;
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to save subnet");
        return false;
      } finally {
        setSubmitting(false);
      }
    },
    [fetchSubnets, showFeedback],
  );

  /** Delete a subnet. `onSuccess` fires after the success banner and
   *  before the list refresh (the page uses it to close the confirm
   *  dialog). Returns true on success. */
  const deleteSubnet = useCallback(
    async (id: string, onSuccess?: () => void): Promise<boolean> => {
      try {
        await deleteDhcpSubnet(id);
        showFeedback("success", "Subnet deleted");
        onSuccess?.();
        await fetchSubnets();
        return true;
      } catch (err) {
        showFeedback("error", err instanceof Error ? err.message : "Failed to delete subnet");
        return false;
      }
    },
    [fetchSubnets, showFeedback],
  );

  return {
    subnets,
    globalDefaults,
    loading,
    submitting,
    feedback,
    showFeedback,
    fetchSubnets,
    saveSubnet,
    deleteSubnet,
  };
}
