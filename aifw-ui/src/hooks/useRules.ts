"use client";

import { useCallback, useEffect, useState } from "react";
import { api, Rule, InterfaceInfo, Schedule } from "@/lib/api";
import {
  RuleForm,
  buildRuleBody,
  postBlockLogging,
  reorderRules,
  toggleStatusRequest,
  validateRuleForm,
} from "@/lib/api/rules";

/// Data + actions for the firewall rules page (#428). Owns the rule,
/// interface, schedule and live-pf-rule lists plus the create/update/
/// delete/reorder actions and their error reporting.
///
/// Note: this page's error banner is manually dismissed (no auto-dismiss
/// and no success toasts in the original), so it keeps a plain `error`
/// state instead of `useFeedback`.
export function useRules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [systemRules, setSystemRules] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [blockLogging, setBlockLogging] = useState(true);
  const [blockLoggingPending, setBlockLoggingPending] = useState(false);

  /* ── Fetch helpers ─────────────────────────────────────────────── */

  const fetchRules = useCallback(async () => {
    try {
      setError(null);
      const res = await api.listRules();
      setRules(res.data);
      // Derive block logging state from rules
      const blockRules = res.data.filter((r: Rule) => r.action.startsWith("block"));
      if (blockRules.length > 0) {
        setBlockLogging(blockRules.some((r: Rule) => r.log));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      fetchRules();

      api.listSystemRules()
        .then((d) => setSystemRules(d.data || []))
        .catch(() => {});

      api.listInterfaces()
        .then((d) => setInterfaces(d.data || []))
        .catch(() => {});

      api.listSchedules()
        .then((d) => setSchedules(d.data || []))
        .catch(() => {});
    });
  }, [fetchRules]);

  /* ── Reorder ───────────────────────────────────────────────────── */

  const moveRule = async (ruleId: string, direction: "up" | "down") => {
    const idx = rules.findIndex(r => r.id === ruleId);
    if (idx < 0) return;
    const targetIdx = direction === "up" ? idx - 1 : idx + 1;
    if (targetIdx < 0 || targetIdx >= rules.length) return;
    const reordered = [...rules];
    [reordered[idx], reordered[targetIdx]] = [reordered[targetIdx], reordered[idx]];
    setRules(reordered);
    try {
      await reorderRules(reordered.map(r => r.id));
      setPendingChanges(true);
    } catch { setError("Failed to save rule order"); }
  };

  /* ── Block logging toggle ──────────────────────────────────────── */

  const toggleBlockLogging = (enabled: boolean) => {
    setBlockLogging(enabled);
    setBlockLoggingPending(true);
  };

  const applyBlockLogging = async () => {
    try {
      await postBlockLogging(blockLogging);
      setBlockLoggingPending(false);
      fetchRules();
    } catch { /* silent */ }
  };

  /* ── Form submit ───────────────────────────────────────────────── */

  const saveRule = async (form: RuleForm, editingId: string | null, onSaved: () => void) => {
    if (submitting) return;
    setSubmitting(true);
    setError(null);

    // Client-side validation
    const errors = validateRuleForm(form);
    if (errors.length > 0) { setError(errors.join(". ")); setSubmitting(false); return; }

    try {
      const body = buildRuleBody(form);

      if (editingId) {
        await api.updateRule(editingId, body);
      } else {
        await api.createRule(body);
      }

      onSaved();
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule");
    } finally {
      setSubmitting(false);
    }
  };

  /* ── Delete ────────────────────────────────────────────────────── */

  const deleteRule = async (id: string) => {
    if (!confirm("Delete this firewall rule?")) return;
    setError(null);
    try {
      await api.deleteRule(id);
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule");
    }
  };

  /* ── Toggle enable/disable ─────────────────────────────────────── */

  const toggleStatus = async (rule: Rule) => {
    setError(null);
    try {
      await api.updateRule(rule.id, toggleStatusRequest(rule));
      await fetchRules();
      setPendingChanges(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to toggle rule status");
    }
  };

  return {
    rules,
    interfaces,
    schedules,
    systemRules,
    loading,
    error,
    setError,
    submitting,
    pendingChanges,
    blockLogging,
    blockLoggingPending,
    fetchRules,
    moveRule,
    toggleBlockLogging,
    applyBlockLogging,
    saveRule,
    deleteRule,
    toggleStatus,
  };
}
