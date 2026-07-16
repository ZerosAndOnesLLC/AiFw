"use client";

import { useState, useEffect, useCallback } from "react";
import { usePolling } from "@/lib/usePolling";
import { useFeedback } from "@/hooks/useFeedback";
import {
  AifwUpdateInfo,
  MaintenanceWindow,
  UpdateHistoryEntry,
  UpdateStatus,
  LocalInstallResult,
  buildLocalInstallForm,
  checkAifwUpdate,
  checkForUpdates,
  getAifwUpdateStatus,
  getUpdateHistory,
  getUpdateSchedule,
  getUpdateStatus,
  installAifwUpdate,
  installLocalPackage,
  installUpdates,
  probeApiRaw,
  probeApiUp,
  rebootAifwSystem,
  restartAifwServices,
  rollbackAifw,
  saveUpdateSchedule,
  scheduleReboot,
  setPrereleaseChannel,
} from "@/lib/api/updates";

// Restart-confirm modal state — shown after install/rollback succeeds.
// `action` is what we just did, used in the modal copy
// ("Update v… installed" vs "Rollback to v… completed").
// `rebootRecommended` flips the primary action to Reboot when the
// release notes contained `[reboot-recommended]`.
export interface RestartPrompt {
  action: "install" | "rollback";
  version: string;
  rebootRecommended: boolean;
  rebootReason: string | null;
}

/// All data-fetching + update/install/restart actions for the Updates page.
/// The page (and its presentational components) consume this hook's state
/// and callbacks; no HTTP happens outside `@/lib/api/updates`.
export function useUpdates() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [schedule, setSchedule] = useState<MaintenanceWindow>({
    enabled: false,
    day_of_week: "Sunday",
    time: "03:00",
    auto_install: false,
    auto_reboot: false,
    auto_check: true,
  });
  const [history, setHistory] = useState<UpdateHistoryEntry[]>([]);
  const { feedback, showFeedback } = useFeedback();
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [rebootConfirm, setRebootConfirm] = useState(false);
  const [loading, setLoading] = useState(true);

  // Local-package install state
  const [tarballFile, setTarballFile] = useState<File | null>(null);
  const [shaFile, setShaFile] = useState<File | null>(null);
  const [installRestart, setInstallRestart] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [installLocalResult, setInstallLocalResult] = useState<LocalInstallResult | null>(null);
  const [localInstalling, setLocalInstalling] = useState(false);

  // AiFw firmware update state
  const [aifwInfo, setAifwInfo] = useState<AifwUpdateInfo | null>(null);
  const [aifwChecking, setAifwChecking] = useState(false);
  const [aifwInstalling, setAifwInstalling] = useState(false);
  const [aifwRollingBack, setAifwRollingBack] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [restartCountdown, setRestartCountdown] = useState(0);
  const [restartPrompt, setRestartPrompt] = useState<RestartPrompt | null>(null);
  // Separate from the existing `rebooting` flag (which the OS-update
  // path uses for the modal-based confirm flow) — this one stays true
  // while we show the post-reboot wait overlay.
  const [aifwRebooting, setAifwRebooting] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await getUpdateStatus();
      setStatus(data);
      if (data.checking) setChecking(true);
      else setChecking(false);
      if (data.installing) setInstalling(true);
      else setInstalling(false);
    } catch {
      // silent on status poll
    }
  }, []);

  const fetchSchedule = useCallback(async () => {
    try {
      const data = await getUpdateSchedule();
      setSchedule(data);
    } catch {
      // use defaults
    }
  }, []);

  const fetchAifwStatus = useCallback(async () => {
    try {
      const data = await getAifwUpdateStatus();
      setAifwInfo(data);
    } catch {
      // silent
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const entries = await getUpdateHistory();
      setHistory(entries.slice(0, 50));
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      // Load fast endpoints first, then slow ones in background
      Promise.all([fetchSchedule(), fetchHistory()]).finally(() => setLoading(false));
      fetchStatus();
      fetchAifwStatus();
    });
  }, [fetchStatus, fetchSchedule, fetchHistory, fetchAifwStatus]);

  // Poll status while checking or installing
  usePolling(fetchStatus, 3000, checking || installing);

  const handleCheck = async () => {
    setChecking(true);
    try {
      const data = await checkForUpdates();
      showFeedback("success", data.message || "Update check complete");
      setChecking(false);
      fetchStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to check for updates");
      setChecking(false);
    }
  };

  const handleInstall = async () => {
    setInstalling(true);
    try {
      const data = await installUpdates();
      showFeedback("success", data.message || "Updates installed");
      setInstalling(false);
      fetchStatus();
      fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to install updates");
      setInstalling(false);
    }
  };

  const handleReboot = async () => {
    setRebooting(true);
    setRebootConfirm(false);
    try {
      const data = await scheduleReboot();
      showFeedback("success", data.message || "Reboot scheduled");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to schedule reboot");
    } finally {
      setRebooting(false);
    }
  };

  const handleSaveSchedule = async () => {
    setSavingSchedule(true);
    try {
      await saveUpdateSchedule(schedule);
      showFeedback("success", "Maintenance window saved");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save schedule");
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleAifwCheck = async () => {
    setAifwChecking(true);
    try {
      const data = await checkAifwUpdate();
      setAifwInfo(data);
      showFeedback("success", data.update_available
        ? `AiFw v${data.latest_version} is available`
        : `AiFw v${data.current_version} is the latest`);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to check for AiFw updates");
    } finally {
      setAifwChecking(false);
    }
  };

  const handleTogglePrerelease = async (enabled: boolean) => {
    // Optimistic — reflect the toggle immediately, revert on failure.
    setAifwInfo((prev) => (prev ? { ...prev, include_prereleases: enabled } : prev));
    try {
      await setPrereleaseChannel(enabled);
      showFeedback("success", `Pre-release channel ${enabled ? "enabled" : "disabled"}`);
      // Re-check against the new channel so the available version updates.
      await handleAifwCheck();
    } catch (err) {
      setAifwInfo((prev) => (prev ? { ...prev, include_prereleases: !enabled } : prev));
      showFeedback("error", err instanceof Error ? err.message : "Failed to change update channel");
    }
  };

  // Wait for the API to bounce, then reload the page. Used by every
  // path that triggers a service restart — install confirm, rollback
  // confirm, and the "restart pending" banner.
  const watchRestart = async () => {
    setRestarting(true);
    setRestartCountdown(120);

    const countdownInterval = setInterval(() => {
      setRestartCountdown((prev) => {
        if (prev <= 1) { clearInterval(countdownInterval); return 0; }
        return prev - 1;
      });
    }, 1000);

    // Phase 1: wait for the old API to go DOWN. The 2s spawn delay in
    // restart_services means our /status probe will keep succeeding for
    // a beat after we POSTed /restart — we want to see that confirmation
    // before declaring the bounce in progress.
    let apiWentDown = false;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      try {
        await probeApiRaw(2000);
      } catch {
        apiWentDown = true;
        break;
      }
    }
    if (!apiWentDown) await new Promise((r) => setTimeout(r, 5000));

    // Phase 2: wait for the new API to come up.
    const pollStart = Date.now();
    while (Date.now() - pollStart < 120000) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        await probeApiUp(3000);
        clearInterval(countdownInterval);
        setRestartCountdown(0);
        await new Promise((r) => setTimeout(r, 500));
        window.location.reload();
        return;
      } catch {
        // API not back yet — keep polling
      }
    }
    clearInterval(countdownInterval);
    window.location.reload();
  };

  const handleAifwInstall = async () => {
    setAifwInstalling(true);
    try {
      const data = await installAifwUpdate();
      setAifwInstalling(false);

      if (data.restart_required) {
        // Install put the new binaries on disk but did NOT bounce services.
        // Prompt the operator before triggering the outage.
        setRestartPrompt({
          action: "install",
          version: aifwInfo?.latest_version ?? "",
          rebootRecommended: data.reboot_recommended ?? aifwInfo?.reboot_recommended ?? false,
          rebootReason: data.reboot_reason ?? aifwInfo?.reboot_reason ?? null,
        });
        // Refresh status so the "restart pending" banner sticks if the
        // operator dismisses the modal.
        fetchAifwStatus();
      } else {
        showFeedback("success", data.message || "Already on the latest version");
      }
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to install AiFw update");
      setAifwInstalling(false);
    }
  };

  const handleAifwRollback = async () => {
    setAifwRollingBack(true);
    try {
      const data = await rollbackAifw();
      setAifwRollingBack(false);

      if (data.restart_required) {
        setRestartPrompt({
          action: "rollback",
          version: aifwInfo?.backup_version ?? "",
          rebootRecommended: false,
          rebootReason: null,
        });
        fetchAifwStatus();
      } else {
        showFeedback("success", data.message || "Rollback completed");
      }
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to rollback AiFw");
      setAifwRollingBack(false);
    }
  };

  // Operator-confirmed restart. Posts to the dedicated restart endpoint
  // and switches to the bounce overlay.
  const handleConfirmRestart = async () => {
    try {
      await restartAifwServices();
      setRestartPrompt(null);
      watchRestart();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to restart services");
    }
  };

  // Operator-confirmed full system reboot. shutdown(8) defers actual
  // reboot for 1 minute (also surfaces in the response message), so the
  // overlay countdown is longer than the service-restart path.
  const handleConfirmReboot = async () => {
    try {
      await rebootAifwSystem();
      setRestartPrompt(null);
      setAifwRebooting(true);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to schedule reboot");
    }
  };

  const selectTarball = (file: File | null) => {
    setTarballFile(file);
    setInstallLocalResult(null);
  };

  const selectShaFile = (file: File | null) => {
    setShaFile(file);
    setInstallLocalResult(null);
  };

  const handleLocalInstall = () => {
    if (!tarballFile) return;
    setLocalInstalling(true);
    setUploadProgress(0);
    setInstallLocalResult(null);

    buildLocalInstallForm(tarballFile, shaFile, installRestart)
      .then((form) => installLocalPackage(form, setUploadProgress))
      .then((result) => {
        setUploadProgress(null);
        setLocalInstalling(false);
        setInstallLocalResult(result);
        if (result.ok) {
          fetchHistory();
          fetchAifwStatus();
        }
      });
  };

  return {
    loading,
    feedback,
    // OS / package updates
    status,
    checking,
    installing,
    rebooting,
    rebootConfirm,
    setRebootConfirm,
    handleCheck,
    handleInstall,
    handleReboot,
    // Maintenance window
    schedule,
    setSchedule,
    savingSchedule,
    handleSaveSchedule,
    // History
    history,
    // AiFw firmware
    aifwInfo,
    aifwChecking,
    aifwInstalling,
    aifwRollingBack,
    handleAifwCheck,
    handleAifwInstall,
    handleAifwRollback,
    handleTogglePrerelease,
    // Restart / reboot flow
    restartPrompt,
    setRestartPrompt,
    restarting,
    restartCountdown,
    aifwRebooting,
    handleConfirmRestart,
    handleConfirmReboot,
    // Local-package install
    tarballFile,
    installRestart,
    setInstallRestart,
    uploadProgress,
    installLocalResult,
    localInstalling,
    selectTarball,
    selectShaFile,
    handleLocalInstall,
  };
}
