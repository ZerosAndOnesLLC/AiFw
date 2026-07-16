"use client";

import { useUpdates } from "@/hooks/useUpdates";
import { FeedbackBanner } from "./components/FeedbackBanner";
import { FirmwareCard } from "./components/FirmwareCard";
import { LocalInstallCard } from "./components/LocalInstallCard";
import { MaintenanceWindowCard } from "./components/MaintenanceWindowCard";
import { OsStatusCard } from "./components/OsStatusCard";
import { PendingPackagesCard } from "./components/PendingPackagesCard";
import { RebootOverlay } from "./components/RebootOverlay";
import { RestartConfirmModal } from "./components/RestartConfirmModal";
import { RestartOverlay } from "./components/RestartOverlay";
import { RestartPendingBanner } from "./components/RestartPendingBanner";
import { UpdateHistoryCard } from "./components/UpdateHistoryCard";

export default function UpdatesPage() {
  const updates = useUpdates();

  if (updates.loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // Reboot overlay — shown while the box goes down for a full reboot.
  if (updates.aifwRebooting) {
    return <RebootOverlay />;
  }

  // Restart overlay — blocks the page during service restart
  if (updates.restarting) {
    return <RestartOverlay countdown={updates.restartCountdown} />;
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {updates.restartPrompt && (
        <RestartConfirmModal
          prompt={updates.restartPrompt}
          onLater={() => updates.setRestartPrompt(null)}
          onRestartServices={updates.handleConfirmRestart}
          onReboot={updates.handleConfirmReboot}
        />
      )}
      <div>
        <h1 className="text-2xl font-bold">System Updates</h1>
        <p className="text-sm text-[var(--text-muted)]">Manage AiFw firmware, operating system, and package updates</p>
      </div>

      {updates.feedback && <FeedbackBanner feedback={updates.feedback} />}

      {/* Restart-pending banner — shows whenever the on-disk version
          differs from the running binary. Survives page reloads because
          the flag comes from /updates/aifw/status. */}
      {updates.aifwInfo?.restart_pending && !updates.restartPrompt && (
        <RestartPendingBanner info={updates.aifwInfo} onRestart={updates.handleConfirmRestart} />
      )}

      {/* AiFw Firmware Card */}
      <FirmwareCard
        info={updates.aifwInfo}
        checking={updates.aifwChecking}
        installing={updates.aifwInstalling}
        rollingBack={updates.aifwRollingBack}
        onCheck={updates.handleAifwCheck}
        onInstall={updates.handleAifwInstall}
        onRollback={updates.handleAifwRollback}
        onTogglePrerelease={updates.handleTogglePrerelease}
      />

      {/* Install from package */}
      <LocalInstallCard
        tarballFile={updates.tarballFile}
        installRestart={updates.installRestart}
        uploadProgress={updates.uploadProgress}
        result={updates.installLocalResult}
        installing={updates.localInstalling}
        onTarballChange={updates.selectTarball}
        onShaChange={updates.selectShaFile}
        onInstallRestartChange={updates.setInstallRestart}
        onInstall={updates.handleLocalInstall}
      />

      {/* OS Status Card */}
      <OsStatusCard
        status={updates.status}
        checking={updates.checking}
        installing={updates.installing}
        rebooting={updates.rebooting}
        rebootConfirm={updates.rebootConfirm}
        onCheck={updates.handleCheck}
        onInstall={updates.handleInstall}
        onReboot={updates.handleReboot}
        onRebootConfirmChange={updates.setRebootConfirm}
      />

      {/* Pending Packages */}
      {updates.status && updates.status.pending_pkg_count > 0 && updates.status.pending_packages.length > 0 && (
        <PendingPackagesCard status={updates.status} />
      )}

      {/* Maintenance Window */}
      <MaintenanceWindowCard
        schedule={updates.schedule}
        saving={updates.savingSchedule}
        onChange={updates.setSchedule}
        onSave={updates.handleSaveSchedule}
      />

      {/* Update History */}
      <UpdateHistoryCard history={updates.history} />
    </div>
  );
}
