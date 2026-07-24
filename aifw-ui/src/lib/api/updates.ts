import { api } from "@/lib/api";

// ---- Types ----

export interface UpdateStatus {
  os_version: string;
  last_check: string;
  pending_os_updates: boolean;
  pending_pkg_count: number;
  pending_packages: string[];
  needs_reboot: boolean;
  checking: boolean;
  installing: boolean;
}

export interface MaintenanceWindow {
  enabled: boolean;
  day_of_week: string;
  time: string;
  auto_install: boolean;
  auto_reboot: boolean;
  auto_check: boolean;
  auto_update_aifw?: boolean;
}

export interface UpdateHistoryEntry {
  id: string;
  action: string;
  details: string;
  status: string;
  created_at: string;
}

export interface AifwUpdateInfo {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_notes: string;
  published_at: string;
  tarball_url: string | null;
  checksum_url: string | null;
  checksum_signature_url: string | null;
  has_backup: boolean;
  backup_version: string | null;
  // True when the on-disk version differs from the running binary —
  // an install/rollback completed but services have not been bounced.
  // Drives the "Restart pending" banner.
  restart_pending?: boolean;
  running_version?: string;
  // Parsed from `[reboot-recommended]` in release notes. Flips the
  // modal's primary action from Restart to Reboot.
  reboot_recommended?: boolean;
  reboot_reason?: string | null;
  // Operator opted this box into the pre-release update channel. When on,
  // checks/installs consider GitHub pre-releases, not just stable releases.
  include_prereleases?: boolean;
  // Minimum FreeBSD release the update needs (parsed from `Requires-OS:`
  // in the release notes). Null on releases published before OS stamping.
  required_os?: string | null;
  // The release needs a newer FreeBSD than this box runs — the OS upgrade
  // flow must happen first; the installer refuses otherwise (#612).
  os_upgrade_required?: boolean;
}

// ---- OS release upgrade (#613) ----

export interface OsUpgradeState {
  target: string;
  // fetching | installing | reboot_required | finalizing | done | failed
  phase: string;
  detail: string;
  started_at: string;
  updated_at: string;
}

export interface OsUpgradeStatus {
  current_os: string | null;
  state: OsUpgradeState | null;
}

export interface UpdateInstallResponse {
  message: string;
  restart_required: boolean;
  reboot_recommended?: boolean;
  reboot_reason?: string | null;
}

export interface LocalInstallResult {
  ok: boolean;
  message: string;
}

// ---- OS / package updates ----

export function getUpdateStatus(): Promise<UpdateStatus> {
  return api.get<UpdateStatus>("/api/v1/updates/status");
}

export function getUpdateSchedule(): Promise<MaintenanceWindow> {
  return api.get<MaintenanceWindow>("/api/v1/updates/schedule");
}

export async function saveUpdateSchedule(schedule: MaintenanceWindow): Promise<void> {
  await api.put("/api/v1/updates/schedule", schedule);
}

export function getUpdateHistory(): Promise<UpdateHistoryEntry[]> {
  return api
    .get<{ data?: UpdateHistoryEntry[] }>("/api/v1/updates/history")
    .then((data) => data.data || []);
}

export function checkForUpdates(): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/updates/check");
}

export function installUpdates(): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/updates/install");
}

export function scheduleReboot(): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/updates/reboot");
}

export function getOsUpgrade(): Promise<OsUpgradeStatus> {
  return api.get<OsUpgradeStatus>("/api/v1/updates/os/upgrade");
}

export function startOsUpgrade(target: string): Promise<{ message?: string }> {
  return api.post<{ message?: string }>("/api/v1/updates/os/upgrade", { target });
}

// ---- AiFw firmware updates ----

export function getAifwUpdateStatus(): Promise<AifwUpdateInfo> {
  return api.get<AifwUpdateInfo>("/api/v1/updates/aifw/status");
}

export function checkAifwUpdate(): Promise<AifwUpdateInfo> {
  return api.post<AifwUpdateInfo>("/api/v1/updates/aifw/check");
}

export async function setPrereleaseChannel(enabled: boolean): Promise<void> {
  await api.post("/api/v1/updates/aifw/prerelease", { enabled });
}

export function installAifwUpdate(): Promise<UpdateInstallResponse> {
  return api.post<UpdateInstallResponse>("/api/v1/updates/aifw/install");
}

export function rollbackAifw(): Promise<UpdateInstallResponse> {
  return api.post<UpdateInstallResponse>("/api/v1/updates/aifw/rollback");
}

export async function restartAifwServices(): Promise<void> {
  await api.post("/api/v1/updates/aifw/restart");
}

export async function rebootAifwSystem(): Promise<void> {
  await api.post("/api/v1/updates/aifw/reboot");
}

// ---- Restart-watch probes ----

/// Raw reachability probe used while waiting for the old API to go DOWN.
/// A plain fetch — any HTTP response (even 401) resolves; only a network
/// failure/timeout rejects, which is the "API is down" signal.
export function probeApiRaw(timeoutMs: number): Promise<Response> {
  return fetch("/api/v1/status", { signal: AbortSignal.timeout(timeoutMs) });
}

/// Authenticated probe used while waiting for the new API to come UP.
/// Rejects until the API answers 2xx again.
export function probeApiUp(timeoutMs: number): Promise<unknown> {
  return api.get("/api/v1/status", {
    noAuthRedirect: true,
    signal: AbortSignal.timeout(timeoutMs),
  });
}

// ---- Local-package install ----

/// Assemble the multipart form for a local tarball install. The optional
/// sha file is read as text and sent as a plain text field.
export function buildLocalInstallForm(
  tarball: File,
  sha: File | null,
  restart: boolean,
): Promise<FormData> {
  return new Promise((resolve) => {
    const form = new FormData();
    form.append("tarball", tarball);
    if (sha) {
      // Read the sha file as text and send it as a plain text field
      const reader = new FileReader();
      reader.onload = () => {
        form.append("sha256", reader.result as string);
        if (restart) form.append("restart", "true");
        resolve(form);
      };
      reader.readAsText(sha);
    } else {
      if (restart) form.append("restart", "true");
      resolve(form);
    }
  });
}

/// Upload + install a local update tarball. Uses XHR (not fetch) so we can
/// report upload progress. Never rejects — the result carries ok/message.
export function installLocalPackage(
  form: FormData,
  onProgress: (percent: number) => void,
): Promise<LocalInstallResult> {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    });
    xhr.addEventListener("loadend", () => {
      const ok = xhr.status >= 200 && xhr.status < 300;
      let message = ok ? "Install accepted" : `Failed (HTTP ${xhr.status})`;
      try {
        const body = JSON.parse(xhr.responseText);
        if (body.message) message = body.message;
      } catch {
        // Non-JSON body: on failure the API now returns the plain-text
        // reason (#504) — show it instead of a bare status code.
        if (!ok && xhr.responseText.trim()) message = xhr.responseText.trim();
      }
      resolve({ ok, message });
    });
    xhr.open("POST", "/api/v1/updates/aifw/install-local");
    // Auth rides the HttpOnly session cookie (same-origin XHR sends it
    // automatically); the custom header satisfies the API's CSRF check.
    xhr.setRequestHeader("X-AiFw-Csrf", "1");
    xhr.send(form);
  });
}
