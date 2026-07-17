"use client";

import { useCluster } from "@/hooks/useCluster";
import StatusBanner from "./components/StatusBanner";
import { CarpVipSection } from "./components/CarpVipSection";
import { ErrorBanner } from "./components/ErrorBanner";
import { GeneratedKeyBanner } from "./components/GeneratedKeyBanner";
import { HealthChecksSection } from "./components/HealthChecksSection";
import { NodesSection } from "./components/NodesSection";
import { PeerKeyRegistrationCard } from "./components/PeerKeyRegistrationCard";
import { PfsyncSection } from "./components/PfsyncSection";

export default function ClusterPage() {
  const {
    vips,
    pfsync,
    nodes,
    healthChecks,
    summary,
    ifaces,
    busy,
    error,
    dismissError,
    generatedKey,
    dismissGeneratedKey,
    loopbackMsg,
    dismissLoopbackMsg,
    peerKeyMsg,
    dismissPeerKeyMsg,
    savingVip,
    savingPfsync,
    savingNode,
    savingHc,
    promote,
    demote,
    generatePeerKey,
    generateLoopbackKey,
    registerPeerKey,
    saveVip,
    deleteVip,
    savePfsync,
    forceSync,
    saveNode,
    deleteNode,
    saveHc,
    deleteHc,
  } = useCluster();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Cluster &amp; High Availability</h1>
          <p className="text-sm text-[var(--text-muted)]">
            CARP failover, pfsync state synchronization, peer nodes
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={promote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-green-600 hover:bg-green-700 disabled:opacity-50 text-sm"
          >
            Promote
          </button>
          <button
            onClick={demote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-sm"
          >
            Demote
          </button>
        </div>
      </div>

      {/* D2: Health-summary warning banners */}
      {summary && summary.warnings.length > 0 && (
        <div className="space-y-2">
          {summary.warnings.map((w, i) => (
            <div
              key={i}
              className="bg-red-500/10 border border-red-500/40 rounded p-3 text-sm text-red-300"
            >
              {w}
            </div>
          ))}
        </div>
      )}

      {/* D4: Loopback key missing banner */}
      {summary?.loopback_key_missing && (
        <div className="bg-yellow-500/10 border border-yellow-500/40 rounded p-3 text-sm flex justify-between items-start gap-3">
          <div>
            <div className="font-semibold">Loopback API key missing</div>
            <div className="text-xs opacity-80 mt-1">
              Cluster background tasks (replicator, role watcher, health prober)
              are disabled until a loopback API key is registered. This is
              normal if you configured HA via the UI rather than the setup
              wizard.
            </div>
          </div>
          <button
            onClick={generateLoopbackKey}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 whitespace-nowrap text-sm"
          >
            Generate now
          </button>
        </div>
      )}

      {/* Loopback key success message */}
      {loopbackMsg && (
        <div className="bg-green-500/10 border border-green-500/40 rounded p-3 text-sm flex justify-between items-start gap-3">
          <div>{loopbackMsg}</div>
          <button
            onClick={dismissLoopbackMsg}
            className="text-xs underline whitespace-nowrap"
          >
            dismiss
          </button>
        </div>
      )}

      {/* SEC-H12: register the inbound peer key so the master can push here */}
      <PeerKeyRegistrationCard
        highlight={summary?.inbound_peer_key_missing}
        busy={busy}
        peerKeyMsg={peerKeyMsg}
        onDismissMsg={dismissPeerKeyMsg}
        onRegister={registerPeerKey}
      />

      {/* Status banner (existing) */}
      <StatusBanner />

      {/* Error banner */}
      {error && <ErrorBanner error={error} onDismiss={dismissError} />}

      {/* Generated peer key banner */}
      {generatedKey && (
        <GeneratedKeyBanner
          generatedKey={generatedKey}
          onDismiss={dismissGeneratedKey}
        />
      )}

      {/* CARP Virtual IPs */}
      <CarpVipSection
        vips={vips}
        ifaces={ifaces}
        saving={savingVip}
        onSave={saveVip}
        onDelete={deleteVip}
      />

      {/* pfsync configuration */}
      <PfsyncSection
        pfsync={pfsync}
        ifaces={ifaces}
        saving={savingPfsync}
        busy={busy}
        onSave={savePfsync}
        onForceSync={forceSync}
      />

      {/* Health checks */}
      <HealthChecksSection
        healthChecks={healthChecks}
        saving={savingHc}
        onSave={saveHc}
        onDelete={deleteHc}
      />

      {/* Cluster Nodes */}
      <NodesSection
        nodes={nodes}
        saving={savingNode}
        onSave={saveNode}
        onDelete={deleteNode}
        onGeneratePeerKey={generatePeerKey}
      />
    </div>
  );
}
