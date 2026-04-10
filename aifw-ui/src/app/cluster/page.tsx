"use client";

export default function ClusterPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Cluster & High Availability</h1>
        <p className="text-sm text-[var(--text-muted)]">
          CARP failover, pfsync state synchronization, cluster health
        </p>
      </div>

      <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          <div>
            <p className="text-sm font-medium text-yellow-400">Not Production Ready</p>
            <p className="text-xs text-[var(--text-muted)] mt-1">
              The Cluster and High Availability features are implemented in the backend but have not been
              thoroughly tested in production environments. Use with caution. CARP failover, pfsync state
              synchronization, and cluster health monitoring will be validated in upcoming releases.
            </p>
          </div>
        </div>
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-12 text-center">
        <div className="mx-auto w-16 h-16 rounded-full bg-[var(--bg-primary)] flex items-center justify-center mb-4">
          <svg className="w-8 h-8 text-[var(--text-muted)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M12 5l7 7-7 7" />
          </svg>
        </div>
        <p className="text-lg font-medium">
          Cluster features available when High Availability is configured
        </p>
        <p className="text-sm text-[var(--text-muted)] mt-2 max-w-md mx-auto">
          Once HA is set up, this page will display cluster nodes, CARP virtual IPs,
          health checks, and pfsync synchronization status.
        </p>
      </div>
    </div>
  );
}
