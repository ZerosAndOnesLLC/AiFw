"use client";

export default function ClusterPage() {
  return (
    <div className="min-h-screen bg-gray-900 text-white p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Cluster & High Availability</h1>
        <p className="text-sm text-gray-400">
          CARP failover, pfsync state synchronization, cluster health
        </p>
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
        <div className="mx-auto w-16 h-16 rounded-full bg-gray-700 flex items-center justify-center mb-4">
          <svg
            className="w-8 h-8 text-gray-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M5 12h14M12 5l7 7-7 7"
            />
          </svg>
        </div>
        <p className="text-lg font-medium text-gray-300">
          Cluster features available when High Availability is configured
        </p>
        <p className="text-sm text-gray-500 mt-2 max-w-md mx-auto">
          Once HA is set up, this page will display cluster nodes, CARP virtual IPs,
          health checks, and pfsync synchronization status.
        </p>
      </div>
    </div>
  );
}
