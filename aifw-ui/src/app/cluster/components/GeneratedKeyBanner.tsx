// ============================================================
// Generated peer key banner (shown once after "Peer Key" on a node)
// ============================================================

export function GeneratedKeyBanner({
  generatedKey,
  onDismiss,
}: {
  generatedKey: { nodeName: string; key: string };
  onDismiss: () => void;
}) {
  return (
    <div className="bg-yellow-500/10 border border-yellow-500/40 rounded p-3 text-sm">
      <div className="font-semibold mb-1">
        Peer API key for {generatedKey.nodeName}
      </div>
      <div className="text-xs opacity-80 mb-2">
        This key is shown ONCE. Copy it and register it on{" "}
        {generatedKey.nodeName} via its cluster page &rarr;{" "}
        &quot;Register Peer Key&quot; before dismissing. This local node
        will use it to authenticate to {generatedKey.nodeName}.
      </div>
      <code className="block break-all bg-[var(--bg-card)] p-2 rounded mb-2">
        {generatedKey.key}
      </code>
      <button
        onClick={() => navigator.clipboard.writeText(generatedKey.key)}
        className="text-xs underline mr-3"
      >
        copy
      </button>
      <button onClick={onDismiss} className="text-xs underline">
        dismiss
      </button>
    </div>
  );
}
