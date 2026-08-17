"use client";

/**
 * Last-resort boundary (#452): only reached when the root layout itself
 * throws (AppShell / providers). Must render its own <html>/<body> because
 * the layout is gone. Kept dependency-free on purpose.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en" className="dark">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0f1524",
          color: "#e2e8f0",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        <div
          role="alert"
          style={{
            maxWidth: 480,
            padding: 24,
            border: "1px solid rgba(239,68,68,0.4)",
            borderRadius: 8,
            background: "#1a2236",
          }}
        >
          <h1 style={{ margin: "0 0 8px", fontSize: 18 }}>AiFw UI failed to start</h1>
          <p style={{ margin: "0 0 16px", fontSize: 13, color: "#8494b0", wordBreak: "break-word" }}>
            {error?.message || "Unknown error"}
            {error?.digest ? ` (ref ${error.digest})` : ""}
          </p>
          <button
            onClick={reset}
            style={{
              padding: "8px 14px",
              background: "#3b82f6",
              color: "#fff",
              border: 0,
              borderRadius: 6,
              fontSize: 13,
              cursor: "pointer",
              marginRight: 8,
            }}
          >
            Try again
          </button>
          <button
            onClick={() => window.location.reload()}
            style={{
              padding: "8px 14px",
              background: "transparent",
              color: "#8494b0",
              border: "1px solid #2a3650",
              borderRadius: 6,
              fontSize: 13,
              cursor: "pointer",
            }}
          >
            Reload
          </button>
        </div>
      </body>
    </html>
  );
}
