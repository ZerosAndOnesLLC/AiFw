"use client";

import { usePathname } from "next/navigation";
import { useState, useEffect, useRef, useCallback } from "react";
import AuthGuard from "./AuthGuard";
import Sidebar from "./Sidebar";
import { WsProvider } from "@/context/WsContext";

const PUBLIC_PATHS = ["/login", "/login/"];
const MIN_WIDTH = 180;
const MAX_WIDTH = 360;
const DEFAULT_WIDTH = 224; // 56 * 4 = 224px (w-56)

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.includes(pathname);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    if (typeof window === "undefined") return DEFAULT_WIDTH;
    const saved = localStorage.getItem("aifw_sidebar_width");
    return saved ? Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, parseInt(saved, 10))) : DEFAULT_WIDTH;
  });
  const [isResizing, setIsResizing] = useState(false);
  const resizeRef = useRef<{ startX: number; startWidth: number } | null>(null);

  // Close sidebar on route change (mobile)
  useEffect(() => { setSidebarOpen(false); }, [pathname]);

  // Close sidebar on escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setSidebarOpen(false); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Resize handlers
  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
    resizeRef.current = { startX: e.clientX, startWidth: sidebarWidth };
  }, [sidebarWidth]);

  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const delta = e.clientX - resizeRef.current.startX;
      const newWidth = Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, resizeRef.current.startWidth + delta));
      setSidebarWidth(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      resizeRef.current = null;
      localStorage.setItem("aifw_sidebar_width", String(sidebarWidth));
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, sidebarWidth]);

  // Save width on change
  useEffect(() => {
    if (!isResizing) {
      localStorage.setItem("aifw_sidebar_width", String(sidebarWidth));
    }
  }, [sidebarWidth, isResizing]);

  return (
    <AuthGuard>
      {isPublic ? (
        children
      ) : (
        <WsProvider>
          <div className="flex min-h-screen">
            {/* Mobile overlay */}
            {sidebarOpen && (
              <div className="fixed inset-0 bg-black/50 z-30 lg:hidden" onClick={() => setSidebarOpen(false)} />
            )}

            {/* Sidebar — fixed on desktop, slide-in on mobile */}
            <div
              className={`
                fixed top-0 left-0 z-40 h-screen
                transform transition-transform duration-200 ease-in-out
                lg:translate-x-0
                ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
              `}
              style={{ width: sidebarWidth }}
            >
              <Sidebar onClose={() => setSidebarOpen(false)} width={sidebarWidth} />

              {/* Resize handle — desktop only */}
              <div
                onMouseDown={handleResizeStart}
                className="hidden lg:block absolute top-0 right-0 w-1 h-full cursor-col-resize group z-50"
              >
                <div className={`w-full h-full transition-colors ${isResizing ? "bg-[var(--accent)]" : "bg-transparent group-hover:bg-[var(--accent)]/50"}`} />
              </div>
            </div>

            {/* Main content */}
            <main className="flex-1 min-h-screen" style={{ marginLeft: typeof window !== "undefined" && window.innerWidth >= 1024 ? sidebarWidth : 0 }}>
              {/* Mobile header bar */}
              <div className="lg:hidden sticky top-0 z-20 bg-[var(--bg-secondary)] border-b border-[var(--border)] px-4 py-3 flex items-center gap-3">
                <button onClick={() => setSidebarOpen(true)} className="text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                  </svg>
                </button>
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded bg-[var(--accent)] flex items-center justify-center font-bold text-white text-[10px]">AI</div>
                  <span className="font-semibold text-sm">AiFw</span>
                </div>
              </div>
              <div className="p-4 lg:p-6 overflow-auto">
                {children}
              </div>
            </main>
          </div>
        </WsProvider>
      )}
    </AuthGuard>
  );
}
