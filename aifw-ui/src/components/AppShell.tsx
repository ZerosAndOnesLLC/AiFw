"use client";

import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import AuthGuard from "./AuthGuard";
import Sidebar from "./Sidebar";
import { WsProvider } from "@/context/WsContext";

const PUBLIC_PATHS = ["/login", "/login/"];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.includes(pathname);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  // Close sidebar on escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") setSidebarOpen(false); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <AuthGuard>
      {isPublic ? (
        children
      ) : (
        <WsProvider>
          <div className="flex min-h-screen">
            {/* Mobile overlay */}
            {sidebarOpen && (
              <div
                className="fixed inset-0 bg-black/50 z-30 lg:hidden"
                onClick={() => setSidebarOpen(false)}
              />
            )}

            {/* Sidebar — fixed on desktop, slide-in on mobile */}
            <div className={`
              fixed top-0 left-0 z-40 h-screen
              transform transition-transform duration-200 ease-in-out
              lg:translate-x-0
              ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
            `}>
              <Sidebar onClose={() => setSidebarOpen(false)} />
            </div>

            {/* Main content */}
            <main className="flex-1 lg:ml-56 min-h-screen">
              {/* Mobile header bar */}
              <div className="lg:hidden sticky top-0 z-20 bg-[var(--bg-secondary)] border-b border-[var(--border)] px-4 py-3 flex items-center gap-3">
                <button
                  onClick={() => setSidebarOpen(true)}
                  className="text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors"
                >
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
