"use client";

import { usePathname } from "next/navigation";
import AuthGuard from "./AuthGuard";
import Sidebar from "./Sidebar";

const PUBLIC_PATHS = ["/login", "/login/"];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.includes(pathname);

  return (
    <AuthGuard>
      {isPublic ? (
        children
      ) : (
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 ml-56 p-6 overflow-auto">
            {children}
          </main>
        </div>
      )}
    </AuthGuard>
  );
}
