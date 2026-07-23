"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { isAuthed } from "@/lib/api";

const PUBLIC_PATHS = ["/login", "/login/"];

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [checked, setChecked] = useState(false);
  const [authed, setAuthedState] = useState(false);

  useEffect(() => {
    queueMicrotask(() => {
      // The session itself is an HttpOnly cookie the page can't inspect
      // (SEC-M7 #304); this flag is the client-side marker set at login.
      // Expiry is handled by the API: a 401 triggers a silent refresh and,
      // failing that, the centralized redirect to /login (see lib/api.ts).
      const loggedIn = isAuthed();

      if (PUBLIC_PATHS.includes(pathname)) {
        // On login page — if already authed, redirect to dashboard
        if (loggedIn) {
          router.replace("/");
        }
        setChecked(true);
        setAuthedState(loggedIn);
        return;
      }

      // Protected page — redirect to login if not logged in
      if (!loggedIn) {
        router.replace("/login");
        setChecked(true);
        setAuthedState(false);
        return;
      }

      setChecked(true);
      setAuthedState(true);
    });
  }, [pathname, router]);

  if (!checked) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // On login page, don't show sidebar
  if (PUBLIC_PATHS.includes(pathname)) {
    return <>{children}</>;
  }

  // Not authed on protected page — show nothing while redirecting
  if (!authed) {
    return null;
  }

  return <>{children}</>;
}
