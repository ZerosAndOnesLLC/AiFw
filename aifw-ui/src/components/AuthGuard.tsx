"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

const PUBLIC_PATHS = ["/login", "/login/"];

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [checked, setChecked] = useState(false);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("aifw_token");

    if (PUBLIC_PATHS.includes(pathname)) {
      // On login page — if already authed, redirect to dashboard
      if (token) {
        router.replace("/");
      }
      setChecked(true);
      setAuthed(!!token);
      return;
    }

    // Protected page — redirect to login if no token
    if (!token) {
      router.replace("/login");
      setChecked(true);
      setAuthed(false);
      return;
    }

    // Validate token isn't expired (decode JWT payload)
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      if (payload.exp && payload.exp * 1000 < Date.now()) {
        // Token expired — try refresh or redirect to login
        localStorage.removeItem("aifw_token");
        router.replace("/login");
        setChecked(true);
        setAuthed(false);
        return;
      }
    } catch {
      localStorage.removeItem("aifw_token");
      router.replace("/login");
      setChecked(true);
      setAuthed(false);
      return;
    }

    setChecked(true);
    setAuthed(true);
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
