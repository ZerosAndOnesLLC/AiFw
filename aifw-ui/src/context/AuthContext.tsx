"use client";

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import { decodePermissions } from "@/lib/permissions";

interface AuthState {
  userId: string | null;
  username: string | null;
  role: string | null;
  permissions: Set<string>;
  isLoading: boolean;
}

const defaultState: AuthState = {
  userId: null,
  username: null,
  role: null,
  permissions: new Set(),
  isLoading: true,
};

const AuthContext = createContext<AuthState>(defaultState);

function decodeJwt(token: string): AuthState {
  try {
    let b64 = token.split(".")[1];
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const payload = JSON.parse(atob(b64));

    // Check expiry
    if (payload.exp && payload.exp * 1000 < Date.now()) {
      return { ...defaultState, isLoading: false };
    }

    const permissions = payload.perm != null
      ? decodePermissions(payload.perm)
      : new Set<string>(); // Legacy token — no permissions in JWT

    return {
      userId: payload.sub || null,
      username: payload.username || null,
      role: payload.role || null,
      permissions,
      isLoading: false,
    };
  } catch {
    return { ...defaultState, isLoading: false };
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(defaultState);

  const refresh = useCallback(() => {
    const token = localStorage.getItem("aifw_token");
    if (!token) {
      setState({ ...defaultState, isLoading: false });
      return;
    }
    setState(decodeJwt(token));
  }, []);

  useEffect(() => {
    refresh();
    // Re-check on storage changes (e.g. login/logout in another tab)
    const handler = () => refresh();
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, [refresh]);

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
