"use client";

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import { api, isAuthed } from "@/lib/api";

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

/// Shape of GET /api/v1/auth/me (see aifw-api routes::rbac::get_current_user).
interface MeResponse {
  id: string;
  username: string;
  role: string;
  permissions?: string[];
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(defaultState);

  // The session lives in an HttpOnly cookie (SEC-M7 #304), so identity and
  // permissions come from /auth/me rather than decoding a stored JWT.
  const refresh = useCallback(() => {
    if (!isAuthed()) {
      setState({ ...defaultState, isLoading: false });
      return;
    }
    api
      .get<MeResponse>("/api/v1/auth/me")
      .then((me) =>
        setState({
          userId: me.id || null,
          username: me.username || null,
          role: me.role || null,
          permissions: new Set(me.permissions ?? []),
          isLoading: false,
        }),
      )
      .catch(() => setState({ ...defaultState, isLoading: false }));
  }, []);

  useEffect(() => {
    queueMicrotask(refresh);
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
