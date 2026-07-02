"use client";

import { createContext, useContext, useCallback, useEffect, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";

// ── Types ─────────────────────────────────────────────────────────────────

export type UserProfile = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
};

type AuthState = {
  accessToken: string | null;
  refreshToken: string | null;
  user: UserProfile | null;
};

type AuthContextValue = {
  accessToken: string | null;
  user: UserProfile | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string) => Promise<void>;
  logout: () => void;
};

// ── Constants ──────────────────────────────────────────────────────────────

const STORAGE_KEY_ACCESS = "aegis_access_token";
const STORAGE_KEY_REFRESH = "aegis_refresh_token";
const STORAGE_KEY_USER = "aegis_user";

function getApiBaseUrl(): string {
  return process.env.NEXT_PUBLIC_AEGIS_API_URL?.replace(/\/$/, "") ?? "";
}

// ── Helpers ────────────────────────────────────────────────────────────────

function loadState(): AuthState {
  if (typeof window === "undefined") return { accessToken: null, refreshToken: null, user: null };
  try {
    const accessToken = localStorage.getItem(STORAGE_KEY_ACCESS);
    const refreshToken = localStorage.getItem(STORAGE_KEY_REFRESH);
    const raw = localStorage.getItem(STORAGE_KEY_USER);
    const user: UserProfile | null = raw ? (JSON.parse(raw) as UserProfile) : null;
    return { accessToken, refreshToken, user };
  } catch {
    return { accessToken: null, refreshToken: null, user: null };
  }
}

function persistState(state: AuthState): void {
  if (typeof window === "undefined") return;
  try {
    if (state.accessToken) {
      localStorage.setItem(STORAGE_KEY_ACCESS, state.accessToken);
    } else {
      localStorage.removeItem(STORAGE_KEY_ACCESS);
    }
    if (state.refreshToken) {
      localStorage.setItem(STORAGE_KEY_REFRESH, state.refreshToken);
    } else {
      localStorage.removeItem(STORAGE_KEY_REFRESH);
    }
    if (state.user) {
      localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(state.user));
    } else {
      localStorage.removeItem(STORAGE_KEY_USER);
    }
  } catch {
    // storage may be unavailable
  }
}

function clearState(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(STORAGE_KEY_ACCESS);
    localStorage.removeItem(STORAGE_KEY_REFRESH);
    localStorage.removeItem(STORAGE_KEY_USER);
  } catch {
    // storage may be unavailable
  }
}

// ── Subscribe helper for useSyncExternalStore ──────────────────────────────

const listeners = new Set<() => void>();

function subscribeToAuthChanges(onStoreChange: () => void): () => void {
  listeners.add(onStoreChange);
  return () => listeners.delete(onStoreChange);
}

function notifyListeners(): void {
  listeners.forEach((fn) => fn());
}

let cachedState: AuthState | null = null;

function getSnapshot(): AuthState {
  const state = loadState();
  
  // Check if state has actually changed to maintain referential identity
  if (
    cachedState &&
    cachedState.accessToken === state.accessToken &&
    cachedState.refreshToken === state.refreshToken &&
    cachedState.user?.id === state.user?.id &&
    cachedState.user?.email === state.user?.email
  ) {
    return cachedState;
  }

  cachedState = state;
  return state;
}

// ── Context ────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const state = useSyncExternalStore(subscribeToAuthChanges, getSnapshot, getSnapshot);

  const logout = useCallback(() => {
    clearState();
    notifyListeners();
    router.push("/login");
  }, [router]);

  const login = useCallback(
    async (email: string, password: string) => {
      const baseUrl = getApiBaseUrl();
      if (!baseUrl) throw new Error("Backend API URL is not configured.");

      const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const detail = (await res.json().catch(() => ({ detail: "Login failed" }))).detail;
        throw new Error(detail);
      }

      const tokens: { access_token: string; refresh_token: string } = await res.json();

      // Fetch user profile
      const meRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });

      let user: UserProfile | null = null;
      if (meRes.ok) {
        user = (await meRes.json()) as UserProfile;
      }

      persistState({ accessToken: tokens.access_token, refreshToken: tokens.refresh_token, user });
      notifyListeners();
      router.push("/dashboard");
    },
    [router],
  );

  const register = useCallback(
    async (email: string, password: string, displayName: string) => {
      const baseUrl = getApiBaseUrl();
      if (!baseUrl) throw new Error("Backend API URL is not configured.");

      const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, display_name: displayName }),
      });

      if (!res.ok) {
        const detail = (await res.json().catch(() => ({ detail: "Registration failed" }))).detail;
        throw new Error(detail);
      }
    },
    [],
  );

  const value: AuthContextValue = {
    accessToken: state.accessToken,
    user: state.user,
    isAuthenticated: state.accessToken !== null,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

// ── Helper to add auth header to API calls ─────────────────────────────────

export function authHeaders(token: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}