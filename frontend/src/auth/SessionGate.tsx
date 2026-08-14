import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useRef } from "react";
import { Navigate, Outlet, useNavigate } from "react-router";
import { setSessionActivityHandler, setSessionExpiredHandler } from "../api/expiry";
import { isUnauthorized } from "../api/problem";
import {
  clearSessionClientState,
  deleteSession,
  endedServerSession,
  getSession,
  hasMemoryCSRF,
} from "../api/session";
import type { SessionView } from "../api/types";
import { queryKeys } from "../lib/query";

type SessionContextValue = {
  session: SessionView;
  logout: () => Promise<void>;
  canLogout: boolean;
};

const SessionContext = createContext<SessionContextValue | undefined>(undefined);

export function useOptionalSession(): SessionContextValue | undefined {
  return useContext(SessionContext);
}

export function useSession(): SessionContextValue {
  const value = useOptionalSession();
  if (value === undefined) {
    throw new Error("useSession requires a signed-in session");
  }
  return value;
}

export function SessionGate() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const hadSession = useRef(false);
  const sessionQuery = useQuery({
    queryKey: queryKeys.session,
    queryFn: getSession,
    retry: false,
  });

  if (sessionQuery.data !== undefined) {
    hadSession.current = true;
  }

  useEffect(() => {
    // Real 401 from the server: the cookie session is already gone.
    const expire = (): void => {
      if (!hadSession.current) {
        return;
      }
      clearSessionClientState(queryClient);
      void navigate("/login", { replace: true, state: { reason: "expired" } });
    };
    setSessionExpiredHandler(expire);
    return () => setSessionExpiredHandler(undefined);
  }, [navigate, queryClient]);

  useEffect(() => {
    let last = 0;
    setSessionActivityHandler(() => {
      const now = Date.now();
      if (now - last < 15_000) {
        return;
      }
      last = now;
      void queryClient.invalidateQueries({ queryKey: queryKeys.session });
    });
    return () => setSessionActivityHandler(undefined);
  }, [queryClient]);

  useEffect(() => {
    if (!sessionQuery.isError || !isUnauthorized(sessionQuery.error)) {
      return;
    }
    const reason = hadSession.current ? "expired" : undefined;
    clearSessionClientState(queryClient);
    void navigate("/login", { replace: true, state: reason === undefined ? null : { reason } });
  }, [navigate, queryClient, sessionQuery.error, sessionQuery.isError]);

  useEffect(() => {
    const expiresAt = sessionQuery.data?.expiresAt;
    if (expiresAt === undefined) {
      return;
    }
    const ms = Date.parse(expiresAt) - Date.now();
    if (!Number.isFinite(ms)) {
      return;
    }
    const timer = window.setTimeout(() => {
      void (async () => {
        // Invalidate the server session while CSRF is still in memory.
        const result = await deleteSession();
        if (!endedServerSession(result)) {
          return;
        }
        hadSession.current = true;
        clearSessionClientState(queryClient);
        await navigate("/login", { replace: true, state: { reason: "expired" } });
      })();
    }, Math.max(0, ms));
    return () => window.clearTimeout(timer);
  }, [navigate, queryClient, sessionQuery.data?.expiresAt]);

  if (sessionQuery.isPending) {
    return (
      <main>
        <p role="status">Checking session…</p>
      </main>
    );
  }

  if (sessionQuery.data === undefined) {
    return (
      <Navigate
        to="/login"
        replace
        state={hadSession.current ? { reason: "expired" } : null}
      />
    );
  }

  const logout = async (): Promise<void> => {
    const result = await deleteSession();
    if (!endedServerSession(result)) {
      return;
    }
    clearSessionClientState(queryClient);
    await navigate("/login", { replace: true });
  };

  return (
    <SessionContext.Provider
      value={{ session: sessionQuery.data, logout, canLogout: hasMemoryCSRF() }}
    >
      <Outlet />
    </SessionContext.Provider>
  );
}
