import type { QueryClient } from "@tanstack/react-query";
import {
  browserSessionComplete,
  classifyLoginHttpStatus,
  emptyTokenField,
  sessionEndInvalidated,
  type SessionEndResult,
} from "../lib/session-model";
import { clearSessionQueryData } from "../lib/query";
import { api } from "./client";
import { isApiError, toApiError } from "./problem";
import { clearMemoryBearer, clearMemoryCSRF, getMemoryCSRF, setMemoryCSRF } from "./token";
import type { SessionCreated, SessionView } from "./types";

export type { SessionEndResult };

export function clearedLoginValues(): typeof emptyTokenField {
  return emptyTokenField;
}

export function applySessionCreated(created: SessionCreated): void {
  // Cookie is HttpOnly. Only the CSRF secret stays in process memory.
  setMemoryCSRF(created.csrfToken);
  clearMemoryBearer();
}

export function clearBrowserSecrets(): void {
  clearMemoryBearer();
  clearMemoryCSRF();
}

export function hasMemoryCSRF(): boolean {
  return getMemoryCSRF() !== undefined;
}

export function isCompleteBrowserSession(hasCookieSession: boolean): boolean {
  return browserSessionComplete(hasCookieSession, hasMemoryCSRF());
}

export function clearSessionClientState(client: QueryClient): void {
  clearBrowserSecrets();
  clearSessionQueryData(client);
}

export async function createSession(token: string): Promise<SessionCreated> {
  clearMemoryBearer();
  const { data, error, response } = await api.POST("/api/v1/session", {
    body: { token },
  });
  if (!response.ok || data === undefined) {
    const err = toApiError(error, response.status, "authentication required");
    if (err.rateLimited) {
      throw toApiError(error, 429, "rate limit exceeded");
    }
    if (classifyLoginHttpStatus(response.status) === "invalid") {
      throw toApiError(error, 401, "authentication required");
    }
    throw err;
  }
  applySessionCreated(data);
  return data;
}

export async function getSession(): Promise<SessionView> {
  const { data, error, response } = await api.GET("/api/v1/session");
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "authentication required");
  }
  return data;
}

// DELETE first while CSRF is still in memory. 403 means the cookie session
// is still live — do not pretend the tab is signed out.
export async function deleteSession(): Promise<SessionEndResult> {
  if (!hasMemoryCSRF()) {
    return "csrf";
  }
  const { response } = await api.DELETE("/api/v1/session");
  if (response.status === 204 || response.ok) {
    clearBrowserSecrets();
    return "deleted";
  }
  if (response.status === 401) {
    clearBrowserSecrets();
    return "unauthorized";
  }
  if (response.status === 403) {
    return "csrf";
  }
  return "failed";
}

export function endedServerSession(result: SessionEndResult): boolean {
  return sessionEndInvalidated(result);
}

export function loginFailureKind(err: unknown): "invalid" | "rate_limit" | "unknown" {
  if (isApiError(err)) {
    if (err.rateLimited) {
      return "rate_limit";
    }
    if (err.unauthorized) {
      return "invalid";
    }
  }
  return "unknown";
}
