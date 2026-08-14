import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "@labldap/openapi";
import { notifySessionActivity, notifySessionExpired } from "./expiry";
import { getMemoryBearer, getMemoryCSRF } from "./token";

function sessionPath(request: Request): string | undefined {
  try {
    return new URL(request.url).pathname;
  } catch {
    return undefined;
  }
}

function isSessionCreate(request: Request): boolean {
  return request.method === "POST" && sessionPath(request) === "/api/v1/session";
}

function isSessionGet(request: Request): boolean {
  return request.method === "GET" && sessionPath(request) === "/api/v1/session";
}

const memoryCredentials: Middleware = {
  async onRequest({ request }) {
    const token = getMemoryBearer();
    if (token !== undefined) {
      request.headers.set("Authorization", `Bearer ${token}`);
    }
    const csrf = getMemoryCSRF();
    if (csrf !== undefined) {
      request.headers.set("X-CSRF-Token", csrf);
    }
    return request;
  },
  async onResponse({ request, response }) {
    if (response.status === 401 && !isSessionCreate(request)) {
      notifySessionExpired();
      return response;
    }
    // Successful authenticated calls extend server idle via Lookup.
    // Skip GET /session so a refresh cannot loop into another GET /session.
    if (response.ok && !isSessionCreate(request) && !isSessionGet(request)) {
      notifySessionActivity();
    }
    return response;
  },
};

export function createApiClient(baseUrl = "") {
  const client = createClient<paths>({
    baseUrl,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    fetch: (request) => fetch(new Request(request, { cache: "no-store" })),
  });
  client.use(memoryCredentials);
  return client;
}

export const api = createApiClient();
