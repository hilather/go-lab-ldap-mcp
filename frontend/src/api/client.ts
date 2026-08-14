import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "@labldap/openapi";
import { notifySessionExpired } from "./expiry";
import { getMemoryBearer, getMemoryCSRF } from "./token";

function isSessionCreate(request: Request): boolean {
  if (request.method !== "POST") {
    return false;
  }
  try {
    return new URL(request.url).pathname === "/api/v1/session";
  } catch {
    return false;
  }
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
