import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "@labldap/openapi";
import { getMemoryBearer, getMemoryCSRF } from "./token";

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
};

export function createApiClient(baseUrl = "") {
  const client = createClient<paths>({
    baseUrl,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  client.use(memoryCredentials);
  return client;
}

export const api = createApiClient();
