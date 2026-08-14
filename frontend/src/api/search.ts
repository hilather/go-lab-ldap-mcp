import { api } from "./client";
import { toApiError } from "./problem";
import type { BindTestBody, BindTestResult, SearchPage, SearchQuery } from "./types";

export async function searchEntries(body: SearchQuery): Promise<SearchPage> {
  const { data, error, response } = await api.POST("/api/v1/search", { body });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "search failed");
  }
  return data;
}

export async function createAuthTest(body: BindTestBody): Promise<BindTestResult> {
  const { data, error, response } = await api.POST("/api/v1/auth-tests", { body });
  if (!response.ok || data === undefined) {
    throw toApiError(error, response.status, "bind test failed");
  }
  return data;
}
